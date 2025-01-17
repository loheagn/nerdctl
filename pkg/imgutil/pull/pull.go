/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Package pull forked from https://github.com/containerd/containerd/blob/v1.4.3/cmd/ctr/commands/content/fetch.go
package pull

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/containerd"
	ctrcontent "github.com/containerd/containerd/cmd/ctr/commands/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/nerdctl/pkg/platformutil"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Config for content fetch
type Config struct {
	// Resolver
	Resolver remotes.Resolver
	// ProgressOutput to display progress
	ProgressOutput io.Writer
	// RemoteOpts, e.g. containerd.WithPullUnpack.
	//
	// Regardless to RemoteOpts, the following opts are always set:
	// WithResolver, WithImageHandler, WithSchema1Conversion
	//
	// RemoteOpts related to unpacking can be set only when len(Platforms) is 1.
	RemoteOpts []containerd.RemoteOpt
	Platforms  []ocispec.Platform // empty for all-platforms
}

// Pull loads all resources into the content store and returns the image
func Pull(ctx context.Context, client *containerd.Client, ref string, config *Config) (containerd.Image, error) {
	ongoing := ctrcontent.NewJobs(ref)

	pctx, stopProgress := context.WithCancel(ctx)
	progress := make(chan struct{})

	go func() {
		if config.ProgressOutput != nil {
			// no progress bar, because it hides some debug logs
			ctrcontent.ShowProgress(pctx, ongoing, client.ContentStore(), config.ProgressOutput)
		}
		close(progress)
	}()

	h := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType != images.MediaTypeDockerSchema1Manifest {
			ongoing.Add(desc)
		}
		return nil, nil
	})

	log.G(pctx).WithField("image", ref).Debug("fetching")
	platformMC := platformutil.NewMatchComparerFromOCISpecPlatformSlice(config.Platforms)
	opts := []containerd.RemoteOpt{
		containerd.WithResolver(config.Resolver),
		containerd.WithImageHandler(h),
		//nolint:staticcheck
		containerd.WithSchema1Conversion, //lint:ignore SA1019 nerdctl should support schema1 as well.
		containerd.WithPlatformMatcher(platformMC),
		containerd.WithImageHandlerWrapper(appendDefaultLabelsHandlerWrapper(ref)),
	}
	opts = append(opts, config.RemoteOpts...)

	var (
		img containerd.Image
		err error
	)
	if len(config.Platforms) == 1 {
		// client.Pull is for single-platform (w/ unpacking)
		img, err = client.Pull(pctx, ref, opts...)
	} else {
		// client.Fetch is for multi-platform (w/o unpacking)
		var imagesImg images.Image
		imagesImg, err = client.Fetch(pctx, ref, opts...)
		img = containerd.NewImageWithPlatform(client, imagesImg, platformMC)
	}
	stopProgress()
	if err != nil {
		return nil, err
	}

	<-progress
	return img, nil
}

func appendDefaultLabelsHandlerWrapper(ref string) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			children, err := f.Handle(ctx, desc)
			if err != nil {
				return nil, err
			}
			switch desc.MediaType {
			case ocispec.MediaTypeImageManifest, images.MediaTypeDockerSchema2Manifest:
				for i := range children {
					c := &children[i]
					if images.IsLayerType(c.MediaType) {
						if c.Annotations == nil {
							c.Annotations = make(map[string]string)
						}
						c.Annotations[ImageRef] = ref
						c.Annotations[CRIDigest] = c.Digest.String()
						var layers string
						for _, l := range children[i:] {
							if images.IsLayerType(l.MediaType) {
								ls := fmt.Sprintf("%s,", l.Digest.String())
								// This avoids the label hits the size limitation.
								// Skipping layers is allowed here and only affects performance.
								if err := Validate(NydusDataLayer, layers+ls); err != nil {
									break
								}
								layers += ls
							}
						}
						c.Annotations[CRIImageLayer] = strings.TrimSuffix(layers, ",")
						c.Annotations[targetManifestDigestLabel] = desc.Digest.String()
					}
				}
			}
			return children, nil
		})
	}
}

const (
	Signature = "containerd.io/snapshot/nydus-signature"

	ImageRef          = "containerd.io/snapshot/cri.image-ref"
	ImagePullSecret   = "containerd.io/snapshot/pullsecret"
	ImagePullUsername = "containerd.io/snapshot/pullusername"

	TargetSnapshotLabel = "containerd.io/snapshot.ref"
	CRIImageLayer       = "containerd.io/snapshot/cri.image-layers"
	CRIDigest           = "containerd.io/snapshot/cri.layer-digest"
	RemoteLabel         = "containerd.io/snapshot/remote"
	NydusMetaLayer      = "containerd.io/snapshot/nydus-bootstrap"
	NydusDataLayer      = "containerd.io/snapshot/nydus-blob"

	targetManifestDigestLabel = "containerd.io/snapshot/cri.manifest-digest"

	maxSize = 4096
)

// Validate a label's key and value are under 4096 bytes
func Validate(k, v string) error {
	if (len(k) + len(v)) > maxSize {
		if len(k) > 10 {
			k = k[:10]
		}
		return fmt.Errorf("label key and value greater than maximum size (%d bytes), key: %s: %w", maxSize, k, errors.New("invalid argument"))
	}
	return nil
}
