package imgutil

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/converter"
	nydusconvert "github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

func ConvertToNydusLayer(opt nydusconvert.PackOption) converter.ConvertFunc {
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if !images.IsLayerType(desc.MediaType) {
			return nil, nil
		}

		ra, err := cs.ReaderAt(ctx, desc)
		if err != nil {
			return nil, errors.Wrap(err, "get source blob reader")
		}
		defer ra.Close()
		rdr := io.NewSectionReader(ra, 0, ra.Size())

		ref := fmt.Sprintf("convert-nydus-from-%s", desc.Digest)
		dst, err := content.OpenWriter(ctx, cs, content.WithRef(ref))
		if err != nil {
			return nil, errors.Wrap(err, "open blob writer")
		}
		defer dst.Close()

		tr, err := compression.DecompressStream(rdr)
		if err != nil {
			return nil, errors.Wrap(err, "decompress blob stream")
		}

		digester := digest.SHA256.Digester()
		pr, pw := io.Pipe()
		tw, err := nydusconvert.Pack(ctx, io.MultiWriter(pw, digester.Hash()), opt)
		if err != nil {
			return nil, errors.Wrap(err, "pack tar to nydus")
		}

		go func() {
			defer pw.Close()
			if _, err := io.Copy(tw, tr); err != nil {
				pw.CloseWithError(err)
				return
			}
			if err := tr.Close(); err != nil {
				pw.CloseWithError(err)
				return
			}
			if err := tw.Close(); err != nil {
				pw.CloseWithError(err)
				return
			}
		}()

		if err := content.Copy(ctx, dst, pr, 0, ""); err != nil {
			return nil, errors.Wrap(err, "copy nydus blob to content store")
		}

		blobDigest := digester.Digest()
		info, err := cs.Info(ctx, blobDigest)
		if err != nil {
			return nil, errors.Wrapf(err, "get blob info %s", blobDigest)
		}

		newDesc := ocispec.Descriptor{
			Digest:    blobDigest,
			Size:      info.Size,
			MediaType: nydusconvert.MediaTypeNydusBlob,
			Annotations: map[string]string{
				// Use `containerd.io/uncompressed` to generate DiffID of
				// layer defined in OCI spec.
				nydusconvert.LayerAnnotationUncompressed: blobDigest.String(),
				nydusconvert.LayerAnnotationNydusBlob:    "true",
			},
		}

		return &newDesc, nil
	}
}

func ConvertToNydusHook(opt nydusconvert.PackOption) converter.ConvertHookFunc {
	return func(ctx context.Context, cs content.Store, orgDesc ocispec.Descriptor, newDesc *ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if newDesc.MediaType != ocispec.MediaTypeImageManifest {
			return newDesc, nil
		}
		// convert manifest
		var manifest ocispec.Manifest
		manifestDesc := *newDesc
		_, err := readJSON(ctx, cs, &manifest, manifestDesc)
		if err != nil {
			return nil, errors.Wrap(err, "read manifest json")
		}

		// Append bootstrap layer to manifest.
		bootstrapDesc, err := mergeNydusLayers(ctx, cs, manifest.Layers, nydusconvert.MergeOption{
			BuilderPath:   opt.BuilderPath,
			WorkDir:       opt.WorkDir,
			ChunkDictPath: opt.ChunkDictPath,
			WithTar:       true,
		}, opt.FsVersion)
		if err != nil {
			return nil, errors.Wrap(err, "merge nydus layers")
		}
		bootstrapDiffID := digest.Digest(bootstrapDesc.Annotations[nydusconvert.LayerAnnotationUncompressed])

		manifest.Layers = append(manifest.Layers, *bootstrapDesc)

		// Remove useless annotation.
		for _, layer := range manifest.Layers {
			delete(layer.Annotations, nydusconvert.LayerAnnotationUncompressed)
		}

		// Update diff ids in image config.
		var config ocispec.Image
		labels, err := readJSON(ctx, cs, &config, manifest.Config)
		if err != nil {
			return nil, errors.Wrap(err, "read image config")
		}
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, bootstrapDiffID)

		// Update image config in content store.
		newConfigDesc, err := writeJSON(ctx, cs, config, manifest.Config, "", labels)
		if err != nil {
			return nil, errors.Wrap(err, "write image config")
		}
		manifest.Config = *newConfigDesc

		// Update image manifest in content store.
		newManifestDesc, err := writeJSON(ctx, cs, manifest, manifestDesc, "", labels)
		if err != nil {
			return nil, errors.Wrap(err, "write manifest")
		}

		return newManifestDesc, nil
	}
}

func mergeNydusLayers(ctx context.Context, cs content.Store, descs []ocispec.Descriptor, opt nydusconvert.MergeOption, fsVersion string) (*ocispec.Descriptor, error) {
	// Extracts nydus bootstrap from nydus format for each layer.
	layers := []nydusconvert.Layer{}
	blobIDs := []string{}

	var chainID digest.Digest
	for _, blobDesc := range descs {
		ra, err := cs.ReaderAt(ctx, blobDesc)
		if err != nil {
			return nil, errors.Wrapf(err, "get reader for blob %q", blobDesc.Digest)
		}
		defer ra.Close()
		blobIDs = append(blobIDs, blobDesc.Digest.Hex())
		layers = append(layers, nydusconvert.Layer{
			Digest:   blobDesc.Digest,
			ReaderAt: ra,
		})
		if chainID == "" {
			chainID = identity.ChainID([]digest.Digest{blobDesc.Digest})
		} else {
			chainID = identity.ChainID([]digest.Digest{chainID, blobDesc.Digest})
		}
	}

	// Merge all nydus bootstraps into a final nydus bootstrap.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if err := nydusconvert.Merge(ctx, layers, pw, opt); err != nil {
			pw.CloseWithError(errors.Wrapf(err, "merge nydus bootstrap"))
		}
	}()

	// Compress final nydus bootstrap to tar.gz and write into content store.
	cw, err := content.OpenWriter(ctx, cs, content.WithRef("nydus-merge-"+chainID.String()))
	if err != nil {
		return nil, errors.Wrap(err, "open content store writer")
	}
	defer cw.Close()

	gw := gzip.NewWriter(cw)
	uncompressedDgst := digest.SHA256.Digester()
	compressed := io.MultiWriter(gw, uncompressedDgst.Hash())
	if _, err := io.Copy(compressed, pr); err != nil {
		return nil, errors.Wrapf(err, "copy bootstrap targz into content store")
	}
	if err := gw.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}

	compressedDgst := cw.Digest()
	if err := cw.Commit(ctx, 0, compressedDgst, content.WithLabels(map[string]string{
		nydusconvert.LayerAnnotationUncompressed: uncompressedDgst.Digest().String(),
	})); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return nil, errors.Wrap(err, "commit to content store")
		}
	}
	if err := cw.Close(); err != nil {
		return nil, errors.Wrap(err, "close content store writer")
	}

	info, err := cs.Info(ctx, compressedDgst)
	if err != nil {
		return nil, errors.Wrap(err, "get info from content store")
	}

	blobIDsBytes, err := json.Marshal(blobIDs)
	if err != nil {
		return nil, errors.Wrap(err, "marshal blob ids")
	}

	desc := ocispec.Descriptor{
		Digest:    compressedDgst,
		Size:      info.Size,
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Annotations: map[string]string{
			nydusconvert.LayerAnnotationUncompressed: uncompressedDgst.Digest().String(),
			// TODO 这个Annotation是必需的吗
			"containerd.io/snapshot/nydus-fs-version": fsVersion,
			// Use this annotation to identify nydus bootstrap layer.
			nydusconvert.LayerAnnotationNydusBootstrap: "true",
			// Track all blob digests for nydus snapshotter.
			nydusconvert.LayerAnnotationNydusBlobIDs: string(blobIDsBytes),
		},
	}

	return &desc, nil
}

func writeJSON(ctx context.Context, cs content.Store, x interface{}, oldDesc ocispec.Descriptor, ref string, labels map[string]string) (*ocispec.Descriptor, error) {
	b, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		return nil, err
	}
	dgst := digest.SHA256.FromBytes(b)

	newDesc := oldDesc
	newDesc.Size = int64(len(b))
	newDesc.Digest = dgst

	if ref == "" {
		ref = dgst.String()
	}

	if err := content.WriteBlob(ctx, cs, ref, bytes.NewReader(b), newDesc, content.WithLabels(labels)); err != nil {
		return nil, err
	}

	return &newDesc, nil
}

func readJSON(ctx context.Context, cs content.Store, x interface{}, desc ocispec.Descriptor) (map[string]string, error) {
	info, err := cs.Info(ctx, desc.Digest)
	if err != nil {
		return nil, err
	}

	labels := info.Labels
	b, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(b, x); err != nil {
		return nil, err
	}

	return labels, nil
}
