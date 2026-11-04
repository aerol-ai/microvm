package docker

import (
	"context"
	"fmt"
	"io"
)

// A Firecracker snapshot is a stopped VM's root filesystem as a one-layer
// image (internal/runtime/firecracker CreateSnapshot). On a Docker node it
// lands in this daemon's store beside the snapshots this engine commits, so
// the snapshot push, delete and image GC see one kind of snapshot image
// whichever runtime made it. The containerd engine has the same two methods.

// ImportRootfsImage imports rootfs, a tar of a filesystem tree, as the image
// imageRef (docker import) and returns the image's ID. An image already
// under that name loses the tag to the new one.
func (c *Client) ImportRootfsImage(ctx context.Context, imageRef string, rootfs io.Reader) (string, error) {
	if err := c.ImportImage(ctx, ImportImageRequest{DestTag: imageRef, Tar: rootfs}); err != nil {
		return "", err
	}
	info, err := c.inspectImage(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("inspect imported image %s: %w", imageRef, err)
	}
	return info.ID, nil
}

// ExportImageArchive writes the local image imageRef to w as a docker save
// archive (skopeo's docker-archive: transport reads it). ok is false, with
// nothing written, when the daemon has no such image.
func (c *Client) ExportImageArchive(ctx context.Context, imageRef string, w io.Writer) (bool, error) {
	exists, err := c.ImageExists(ctx, imageRef)
	if err != nil || !exists {
		return false, err
	}
	body, err := c.ExportImageTar(ctx, imageRef)
	if err != nil {
		return false, err
	}
	defer body.Close()
	if _, err := io.Copy(w, body); err != nil {
		return false, fmt.Errorf("export image %s: %w", imageRef, err)
	}
	return true, nil
}
