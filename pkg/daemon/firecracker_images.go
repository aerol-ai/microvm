package daemon

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/config"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// engineImageArchiver is what both container engines (docker.Client and the
// containerd driver) offer a Firecracker snapshot: import a filesystem tar as
// an image, and write a local image out as an archive skopeo can read.
type engineImageArchiver interface {
	ImportRootfsImage(ctx context.Context, ref string, rootfs io.Reader) (string, error)
	ExportImageArchive(ctx context.Context, ref string, w io.Writer) (bool, error)
}

// firecrackerImageStore is the node's container engine as the Firecracker
// driver's ImageStore. Firecracker snapshots go into the engine that owns
// the node's other snapshots, so the snapshot pusher (docker or containerd,
// chosen the same way in startSnapshotPushReconciler), the delete and image
// GC handle them unchanged.
type firecrackerImageStore struct {
	engine engineImageArchiver
	// transport is the skopeo transport for engine's archive format.
	transport string
	// dir holds an exported archive while skopeo reads it: on disk under
	// the templates dir, not under /run, which is memory on most hosts.
	dir string
}

func newFirecrackerImageStore(cfg config.Config, dockerClient *docker.Client, ctd *containerdEngineWiring) fcruntime.ImageStore {
	dir := filepath.Join(cfg.FirecrackerTemplatesDir, "_exports")
	if cfg.ContainerEngine == models.ContainerEngineContainerd && ctd != nil && ctd.driver != nil {
		return &firecrackerImageStore{engine: ctd.driver, transport: "oci-archive", dir: dir}
	}
	if dockerClient == nil {
		return nil
	}
	return &firecrackerImageStore{engine: dockerClient, transport: "docker-archive", dir: dir}
}

func (s *firecrackerImageStore) ImportRootfs(ctx context.Context, ref string, rootfs io.Reader) (string, error) {
	return s.engine.ImportRootfsImage(ctx, ref, rootfs)
}

// OpenImage writes ref out to an archive file for skopeo and returns its
// transport reference and a cleanup that deletes the file.
func (s *firecrackerImageStore) OpenImage(ctx context.Context, ref string) (string, func(), bool, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", nil, false, err
	}
	f, err := os.CreateTemp(s.dir, "image-*.tar")
	if err != nil {
		return "", nil, false, err
	}
	name := f.Name()
	ok, err := s.engine.ExportImageArchive(ctx, ref, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || !ok {
		_ = os.Remove(name)
		return "", nil, false, err
	}
	return s.transport + ":" + name, func() { _ = os.Remove(name) }, true, nil
}
