package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// DefaultBuildKitAddr is the buildkitd control socket the bootstrap installs.
const DefaultBuildKitAddr = "unix:///run/buildkit/buildkitd.sock"

// BuildKitBuilder builds images for the containerd engine by shelling out to
// `buildctl` against a local buildkitd whose containerd worker writes into the
// aerolvm namespace. It satisfies the same ImageBuilder seam as the dockerd
// build path (BuildImage(ctx, docker.BuildImageRequest)), so the v1/daytona
// build handlers work unchanged once the engine-gate is lifted.
//
// buildctl is used instead of the moby/buildkit Go client to avoid pulling
// buildkit's large dependency tree into the daemon; buildctl ships alongside
// buildkitd from the same release.
type BuildKitBuilder struct {
	addr    string // BUILDKIT_HOST
	buildct string // buildctl binary path
	logger  *slog.Logger
}

// NewBuildKitBuilder returns a builder targeting addr (default
// DefaultBuildKitAddr). buildctlPath defaults to "buildctl" on PATH.
func NewBuildKitBuilder(addr, buildctlPath string, logger *slog.Logger) *BuildKitBuilder {
	if strings.TrimSpace(addr) == "" {
		addr = DefaultBuildKitAddr
	}
	if strings.TrimSpace(buildctlPath) == "" {
		buildctlPath = "buildctl"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BuildKitBuilder{addr: addr, buildct: buildctlPath, logger: logger}
}

// BuildImage builds req.DockerfileContent (+ optional context tar) into an image
// tagged req.Tag, exported and unpacked into the containerd image store so a
// later create can run it directly.
func (b *BuildKitBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	tag := strings.TrimSpace(req.Tag)
	if tag == "" {
		return errors.New("build image: tag is required")
	}
	dockerfile := strings.TrimRight(req.DockerfileContent, "\n") + "\n"
	if strings.TrimSpace(dockerfile) == "" {
		return errors.New("build image: dockerfile content is required")
	}

	dir, err := os.MkdirTemp("", "aerolvm-buildkit-")
	if err != nil {
		return fmt.Errorf("build image: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if len(req.ContextTar) > 0 {
		if err := extractTar(req.ContextTar, dir); err != nil {
			return fmt.Errorf("build image: extract context: %w", err)
		}
	}
	// The Dockerfile is authoritative even if a context tar also carried one.
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return fmt.Errorf("build image: write dockerfile: %w", err)
	}

	// unpack=true realizes the image's layers in the snapshotter so a subsequent
	// WithNewSnapshot create can use it without an extra pull/unpack.
	args := []string{
		"--addr", b.addr,
		"build",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + dir,
		"--local", "dockerfile=" + dir,
		"--output", "type=image,name=" + tag + ",unpack=true",
	}
	cmd := exec.CommandContext(ctx, b.buildct, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if req.OnLog != nil {
		// buildctl writes progress to stderr; tee it to the caller's log sink.
		cmd.Stderr = io.MultiWriter(&stderr, logLineWriter(req.OnLog))
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("buildctl build %s: %w: %s", tag, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ImageBuilder is the full image-builder surface the v1 / daytona build
// handlers require for the containerd engine. It composes the buildctl-backed
// BuildImage with the driver's containerd-native image operations
// (ImageExists / RemoveImage) and the registry pusher, so it is a drop-in for
// the same seam the dockerd path satisfies with *pkg/docker.Client.
type ImageBuilder struct {
	build  *BuildKitBuilder
	driver *Driver
	pusher *RegistryPusher
}

// NewImageBuilder wires a containerd image builder from a driver (image store
// + registry push) and a buildkit builder (Dockerfile compile).
func NewImageBuilder(driver *Driver, build *BuildKitBuilder) *ImageBuilder {
	return &ImageBuilder{build: build, driver: driver, pusher: NewRegistryPusher(driver)}
}

func (b *ImageBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	return b.build.BuildImage(ctx, req)
}

func (b *ImageBuilder) ImageExists(ctx context.Context, imageRef string) (bool, error) {
	return b.driver.ImageExists(ctx, imageRef)
}

func (b *ImageBuilder) PushImage(ctx context.Context, req docker.PushImageRequest) (string, error) {
	return b.pusher.PushImage(ctx, req)
}

func (b *ImageBuilder) RemoveImage(ctx context.Context, imageRef string) error {
	return b.driver.RemoveImage(ctx, imageRef)
}

// RefreshTag is a no-op on containerd. The dockerd builder bumps
// Metadata.LastTagTime so its built-image janitor doesn't GC a cache-hit tag;
// containerd's built-image lifecycle is snapshot/lease-driven, not tag-time
// metadata, so there is nothing to refresh.
func (b *ImageBuilder) RefreshTag(ctx context.Context, fullRef string) error {
	return nil
}

// logLineWriter adapts a line callback to an io.Writer, flushing per newline.
type logLineWriter func(string)

func (w logLineWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			w(line)
		}
	}
	return len(p), nil
}

// Bounds on an extracted build context, capping host disk and inode use from a
// crafted context tar (many entries, or entries that extract to far more than
// the tar's own size). Generous ceilings — real build contexts are far smaller;
// these only stop abuse. Vars, not consts, so tests can lower them.
var (
	maxContextEntries          = 100_000
	maxContextTotalBytes int64 = 2 << 30 // 2 GiB extracted
)

func extractTar(data []byte, dir string) error {
	tr := tar.NewReader(bytes.NewReader(data))
	entries := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxContextEntries {
			return fmt.Errorf("build context has too many entries (max %d)", maxContextEntries)
		}
		// Reject path traversal before any filesystem call. filepath.IsLocal is
		// the lexical check CodeQL's zip-slip query models as a sanitizer: it
		// rejects empty, absolute, and ".." names. The prefix check stays as
		// a backstop because filepath.Join drops the base when a later element
		// is absolute, so a name that slipped past IsLocal still fails closed.
		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("tar entry escapes context dir: %q", hdr.Name)
		}
		target := filepath.Join(dir, hdr.Name)
		cleanDir := filepath.Clean(dir)
		if target != cleanDir && !strings.HasPrefix(target, cleanDir+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes context dir: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			// Bound the running total; CopyN of remaining+1 lets us detect an
			// entry that would push the extraction past the ceiling (io.CopyN,
			// not io.Copy, so a lying/oversized entry cannot write unbounded).
			remaining := maxContextTotalBytes - total
			n, cErr := io.CopyN(f, tr, remaining+1)
			total += n
			if cErr != nil && cErr != io.EOF {
				_ = f.Close()
				return cErr
			}
			if n > remaining {
				_ = f.Close()
				return fmt.Errorf("build context exceeds %d bytes", maxContextTotalBytes)
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}
