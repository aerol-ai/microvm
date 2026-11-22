package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// DefaultBuildKitAddr is the buildkitd control socket the bootstrap installs.
const DefaultBuildKitAddr = "unix:///run/buildkit/buildkitd.sock"

// BuildKitBuilder builds images for the containerd engine by shelling out to
// `buildctl` against a local buildkitd. It satisfies the same ImageBuilder
// seam as the dockerd build path (BuildImage(ctx, docker.BuildImageRequest)),
// so the v1/daytona build handlers work unchanged once the engine-gate is
// lifted. Two kinds of buildkitd:
//   - root, with a containerd worker that writes the image straight into the
//     aerolvm namespace (today's, and the default in privilege mode single);
//   - rootless (WithArchiveImport, SB_CONTAINERD_BUILDKIT_ROOTLESS): BuildKit's
//     rootless mode with its OCI worker, which cannot reach containerd. The
//     build streams an OCI archive to buildctl's stdout, and the driver
//     imports it (Driver.ImportBuildArchive), through the root helper's gate
//     in privilege mode split.
//
// buildctl is used instead of the moby/buildkit Go client to avoid pulling
// buildkit's large dependency tree into the daemon; buildctl ships alongside
// buildkitd from the same release.
type BuildKitBuilder struct {
	addr    string // BUILDKIT_HOST
	buildct string // buildctl binary path
	logger  *slog.Logger
	// contextIDs hands each context unpack its own uid and gid (see
	// unpackContext).
	contextIDs *contextIDPool
	// archive, when set, imports a rootless build's OCI archive, at most
	// maxImageBytes of it.
	archive       buildArchiveImporter
	maxImageBytes int64
}

// buildArchiveImporter imports a rootless build's OCI archive (*Driver).
type buildArchiveImporter interface {
	ImportBuildArchive(ctx context.Context, ref string, archive io.Reader, maxBytes int64, finished func() error) error
}

// maxBuildTrailer is how much buildctl may still write once the archive's
// end-of-archive blocks have been read: tar writers pad to a record (10 KiB
// by default) at most. More means the output is not one archive.
const maxBuildTrailer = 64 << 10

// buildctlWaitDelay bounds how long Wait waits for buildctl's pipes once
// buildctl has exited or been stopped: anything it left running that holds
// them must not hold the build up. A var so tests can shorten it.
var buildctlWaitDelay = 5 * time.Second

// buildDirPrefix names every build's temp folder; SweepBuildDirs looks for it.
const buildDirPrefix = "aerolvm-buildkit-"

// ContextUnpackFlag is the sandboxd mode that unpacks one build context:
// sandboxd re-execs itself with it, and cmd/sandboxd hands it to
// RunContextUnpack.
const ContextUnpackFlag = "--build-context-unpack"

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
	return &BuildKitBuilder{
		addr:       addr,
		buildct:    buildctlPath,
		logger:     logger,
		contextIDs: sharedContextIDPool(config.DefaultBuildContextIDBase, config.DefaultBuildContextIDBase, config.BuildContextIDCount),
	}
}

// WithContextIDBase sets the first of the config.BuildContextIDCount ids
// that unpack build contexts (SB_CONTAINERD_BUILD_CONTEXT_ID_BASE; config
// checks the range). Each unpack runs as one of them, uid and gid alike.
func (b *BuildKitBuilder) WithContextIDBase(base int) *BuildKitBuilder {
	b.contextIDs = sharedContextIDPool(base, base, config.BuildContextIDCount)
	return b
}

// WithArchiveImport makes the builder drive a rootless buildkitd: each build
// exports an OCI archive on buildctl's stdout, which imp reads, at most
// maxBytes of it, and names as the build's tag.
func (b *BuildKitBuilder) WithArchiveImport(imp buildArchiveImporter, maxBytes int64) *BuildKitBuilder {
	b.archive = imp
	b.maxImageBytes = maxBytes
	return b
}

// ImportsArchives reports whether this builder drives a rootless buildkitd
// (WithArchiveImport).
func (b *BuildKitBuilder) ImportsArchives() bool { return b.archive != nil }

// CheckContextUnpacker looks, once at daemon start, for what would make every
// build with a context fail: the unpacker runs sandboxd as an id that owns
// nothing, so it reaches the binary only through "other" permission bits on
// the binary and every folder above it, and it needs CAP_SYS_ADMIN for its
// PID namespace. It logs a warning whose error says what to change, and
// returns the problem; nil when the unpacker is not used here.
func (b *BuildKitBuilder) CheckContextUnpacker() error {
	if !unpackInChild() {
		return nil
	}
	err := checkContextUnpacker()
	if err != nil {
		b.logger.Warn("image builds with a build context will fail on this node: the build-context unpacker cannot start", "error", err)
	}
	return err
}

// contextIDPool hands out [uidBase, uidBase+n) and [gidBase, gidBase+n) in
// pairs, one pair per unpack at a time. A process with an id of its own
// cannot be reached by any other non-root process through /proc (its fd and
// cwd links) or ptrace, whatever the timing; a shared id (nobody, say) can,
// in the moment after exec before the child turns dumping off. Production
// passes the same base twice; tests that are not root pass their own uid and
// gid with n = 1.
type contextIDPool struct {
	uidBase, gidBase int
	free             chan int // offsets not in use
}

var (
	contextIDPoolsMu sync.Mutex
	contextIDPools   = map[[3]int]*contextIDPool{}
)

// sharedContextIDPool returns the one pool for a range, so two builders
// over the same ids can never hand the same id out twice.
func sharedContextIDPool(uidBase, gidBase, n int) *contextIDPool {
	contextIDPoolsMu.Lock()
	defer contextIDPoolsMu.Unlock()
	key := [3]int{uidBase, gidBase, n}
	if p, ok := contextIDPools[key]; ok {
		return p
	}
	p := &contextIDPool{uidBase: uidBase, gidBase: gidBase, free: make(chan int, n)}
	for i := range n {
		p.free <- i
	}
	contextIDPools[key] = p
	return p
}

// acquire waits for a free pair, or for ctx.
func (p *contextIDPool) acquire(ctx context.Context) (uid, gid, offset int, err error) {
	select {
	case off := <-p.free:
		return p.uidBase + off, p.gidBase + off, off, nil
	case <-ctx.Done():
		return 0, 0, 0, ctx.Err()
	}
}

func (p *contextIDPool) release(offset int) { p.free <- offset }

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

	// dir stays root's and 0700. The context goes one level down, in a
	// folder the unpacker owns while it runs; the unpacker reaches it only
	// through the descriptor it is handed, never by a path through dir.
	// removeBuildDir runs on every exit, never follows a link, and holds a
	// bounded number of descriptors however deep the tree.
	dir, err := os.MkdirTemp("", buildDirPrefix)
	if err != nil {
		return fmt.Errorf("build image: temp dir: %w", err)
	}
	defer func() { _ = removeBuildDir(dir) }()
	contextDir := filepath.Join(dir, "context")

	if len(req.ContextTar) > 0 {
		if err := b.unpackContext(ctx, req.ContextTar, contextDir); err != nil {
			return fmt.Errorf("build image: extract context: %w", err)
		}
	} else if err := os.Mkdir(contextDir, 0o700); err != nil {
		return fmt.Errorf("build image: context dir: %w", err)
	}
	// The Dockerfile is authoritative even if a context tar also carried one.
	if err := writeDockerfile(contextDir, dockerfile); err != nil {
		return fmt.Errorf("build image: write dockerfile: %w", err)
	}

	// A root buildkitd's containerd worker names the image itself, and
	// unpack=true realizes its layers in the snapshotter so a subsequent
	// WithNewSnapshot create can use it without an extra pull/unpack. A
	// rootless one hands the image over as an OCI archive on stdout.
	output := "type=image,name=" + tag + ",unpack=true"
	if b.archive != nil {
		output = "type=oci,dest=-"
	}
	args := []string{
		"--addr", b.addr,
		"build",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + contextDir,
		"--local", "dockerfile=" + contextDir,
		"--output", output,
	}
	if req.ForcePull {
		// Resolve FROM, COPY --from and ONBUILD images from their registry,
		// never from images already on this node (see
		// docker.BuildImageRequest.ForcePull).
		args = append(args, "--opt", "image-resolve-mode=pull")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, b.buildct, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if req.OnLog != nil {
		// buildctl writes progress to stderr; tee it to the caller's log sink.
		cmd.Stderr = io.MultiWriter(&stderr, logLineWriter(req.OnLog))
	}
	if b.archive != nil {
		return b.importBuild(runCtx, cancel, cmd, tag, &stderr)
	}
	if err := cmd.Run(); err != nil {
		return buildctlError(tag, err, &stderr)
	}
	return nil
}

// importBuild runs a rootless build and imports the OCI archive buildctl
// streams on its stdout. The image is named only once buildctl has exited
// cleanly (the importer's finished step). When the import fails first,
// buildctl is stopped; if it had already failed on its own (a RUN step, a
// pull), its error is the one reported, since it says why.
func (b *BuildKitBuilder) importBuild(ctx context.Context, cancel context.CancelFunc, cmd *exec.Cmd, tag string, stderr *bytes.Buffer) error {
	cmd.WaitDelay = buildctlWaitDelay
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("buildctl build %s: %w", tag, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("buildctl build %s: %w", tag, err)
	}
	waited := false
	var waitErr error
	wait := func() error {
		if !waited {
			waited = true
			waitErr = cmd.Wait()
		}
		return waitErr
	}
	finished := func() error {
		n, err := io.Copy(io.Discard, io.LimitReader(out, maxBuildTrailer+1))
		if err == nil && n > maxBuildTrailer {
			err = fmt.Errorf("buildctl build %s: its output goes on past the end of the image archive", tag)
		}
		if err != nil {
			cancel()
			_ = wait()
			return err
		}
		if err := wait(); err != nil {
			return buildctlError(tag, err, stderr)
		}
		return nil
	}
	err = b.archive.ImportBuildArchive(ctx, tag, out, b.maxImageBytes, finished)
	if err == nil || waited {
		return err
	}
	cancel()
	if werr := wait(); werr != nil && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() > 0 {
		return buildctlError(tag, werr, stderr)
	}
	return fmt.Errorf("buildctl build %s: import the image: %w", tag, err)
}

// buildctlError is a failed buildctl run, with what it wrote to stderr.
func buildctlError(tag string, err error, stderr *bytes.Buffer) error {
	return fmt.Errorf("buildctl build %s: %w: %s", tag, err, strings.TrimSpace(stderr.String()))
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
	// maxContextDepth bounds how deep folders nest. Work on a path grows with
	// its depth, and the parent's lockdown holds one descriptor per level; a
	// name of "a/" repeated would otherwise reach 2048 levels within
	// PATH_MAX, or 500,000 within the 1 MiB names Go's tar reader allows.
	// Real contexts stay far shallower (deep npm trees reach a few dozen).
	maxContextDepth = 256
)

// maxContextNameBytes is PATH_MAX: no longer name can be opened in one call.
const maxContextNameBytes = 4096

// unpackContext unpacks a build-context tar into dir, which must not exist
// yet. A root sandboxd on Linux does it in a child with no rights
// (unpackContextInChild), so a bug in the unpacking cannot write as root.
// Everywhere else it unpacks in process; unpackInChild, in
// buildkit_unpack_linux.go and buildkit_unpack_other.go, says why.
func (b *BuildKitBuilder) unpackContext(ctx context.Context, data []byte, dir string) error {
	if unpackInChild() {
		uid, gid, off, err := b.contextIDs.acquire(ctx)
		if err != nil {
			return fmt.Errorf("build context unpacker: wait for a free id: %w", err)
		}
		// Back in the pool only once unpackContextInChild returns: by then
		// the child and anything it started are dead (its PID namespace went
		// with it) and the tree is root's, so the ids own nothing.
		defer b.contextIDs.release(off)
		return unpackContextInChild(ctx, data, dir, uid, gid)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return extractTar(data, dir)
}

// writeDockerfile puts the request's Dockerfile at the top of the context,
// replacing any file the context tar carried there (a folder there fails the
// build, as it always has). The unprivileged unpacker made what is in the
// folder, so this root write never follows what is already there: the old
// entry is removed through an os.Root, and O_EXCL makes the create refuse
// anything that took its place, a symlink included.
func writeDockerfile(dir, content string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat("Dockerfile"); err == nil && info.IsDir() {
		return errors.New("the build context has a folder named Dockerfile")
	}
	if err := root.Remove("Dockerfile"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile("Dockerfile", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func extractTar(data []byte, dir string) error {
	return extractTarStream(bytes.NewReader(data), dir, maxContextEntries, maxContextTotalBytes)
}

// extractTarStream unpacks a tar stream into dir under the given bounds. The
// unpacking child calls it with dir "." once it has entered the folder it was
// handed, so the bounds come in as arguments rather than from the vars above.
//
// Only folders and regular files are made. Symlinks, hard links, devices and
// pipes are skipped: a build context needs none of them, and a link made here
// is one a later entry could write through.
func extractTarStream(r io.Reader, dir string, maxEntries int, maxBytes int64) error {
	// Every write goes through root, an os.Root on dir, whose kernel-level
	// path resolution never leaves dir. That replaces the old backstop, a
	// prefix check on filepath.Join(dir, name), which existed because Join
	// drops dir when a later element is absolute; os.Root has no such case.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(r)
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
		if entries > maxEntries {
			return fmt.Errorf("build context has too many entries (max %d)", maxEntries)
		}
		// Reject path traversal before any filesystem call. filepath.IsLocal is
		// the lexical check CodeQL's zip-slip query models as a sanitizer: it
		// rejects empty, absolute, and ".." names.
		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("tar entry escapes context dir: %q", hdr.Name)
		}
		// Every step on a path costs in proportion to its depth, here and in
		// the parent's lockdown, so a long or deep name is refused outright.
		if len(hdr.Name) > maxContextNameBytes {
			return fmt.Errorf("tar entry name is longer than %d bytes: %.64q...", maxContextNameBytes, hdr.Name)
		}
		if depth := strings.Count(filepath.Clean(hdr.Name), string(filepath.Separator)) + 1; depth > maxContextDepth {
			return fmt.Errorf("tar entry is nested deeper than %d folders: %.64q...", maxContextDepth, hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(hdr.Name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(hdr.Name), 0o755); err != nil {
				return err
			}
			// A name the archive already wrote (tar -r appends; a repo's
			// .git/objects are 0444) is replaced, not opened again: the
			// unpacker owns that file but, not being root, may not write it.
			// The later entry wins outright, mode included, as with tar -x.
			if info, err := root.Lstat(hdr.Name); err == nil && info.Mode().IsRegular() {
				if err := root.Remove(hdr.Name); err != nil {
					return err
				}
			}
			f, err := root.OpenFile(hdr.Name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			// Bound the running total; CopyN of remaining+1 lets us detect an
			// entry that would push the extraction past the ceiling (io.CopyN,
			// not io.Copy, so a lying/oversized entry cannot write unbounded).
			remaining := maxBytes - total
			n, cErr := io.CopyN(f, tr, remaining+1)
			total += n
			if cErr != nil && cErr != io.EOF {
				_ = f.Close()
				return cErr
			}
			if n > remaining {
				_ = f.Close()
				return fmt.Errorf("build context exceeds %d bytes", maxBytes)
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}
