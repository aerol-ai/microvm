// Package oci builds an ext4 root filesystem image from an OCI container
// reference. It is the input to the Firecracker driver's cold-boot path:
// given "docker://python:3.11", produce a single file rootfs.ext4 that a
// Firecracker drive entry can point at.
//
// The pipeline is three subprocesses chained on the host:
//
//  1. skopeo copy docker://<ref> oci:<staging-dir>:<tag>
//     Pull the image manifest + layer blobs into a local OCI-layout dir.
//     Stateless on success; failure leaves the staging dir partial and the
//     caller is expected to clean up via the Result's CleanupDir method.
//
//  2. umoci unpack --image <staging-dir>:<tag> <bundle-dir>
//     Materialize the layers into a runc-style bundle. The rootfs lives at
//     <bundle-dir>/rootfs/. config.json is written too but ignored — we
//     read the OCI config from the staging dir directly so layer ordering
//     is unambiguous.
//
//  3. mkfs.ext4 -d <bundle-dir>/rootfs/ -F <out.ext4>
//     Build a single-file ext4 filesystem from the materialized rootfs.
//     Size is auto-sized by mkfs.ext4 (the -d flag computes minimum
//     necessary blocks plus the journal); the caller can set MinSizeMiB
//     to round up so guest writes have headroom before the filesystem
//     fills.
//
// What does NOT live here: the per-sandbox overlay file (that's the
// runtime driver's job; the overlay is a sparse file plus a writeback
// drive entry pointing at it). What lives here is only the base
// read-only rootfs.ext4 that overlay sits on top of.
//
// External-tool dependencies are intentional — reimplementing OCI unpack
// and ext4 in Go would be a project on its own. The tools are well-known,
// scriptable, and the test wraps them with a fake-binary shim so the
// package's own tests don't require them on the host. Production hosts
// install skopeo + umoci + e2fsprogs via Ansible.
package oci

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// stderrTailCap caps how many bytes of subprocess stderr we hold in
// memory per stage. Head-keep — the first error from a misconfigured
// skopeo (e.g. "unauthorized: incorrect username or password") is what
// the operator needs to see; subsequent retries or noise add nothing.
const stderrTailCap = 16 << 10 // 16 KiB

// Config carries the absolute paths to the external tools, so the
// daemon's config can override them and tests can substitute fakes
// without an env-var dance. All three are required; New rejects an
// empty path rather than silently picking up something on $PATH (which
// would be a security smell on a daemon that pulls remote images).
type Config struct {
	// SkopeoBin: path to `skopeo`. Pulls the OCI image. Apt/yum/brew
	// install ship skopeo as a static binary; the daemon does NOT
	// expect a Skopeo daemon.
	SkopeoBin string
	// UmociBin: path to `umoci`. Unpacks OCI layout into a bundle.
	UmociBin string
	// Mkfs4Bin: path to `mkfs.ext4` (from e2fsprogs). Builds the
	// single-file ext4 image from the unpacked rootfs.
	Mkfs4Bin string
	// WorkDir: the parent directory under which per-build staging trees
	// live. Each Builder.Build call creates a fresh subdirectory here.
	// Should be on a filesystem with at least 2x the largest image size
	// in free space (skopeo + umoci both materialize layers).
	WorkDir string
}

// Builder is a Config-bound handle for kicking off image builds. The
// zero value is not usable; construct via New.
type Builder struct {
	cfg Config
}

// New validates the config and returns a Builder. All three tool paths
// are required: a missing path at boot is preferable to a confusing
// "exec: <empty>: no such file or directory" at the first sandbox
// create.
func New(cfg Config) (*Builder, error) {
	if cfg.SkopeoBin == "" {
		return nil, errors.New("oci: SkopeoBin is required")
	}
	if cfg.UmociBin == "" {
		return nil, errors.New("oci: UmociBin is required")
	}
	if cfg.Mkfs4Bin == "" {
		return nil, errors.New("oci: Mkfs4Bin is required")
	}
	if cfg.WorkDir == "" {
		return nil, errors.New("oci: WorkDir is required")
	}
	return &Builder{cfg: cfg}, nil
}

// BuildRequest is one image build's inputs. ImageRef is a skopeo-style
// reference ("docker://python:3.11", "oci-archive:/path/foo.tar", etc.) —
// skopeo handles the transport prefix, so the daemon passes it through
// verbatim. OutPath is the destination rootfs.ext4 file; existing files
// are overwritten (mkfs.ext4 -F). MinSizeMiB rounds the image up so the
// guest has writable headroom on a sparse-but-fixed-size ext4; zero
// means "minimum size as computed by mkfs.ext4 -d".
type BuildRequest struct {
	ImageRef   string
	OutPath    string
	MinSizeMiB int
	// Tag is the OCI tag to apply inside the staging layout. Almost
	// always "latest" — kept as a knob because skopeo's docker://
	// transport sometimes needs the tag explicitly when the source ref
	// doesn't carry one.
	Tag string
}

// Result reports a finished build. RootfsPath is OutPath echoed back for
// the caller's convenience. StagingDir is the per-build temp tree;
// callers should CleanupDir after they have the rootfs in a permanent
// location. SizeBytes is the rootfs.ext4 file size after mkfs (NOT the
// unpacked-rootfs size — guests see this as the disk size).
type Result struct {
	RootfsPath string
	StagingDir string
	SizeBytes  int64
}

// CleanupDir removes the staging directory. Best-effort: a stale tree
// only costs disk, not correctness. The runtime driver calls this once
// it has hard-linked the rootfs into the per-template directory.
func (r Result) CleanupDir() error {
	if r.StagingDir == "" {
		return nil
	}
	return os.RemoveAll(r.StagingDir)
}

// Build runs the three-stage pipeline. Each stage's stderr tail is
// surfaced in the returned error on failure so the operator sees the
// real cause (most commonly "401 unauthorized" from skopeo or "no space
// left" from mkfs.ext4). On success the temp tree is preserved at
// Result.StagingDir until the caller cleans it up.
func (b *Builder) Build(ctx context.Context, req BuildRequest) (*Result, error) {
	if req.ImageRef == "" {
		return nil, errors.New("oci: ImageRef is required")
	}
	if req.OutPath == "" {
		return nil, errors.New("oci: OutPath is required")
	}
	if req.Tag == "" {
		req.Tag = "latest"
	}
	if err := os.MkdirAll(b.cfg.WorkDir, 0o755); err != nil {
		return nil, fmt.Errorf("oci: mkdir workdir: %w", err)
	}
	staging, err := os.MkdirTemp(b.cfg.WorkDir, "oci-build-*")
	if err != nil {
		return nil, fmt.Errorf("oci: mkdtemp: %w", err)
	}
	ociDir := filepath.Join(staging, "image")
	bundleDir := filepath.Join(staging, "bundle")

	// Stage 1: skopeo copy <ref> oci:<dir>:<tag>
	if err := b.runSkopeo(ctx, req.ImageRef, ociDir, req.Tag); err != nil {
		_ = os.RemoveAll(staging)
		return nil, err
	}
	// Stage 2: umoci unpack --image <dir>:<tag> <bundle>
	if err := b.runUmoci(ctx, ociDir, req.Tag, bundleDir); err != nil {
		_ = os.RemoveAll(staging)
		return nil, err
	}
	// Stage 3: mkfs.ext4 -d <bundle>/rootfs -F <out>
	rootfsSrc := filepath.Join(bundleDir, "rootfs")
	if err := b.runMkfs(ctx, rootfsSrc, req.OutPath, req.MinSizeMiB); err != nil {
		_ = os.RemoveAll(staging)
		return nil, err
	}
	stat, err := os.Stat(req.OutPath)
	if err != nil {
		_ = os.RemoveAll(staging)
		return nil, fmt.Errorf("oci: stat output: %w", err)
	}
	return &Result{
		RootfsPath: req.OutPath,
		StagingDir: staging,
		SizeBytes:  stat.Size(),
	}, nil
}

// runSkopeo wraps stage 1. The "--insecure-policy" flag bypasses
// skopeo's host signature-policy file — production hosts ship a policy
// that allows-all (signature verification is upstream of this pipeline);
// the flag keeps the daemon working even when /etc/containers/policy.json
// is missing (common on minimal base images).
func (b *Builder) runSkopeo(ctx context.Context, ref, ociDir, tag string) error {
	args := []string{
		"--insecure-policy",
		"copy",
		ref,
		"oci:" + ociDir + ":" + tag,
	}
	return runStage(ctx, "skopeo", b.cfg.SkopeoBin, args)
}

// runUmoci wraps stage 2. --rootless lets the unpack work without
// elevated privileges (the daemon may or may not have CAP_CHOWN — running
// rootless means even root-owned files in the layer end up owned by the
// daemon's UID, which is fine for an immutable rootfs.ext4 image).
func (b *Builder) runUmoci(ctx context.Context, ociDir, tag, bundleDir string) error {
	args := []string{
		"unpack",
		"--rootless",
		"--image", ociDir + ":" + tag,
		bundleDir,
	}
	return runStage(ctx, "umoci", b.cfg.UmociBin, args)
}

// runMkfs wraps stage 3. -d copies a directory in as the initial
// contents; -F overwrites without prompting; we pass an explicit size in
// MiB only when MinSizeMiB > 0 (mkfs.ext4's -d alone would size the
// filesystem to the minimum needed, leaving zero room for guest writes).
func (b *Builder) runMkfs(ctx context.Context, rootfsSrc, outPath string, minSizeMiB int) error {
	args := []string{
		"-d", rootfsSrc,
		"-F",
	}
	// Pinning the UUID would make build output deterministic, but mkfs
	// doesn't accept a "-U <uuid>" option universally and the runtime
	// driver doesn't rely on the UUID — skip it.
	if minSizeMiB > 0 {
		args = append(args, outPath, strconv.Itoa(minSizeMiB)+"M")
	} else {
		args = append(args, outPath)
	}
	return runStage(ctx, "mkfs.ext4", b.cfg.Mkfs4Bin, args)
}

// runStage executes one subprocess with bounded stderr capture, returning
// an error that names the stage so failures in the chain are unambiguous
// from log lines alone.
func runStage(ctx context.Context, label, binary string, args []string) error {
	if binary == "" {
		return fmt.Errorf("oci: %s binary not configured", label)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	tail := newCappedBuffer(stderrTailCap)
	cmd.Stderr = tail
	cmd.Stdout = tail
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("oci: %s %s: %w (stderr: %s)",
			label, strings.Join(args, " "), err, tail.String())
	}
	return nil
}

// cappedBuffer is a head-keep, goroutine-safe writer. Same shape as the
// one in internal/runtime/firecracker/vmm.go but duplicated here so the
// oci package has no import cycle with the runtime package. Tiny; not
// worth a shared util.
type cappedBuffer struct {
	mu    sync.Mutex
	cap   int
	buf   []byte
	dropd int
}

func newCappedBuffer(cap int) *cappedBuffer { return &cappedBuffer{cap: cap} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) >= b.cap {
		b.dropd += len(p)
		return len(p), nil
	}
	take := len(p)
	if len(b.buf)+take > b.cap {
		take = b.cap - len(b.buf)
		b.dropd += len(p) - take
	}
	b.buf = append(b.buf, p[:take]...)
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dropd == 0 {
		return string(b.buf)
	}
	return fmt.Sprintf("%s\n[... %d more bytes dropped ...]", string(b.buf), b.dropd)
}
