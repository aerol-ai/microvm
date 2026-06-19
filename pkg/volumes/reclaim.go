package volumes

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ExecRunner is the production Runner: it executes the command (with extraEnv
// appended to the process environment) and folds any stderr/stdout into the
// returned error for operator logs. Reclaim commands produce little output, so
// capturing combined output is cheap.
func ExecRunner(ctx context.Context, extraEnv []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("%s: %w: %s", name, err, trimmed)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Reclaimer deletes the backing bytes of a deleted platform volume. It is the
// missing consumer of the pending_volume_deletions ledger: DeletePlatformVolume
// only removes the metadata row and records coordinates; this is what actually
// reclaims the S3 prefix / NFS directory.
//
// The repo deliberately carries no AWS SDK — sandbox mounts are realized by the
// mount-s3 binary — so backend deletion shells out to the same CLI tooling the
// host already needs (the AWS CLI for S3, mount(8) + the kernel NFS client for
// NFS). Commands run through an injected Runner so the command construction is
// unit-testable offline; make test never executes a real delete.
type Reclaimer struct {
	backend Backend
	run     Runner
	// mountRoot is the parent dir transient NFS mounts are created under. The
	// daemon points this at a private, root-owned scratch dir.
	mountRoot string
}

// Runner executes one external command with extraEnv appended to its
// environment. The default wires exec.CommandContext; tests inject a recorder.
// extraEnv carries S3 static credentials so the AWS CLI deletes with the same
// keys the mount path uses rather than relying on the host's ambient chain.
type Runner func(ctx context.Context, extraEnv []string, name string, args ...string) error

// NewReclaimer builds a Reclaimer for the operator's configured backend. region
// / endpoint live on the Backend so S3 deletes hit the same store the mounts do.
func NewReclaimer(backend Backend, mountRoot string, run Runner) *Reclaimer {
	return &Reclaimer{backend: backend, run: run, mountRoot: strings.TrimSpace(mountRoot)}
}

// Reclaim deletes the data at source for the given backend kind. It is
// idempotent: deleting an already-empty or already-gone prefix/dir is success,
// so a ledger row can be retried until the row is removed. backendKind is the
// volume's stored backend (authoritative over the operator's current default,
// so a volume created under s3 still reclaims from s3 after a reconfigure).
func (r *Reclaimer) Reclaim(ctx context.Context, backendKind, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("reclaim: empty source")
	}
	switch backendKind {
	case BackendS3:
		return r.reclaimS3(ctx, source)
	case BackendNFS:
		return r.reclaimNFS(ctx, source)
	default:
		return fmt.Errorf("reclaim: unknown backend %q", backendKind)
	}
}

// reclaimS3 removes every object under the prefix. source is "bucket/key..." as
// produced by MountSource; we re-form the s3:// URI and recurse. --recursive on
// a missing prefix is a no-op exit 0, which gives us idempotency for free.
func (r *Reclaimer) reclaimS3(ctx context.Context, source string) error {
	uri := "s3://" + strings.TrimPrefix(source, "s3://")
	args := []string{"s3", "rm", uri, "--recursive"}
	if ep := strings.TrimSpace(r.backend.S3Endpoint); ep != "" {
		args = append(args, "--endpoint-url", ep)
	}
	if region := strings.TrimSpace(r.backend.S3Region); region != "" {
		args = append(args, "--region", region)
	}
	if err := r.run(ctx, r.s3CredEnv(), "aws", args...); err != nil {
		return fmt.Errorf("reclaim s3 %q: %w", uri, err)
	}
	return nil
}

// s3CredEnv returns the static-credential environment for the AWS CLI when the
// operator configured keys. Empty means rely on the host's ambient credential
// chain (instance role / IRSA), mirroring the mount path's behavior.
func (r *Reclaimer) s3CredEnv() []string {
	id := strings.TrimSpace(r.backend.S3AccessKeyID)
	secret := strings.TrimSpace(r.backend.S3SecretAccessKey)
	if id == "" || secret == "" {
		return nil
	}
	return []string{
		"AWS_ACCESS_KEY_ID=" + id,
		"AWS_SECRET_ACCESS_KEY=" + secret,
	}
}

// reclaimNFS mounts the export read-write at a transient path, removes the
// volume's directory tree, then unmounts. The volume's data lives at
// server:/export/tenant/name; we mount that exact subtree and empty it. Unmount
// runs even when the delete failed so we never leak a mount.
func (r *Reclaimer) reclaimNFS(ctx context.Context, source string) error {
	if r.mountRoot == "" {
		return fmt.Errorf("reclaim nfs: no mount root configured")
	}
	tmp, err := os.MkdirTemp(r.mountRoot, "vol-reclaim-")
	if err != nil {
		return fmt.Errorf("reclaim nfs: scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	mountArgs := []string{"-t", "nfs"}
	if opts := strings.TrimSpace(r.backend.NFSOptions); opts != "" {
		mountArgs = append(mountArgs, "-o", opts)
	}
	mountArgs = append(mountArgs, source, tmp)
	if err := r.run(ctx, nil, "mount", mountArgs...); err != nil {
		return fmt.Errorf("reclaim nfs mount %q: %w", source, err)
	}

	// Empty the mounted subtree rather than removing the mountpoint itself.
	rmErr := emptyDir(tmp)

	if err := r.run(ctx, nil, "umount", tmp); err != nil {
		// A failed unmount is worse than a failed delete (leaked mount), so it
		// wins the returned error; the ledger row stays and we retry next tick.
		return fmt.Errorf("reclaim nfs umount %q: %w", tmp, err)
	}
	if rmErr != nil {
		return fmt.Errorf("reclaim nfs delete %q: %w", source, rmErr)
	}
	return nil
}

// emptyDir removes every entry under dir without removing dir itself (which is
// the live mountpoint). A missing dir is treated as already-empty.
func emptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var firstErr error
	for _, e := range entries {
		if err := os.RemoveAll(dir + "/" + e.Name()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
