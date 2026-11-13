package containerd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"

	"github.com/aerol-ai/microvm/internal/runscwrap"
	"github.com/aerol-ai/microvm/internal/runtime/movebundle"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
)

// gVisor checkpoint moves (C21, plans/kubernetes-v2-architecture.md §10.5):
// a running gVisor sandbox moves to another worker with its memory.
//
//   - Source: the service's stop, marked runtime.WithCheckpoint, runs
//     `runsc checkpoint` on the sandbox before it reaps the task. runsc
//     saves the sandbox, its memory and its own root overlay (where every
//     write inside a gVisor sandbox lands) under moves/out/<id>, then ends
//     it. The stock shim answers containerd's task checkpoint with "not
//     implemented", so sandboxd runs runsc itself, on the shim's state root.
//   - The move: ExportSandboxSnapshot streams that folder to the target,
//     which ImportSandboxSnapshot stages under moves/in/<id>.
//   - Target: the service's recreate, marked runtime.WithRestore, creates
//     the container as any create does, plus RestoreAnnotation and the
//     shim option that runs aerolvm-runsc (internal/runscwrap); the task's
//     start becomes `runsc restore`. The sandbox takes the target network
//     slot's address (runsc reads the namespace's interfaces again on
//     restore; Phase 5 spike), so no address is reserved across workers.
//
// runsc checks on restore that the new spec matches the saved one, except
// for env, hostname, cgroup path and the mount sources: the target builds
// the same spec from the same request, so it matches. A warm-pool sandbox
// does not (its spec carries the pool's park socket), so it is refused.

const (
	movesDirName = "moves"
	moveOut      = "out"
	moveIn       = "in"
	// runscRestoreConfigRelPath is the shim config of a restored sandbox:
	// runscConfigRelPath's flags, and aerolvm-runsc as the runsc to run.
	runscRestoreConfigRelPath = "runsc/restore.toml"
	// runscWrapperPath is where the runtime image installs aerolvm-runsc,
	// next to runsc and the shim that runs it.
	runscWrapperPath = "/usr/local/bin/" + runscwrap.CommandName
	// runscStateRoot is the shim's runsc state root (its default; our shim
	// config leaves it), one folder per containerd namespace.
	runscStateRoot = "/run/containerd/runsc"
)

var (
	errNotCheckpointable = errors.New("only a running gVisor sandbox is checkpointed for a move")
	errWarmPoolMove      = errors.New("a sandbox from the warm pool moves by recreate only: its spec carries the pool's park socket")
)

// runscCommandFn runs runsc with args; tests replace it.
var runscCommandFn = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "runsc", args...).CombinedOutput()
}

// moveDir is sandboxID's folder on one side of a move. The ID reaches here
// from API calls and from other workers, so every caller gets the path
// only through this check (code scanning, go/path-injection).
func (d *Driver) moveDir(side, sandboxID string) (string, error) {
	if err := validateSandboxID(sandboxID); err != nil {
		return "", err
	}
	return movebundle.Inside(filepath.Join(d.runDir(), movesDirName, side), sandboxID)
}

func (d *Driver) runDir() string {
	if d.cfg.RunDir == "" {
		return "/var/lib/aerolvm/containerd"
	}
	return d.cfg.RunDir
}

// checkpointForMove saves a running gVisor sandbox under moves/out/<id>.
// runsc ends the sandbox once it is saved.
func (d *Driver) checkpointForMove(ctx context.Context, client *Client, container cntr.Container, task cntr.Task) error {
	info, err := container.Info(ctx)
	if err != nil {
		return fmt.Errorf("load container: %w", err)
	}
	if info.Runtime.Name != runscShimName {
		return errNotCheckpointable
	}
	if status, err := task.Status(ctx); err != nil || status.Status != cntr.Running {
		return errNotCheckpointable
	}
	spec, err := container.Spec(ctx)
	if err != nil {
		return fmt.Errorf("load container spec: %w", err)
	}
	if spec.Process != nil {
		if _, _, parked := dockerpkg.ParkedEnvCredentials(spec.Process.Env); parked {
			return errWarmPoolMove
		}
	}
	id := container.ID()
	dir, err := d.moveDir(moveOut, id)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out, err := runscCommandFn(ctx, "--root="+filepath.Join(runscStateRoot, client.Namespace()),
		"checkpoint", "--image-path="+dir, id)
	if err == nil && !runscwrap.HasCheckpoint(dir) {
		err = errors.New("it wrote no checkpoint")
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("runsc checkpoint %s: %w: %s", id, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ExportSandboxSnapshot writes the checkpoint a move's stop saved for
// sandboxID to w, for ImportSandboxSnapshot on the target.
func (d *Driver) ExportSandboxSnapshot(ctx context.Context, sandboxID string, w io.Writer) error {
	dir, err := d.moveDir(moveOut, sandboxID)
	if err != nil {
		return fmt.Errorf("containerd runtime: export %s: %w", sandboxID, err)
	}
	if !runscwrap.HasCheckpoint(dir) {
		return fmt.Errorf("containerd runtime: export %s: no checkpoint (it was not stopped for a move, or it ran since)", sandboxID)
	}
	if err := movebundle.WriteDir(ctx, w, dir, sandboxID); err != nil {
		return fmt.Errorf("containerd runtime: export %s: %w", sandboxID, err)
	}
	return nil
}

// ImportSandboxSnapshot stages a checkpoint another worker exported under
// moves/in/<id>, where a create marked runtime.WithRestore finds it. A
// failed import leaves nothing behind.
func (d *Driver) ImportSandboxSnapshot(ctx context.Context, sandboxID string, r io.Reader) error {
	final, err := d.moveDir(moveIn, sandboxID)
	if err != nil {
		return fmt.Errorf("containerd runtime: import %s: %w", sandboxID, err)
	}
	base := filepath.Dir(final)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(base, ".import-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if _, err := movebundle.ReadDir(ctx, r, staging, sandboxID); err != nil {
		return fmt.Errorf("containerd runtime: import %s: %w", sandboxID, err)
	}
	if !runscwrap.HasCheckpoint(staging) {
		return fmt.Errorf("containerd runtime: import %s: the bundle holds no checkpoint", sandboxID)
	}
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	return os.Rename(staging, final)
}

// DropImportedSnapshot removes what ImportSandboxSnapshot staged.
func (d *Driver) DropImportedSnapshot(_ context.Context, sandboxID string) error {
	dir, err := d.moveDir(moveIn, sandboxID)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// restoreSpecOpt names the staged checkpoint on a restored sandbox's spec,
// for aerolvm-runsc. runsc does not check this annotation on restore.
func (d *Driver) restoreSpecOpt(sandboxID string) (oci.SpecOpts, error) {
	dir, err := d.moveDir(moveIn, sandboxID)
	if err != nil {
		return nil, err
	}
	return oci.WithAnnotations(map[string]string{runscwrap.RestoreAnnotation: dir}), nil
}

// staged reports whether a checkpoint for sandboxID waits here.
func (d *Driver) staged(sandboxID string) bool {
	dir, err := d.moveDir(moveIn, sandboxID)
	return err == nil && runscwrap.HasCheckpoint(dir)
}

// removeMoveFiles drops both sides' checkpoints of sandboxID: a start here
// makes a saved one stale, and a deleted sandbox has no use for them.
func (d *Driver) removeMoveFiles(sandboxID string) {
	for _, side := range []string{moveOut, moveIn} {
		if dir, err := d.moveDir(side, sandboxID); err == nil {
			_ = os.RemoveAll(dir)
		}
	}
}

// ensureRunscRestoreConfig writes the shim config of a restored sandbox.
func (d *Driver) ensureRunscRestoreConfig() (string, error) {
	return d.ensureRunscFile(runscRestoreConfigRelPath, runscRestoreConfigBody)
}

var runscRestoreConfigBody = "# Managed by AerolVM containerd driver (do not edit).\n" +
	"binary_name = \"" + runscWrapperPath + "\"\n" + runscFlagsSection
