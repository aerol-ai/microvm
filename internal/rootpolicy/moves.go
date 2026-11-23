package rootpolicy

import (
	"path/filepath"
)

// gVisor checkpoint moves (M1 PR 13; C21 of the Kubernetes plan). The root
// helper keeps a sandbox's checkpoints in its moves folder (Policy.MovesDir),
// in one folder per sandbox on each side of a move:
//
//	<MovesDir>/out/<id>  runsc checkpoint's image, on the source
//	<MovesDir>/in/<id>   a bundle staged for the restore, on the target
//
// runsc reads and writes those folders whole, as root, so only the helper
// makes anything in them, and a restored container may name only its own
// staged folder.
const (
	MovesOut = "out"
	MovesIn  = "in"
)

// MoveFolder is a sandbox's folder on one side of a move. The ID must pass
// ValidateID first.
func MoveFolder(p Policy, side, id string) string {
	return filepath.Join(p.MovesDir, side, id)
}

// CheckRestorePath allows a restored container's checkpoint only at the
// container's own staged folder, <MovesDir>/in/<container ID>: runsc
// restores, as root, whatever it finds there, so a container may not name
// another sandbox's checkpoint, the source side or the moves folder
// itself. With no container ID it is CheckCheckpointPath.
func CheckRestorePath(p Policy, containerID, dir string) error {
	if err := CheckCheckpointPath(p, dir); err != nil {
		return err
	}
	if containerID != "" && dir != MoveFolder(p, MovesIn, containerID) {
		return violate(RuleCheckpoint, "restore image %q is not container %s's own staged checkpoint", dir, containerID)
	}
	return nil
}

// CheckMoveBundleSize refuses a move bundle past max bytes: the helper
// writes a bundle as root, so the agent may not make it write without end.
func CheckMoveBundleSize(n, max int64) error {
	if n > max {
		return violate(RuleMoveBundle, "the move bundle is more than %d bytes", max)
	}
	return nil
}
