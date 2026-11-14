//go:build !linux

package firecracker

import (
	"fmt"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
)

// Firecracker runs on Linux only; elsewhere a VM never outlives sandboxd.

func moveToVMMCgroup(int, string) error { return errVMMAdoptionUnsupported }

func vmmCgroupPIDs() ([]int, error) { return nil, nil }

func procStartTicks(int) (uint64, error) { return 0, errVMMAdoptionUnsupported }

func currentBootID() (string, error) { return "", errVMMAdoptionUnsupported }

func openLiveProcess(int, uint64) (liveProcess, error) { return nil, errVMMAdoptionUnsupported }

func killCgroupStray(int) error { return errVMMAdoptionUnsupported }

func procCmdline(int) ([]string, error) { return nil, errVMMAdoptionUnsupported }

func setVMMGroupFrozen(string, bool) error {
	return fmt.Errorf("%w: %w", errVMMAdoptionUnsupported, sbruntime.ErrCannotFreeze)
}

func vmmGroupFrozen(string) bool { return false }

func removeVMMGroup(string) {}

func removeEmptyVMMGroups() {}
