package capacity

import (
	"fmt"
	"syscall"
)

// DiskProbe reports the sandbox volume's size and the space an unprivileged
// writer can still use, in bytes. The default reads statfs on one path;
// tests substitute a fake.
type DiskProbe interface {
	DiskUsage() (total, free uint64, err error)
}

type statfsDiskProbe struct{ path string }

// NewStatfsDiskProbe reads the filesystem holding path. Free is Bavail, not
// Bfree: the blocks ext4 reserves for root are no use to a sandbox's writes.
func NewStatfsDiskProbe(path string) DiskProbe { return statfsDiskProbe{path: path} }

func (p statfsDiskProbe) DiskUsage() (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p.path, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", p.path, err)
	}
	bsize := uint64(st.Bsize)
	return uint64(st.Blocks) * bsize, uint64(st.Bavail) * bsize, nil
}

// SetDiskProbe installs the sandbox volume reader that DiskFloorRatio and
// the snapshot's disk fields use; nil removes it.
func (a *Admitter) SetDiskProbe(p DiskProbe) {
	a.mu.Lock()
	a.disk = p
	a.mu.Unlock()
}

// diskFloorReason is the refusal when the sandbox volume has less free space
// than DiskFloorRatio of its size, or "" when it has enough, no floor is set,
// or the volume cannot be read. A read error allows, like the memory probe's:
// a passing statfs failure must not stop every create.
//
// The request's DiskGB is not counted against the floor. On the runtimes
// this floor exists for nothing sets that space aside at create, and a
// sandbox may never write it; DiskReservationRatio is the axis for promised
// space. The floor is about the space actually left.
func (a *Admitter) diskFloorReason(disk DiskProbe) string {
	if a.limits.DiskFloorRatio <= 0 || disk == nil {
		return ""
	}
	total, free, err := disk.DiskUsage()
	if err != nil || total == 0 {
		return ""
	}
	floor := uint64(float64(total) * a.limits.DiskFloorRatio)
	if free >= floor {
		return ""
	}
	return fmt.Sprintf("disk floor breached (%d MB free < %d MB floor on the sandbox volume)",
		bytesToMB(free), bytesToMB(floor))
}

// bytesToMB rounds down, so a volume is never reported roomier than it is.
func bytesToMB(b uint64) int { return int(b >> 20) }
