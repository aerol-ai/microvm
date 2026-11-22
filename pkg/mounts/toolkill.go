package mounts

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Signalling the mount tools that /proc lists. Teardown and the sweep find
// a tool by its command line (single mode) or its marker (isolated mode),
// then stop it. In split mode that code runs as root in the helper, so what
// it may signal is kept narrow:
//
//   - In isolated mode only processes of the tools' own user (Tools.UID)
//     count. Single mode's tools run as sandboxd's own user, so there the
//     listing alone decides, as before.
//   - A listed process is held (a pidfd on Linux) and checked again before
//     any signal, so a pid reused since the listing is never signalled.
//   - Its process group is signalled only when the process leads that
//     group itself (pgid == pid > 1). An isolated tool starts as the leader
//     of a session of its own (Setsid), which it cannot leave, so its group
//     holds only it and its children. A process found in another group is
//     signalled alone: never that group, and never group 1 (kill(-1) is
//     every process the caller may signal).

// procUIDs is pid's real and effective uid, from root/<pid>/status.
func procUIDs(root string, pid int) (real, eff uint32, ok bool) {
	f, err := os.Open(filepath.Join(root, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, found := strings.CutPrefix(sc.Text(), "Uid:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return 0, 0, false
		}
		r, rerr := strconv.ParseUint(fields[0], 10, 32)
		e, eerr := strconv.ParseUint(fields[1], 10, 32)
		if rerr != nil || eerr != nil {
			return 0, 0, false
		}
		return uint32(r), uint32(e), true
	}
	return 0, 0, false
}

// runsAs reports whether pid runs as uid: its real and effective uid both.
func runsAs(root string, pid int, uid uint32) bool {
	r, e, ok := procUIDs(root, pid)
	return ok && r == uid && e == uid
}

// leadsOwnGroup reports whether pid leads its process group, the only case
// in which that group is signalled with it.
func leadsOwnGroup(pid int) bool {
	if pid <= 1 {
		return false
	}
	pgid, err := syscall.Getpgid(pid)
	return err == nil && pgid == pid
}

// ownerOK is the owner check of a listing: any process when owner is nil.
func ownerOK(root string, pid int, owner *uint32) bool {
	return owner == nil || runsAs(root, pid, *owner)
}

// signalListedPlain is signalListed without a pidfd: still, then the
// signals, with the same rule for the group.
func signalListedPlain(pid int, sig syscall.Signal, still func() bool) error {
	if pid <= 1 || !still() {
		return errProcessGone
	}
	if leadsOwnGroup(pid) {
		_ = syscall.Kill(-pid, sig)
	}
	if err := syscall.Kill(pid, sig); err != nil && err != syscall.ESRCH {
		return err
	}
	return nil
}
