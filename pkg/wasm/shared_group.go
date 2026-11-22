package wasm

import (
	"io/fs"
	"sync/atomic"
)

// sharedWithGroup is on in a worker the root helper starts in privilege
// mode split (plans/security-gaps-m1-m4.md, M1 PR 9). There sandboxd is
// not root, and serves a sandbox's files (the toolbox's uploads, listings
// and reads, and the removal of its /work) as a member of the worker's
// group. The sandbox's /work is sandboxd's, setgid to that group, so what
// the guest makes in it is the group's too; this makes it readable and
// writable by the group as well. No other user can enter /work: its
// parent is sandboxd's alone, and each worker reaches its own /work only
// through the folder sandboxd passes it.
var sharedWithGroup atomic.Bool

// ShareFilesWithGroup turns the group sharing on for this process (the
// worker, at its start).
func ShareFilesWithGroup() { sharedWithGroup.Store(true) }

// sharedFileMode is perm with the group's bits matched to the owner's
// read and write, when sharing is on.
func sharedFileMode(perm fs.FileMode) fs.FileMode {
	if !sharedWithGroup.Load() {
		return perm
	}
	return perm | (perm&0o600)>>3
}

// sharedDirMode is a new folder's perm with the group given read, write
// and search, when sharing is on. The setgid bit it inherits keeps its
// entries the group's.
func sharedDirMode(perm fs.FileMode) fs.FileMode {
	if !sharedWithGroup.Load() {
		return perm
	}
	return perm | 0o070
}
