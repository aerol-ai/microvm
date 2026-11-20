//go:build linux

package worker

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A folder whose access ACL lets the worker uid write is refused on the
// way, though its mode bits say only root may: the walk reads the ACL.
func TestOpenGrantPathRefusesACLFolder(t *testing.T) {
	root := t.TempDir()
	mid := filepath.Join(root, "acl")
	if err := os.Mkdir(mid, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(mid, "m.wasm")
	if err := os.WriteFile(file, []byte("m"), 0o600); err != nil {
		t.Fatal(err)
	}
	// struct posix_acl_xattr: version 2, then {tag, perm, id} entries.
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{0x01, 7, ^uint32(0)}, {0x02, 7, uint32(grantWorker.UID)}, {0x04, 0, ^uint32(0)}, {0x10, 7, ^uint32(0)}, {0x20, 0, ^uint32(0)}} {
		acl = binary.LittleEndian.AppendUint16(acl, e.tag)
		acl = binary.LittleEndian.AppendUint16(acl, e.perm)
		acl = binary.LittleEndian.AppendUint32(acl, e.id)
	}
	if err := unix.Setxattr(mid, posixACLAccess, acl, 0); err != nil {
		t.Skipf("no POSIX ACLs here: %v", err)
	}
	withGrantPolicy(t, GrantPolicy{Roots: []string{root}, Worker: grantWorker})
	if _, err := openGrantPath(file, false); !errors.Is(err, errGrantRefused) {
		t.Fatalf("through a folder the worker may write by ACL = %v", err)
	}
	if err := unix.Removexattr(mid, posixACLAccess); err != nil {
		t.Fatal(err)
	}
	f, err := openGrantPath(file, false)
	if err != nil {
		t.Fatalf("without the ACL = %v", err)
	}
	_ = f.Close()
}
