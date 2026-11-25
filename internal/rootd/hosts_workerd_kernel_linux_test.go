//go:build linux

package rootd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/isolate"
)

// TestWorkerdJailIsMadeFresh: a V8 group whose workerd is gone gets a new
// jail, never the old one: what the last workerd left in its run folder is
// gone. Root only (mounts).
func TestWorkerdJailIsMadeFresh(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the jail's tmpfs mounts")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	w := newWorkerdHosts(&WorkerdHostsConfig{Jail: isolate.RootJail{ChrootBase: base, WorkerdPath: self, UID: 1000, GID: 1000,
		AgentUID: 65531, SeccompMode: isolate.SeccompEnforce, ShimPath: self}, PidsMax: 64, MaxJails: defaultMaxV8Jails}, filepath.Join(t.TempDir(), "hosts.log"))
	resp, err := w.prepare("g1", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.teardown("g1") })
	left := filepath.Join(resp.GetRunDir(), "left-by-workerd")
	if err := os.WriteFile(left, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepare("g1", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatal("a stopped group's jail was reused, with what its workerd left")
	}
	// A group that runs keeps its jail as it is.
	if err := os.WriteFile(left, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepare("g1", true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); err != nil {
		t.Fatal("a running group's jail was rebuilt under it")
	}
}
