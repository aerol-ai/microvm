package rootclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// TestMarkSandboxCgroup (M1 PR 6): the agent's mark reaches the helper's
// cgroup part and the helper writes the group's two settings; a hostile
// name is a refusal the client records; a helper that does not list the
// part is never sent it.
func TestMarkSandboxCgroup(t *testing.T) {
	base := t.TempDir()
	root, proc := filepath.Join(base, "cgroup"), filepath.Join(base, "proc")
	write := func(p, v string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "sandboxes", "sb-1", "cgroup.procs"), "7\n")
	write(filepath.Join(root, "sandboxes", "sb-1", "memory.oom.group"), "0\n")
	write(filepath.Join(proc, "7", "cgroup"), "0::/sandboxes/sb-1\n")
	write(filepath.Join(proc, "7", "oom_score_adj"), "-999\n")
	write(filepath.Join(proc, "self", "cgroup"), "0::/sandboxes/_runtime/aerolvm-rootd\n")

	sock := sockPath(t)
	realHelperWith(t, sock, func(c *rootd.Config) { c.Policy.CgroupParent = "/sandboxes" },
		func(o *rootd.Options) { o.CgroupRoot, o.ProcRoot = root, proc })
	var refusals []Refusal
	c := New(Config{Socket: sock, HelperUID: uint32(os.Getuid()), OnRefusal: func(_ context.Context, r Refusal) { refusals = append(refusals, r) }})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	if parts, err := c.Parts(ctx); err != nil || len(parts) != 1 || parts[0] != rootdpb.PartCgroup {
		t.Fatalf("Parts = %v, %v", parts, err)
	}
	if err := c.MarkSandboxCgroup(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{filepath.Join(root, "sandboxes", "sb-1", "memory.oom.group"): "1", filepath.Join(proc, "7", "oom_score_adj"): "500"} {
		if raw, _ := os.ReadFile(p); strings.TrimSpace(string(raw)) != want {
			t.Fatalf("%s = %q, want %s", p, raw, want)
		}
	}
	if err := c.MarkSandboxCgroup(ctx, "_runtime"); !errors.Is(err, ErrRefused) || len(refusals) != 1 || refusals[0].Reason != "cgroup" {
		t.Fatalf("containerd's group = %v, refusals %+v", err, refusals)
	}

	// A helper that serves no cgroup part is never sent one.
	sock2 := newOwnedSocket(t)
	h := &partsHelper{parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}}
	sock2.serve(t, h)
	old := New(Config{Socket: sock2.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = old.Close() })
	var ue *UnsupportedError
	if err := old.MarkSandboxCgroup(ctx, "sb-1"); !errors.As(err, &ue) || !strings.Contains(err.Error(), rootdpb.PartCgroup) || h.prepares.Load() != 0 {
		t.Fatalf("an older helper = %v (sent %d)", err, h.prepares.Load())
	}
}
