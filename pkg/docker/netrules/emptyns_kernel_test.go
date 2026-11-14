//go:build linux && kerneltest

package netrules

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Real-kernel regression for finding F1 (Kubernetes Phase 0): a network
// namespace nothing has touched has no ip filter table, and the containerd
// engine's boot step, EnsureChain, failed there with ENOENT, so sandboxd
// exited. Run in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run KernelEnsureChainEmptyNamespace
//
// It deletes this namespace's ip filter table (the container's own, never
// the machine's), runs EnsureChain twice, and checks the table, the user
// chain and the FORWARD jump exist exactly once.
func TestKernelEnsureChainEmptyNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	_ = exec.Command("nft", "delete", "table", "ip", "filter").Run()
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip", "filter").Run() })
	if out, _ := exec.Command("nft", "list", "tables").CombinedOutput(); strings.Contains(string(out), "table ip filter") {
		t.Fatalf("could not start without an ip filter table: %s", out)
	}

	mgr, err := NewWithOptions(true, BackendNetlink, ChainAerolvmUser)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := mgr.EnsureChain(); err != nil {
			t.Fatalf("EnsureChain (call %d) in a namespace with no filter table: %v", i+1, err)
		}
	}
	out, err := exec.Command("nft", "list", "table", "ip", "filter").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table ip filter: %v: %s", err, out)
	}
	ruleset := string(out)
	if n := strings.Count(ruleset, "chain "+ChainAerolvmUser+" {"); n != 1 {
		t.Fatalf("%d %s chains, want 1:\n%s", n, ChainAerolvmUser, ruleset)
	}
	if n := strings.Count(ruleset, "chain FORWARD {"); n != 1 {
		t.Fatalf("%d FORWARD chains, want 1:\n%s", n, ruleset)
	}
	if n := strings.Count(ruleset, "jump "+ChainAerolvmUser); n != 1 {
		t.Fatalf("%d jumps to %s, want 1:\n%s", n, ChainAerolvmUser, ruleset)
	}
}
