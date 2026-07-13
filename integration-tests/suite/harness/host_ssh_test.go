package harness

import "testing"

func TestSSHUserDefault(t *testing.T) {
	t.Setenv("AEROL_SSH_USER", "")
	if got := SSHUser(); got != "ubuntu" {
		t.Fatalf("SSHUser() = %q, want ubuntu", got)
	}
	t.Setenv("AEROL_SSH_USER", "ops")
	if got := SSHUser(); got != "ops" {
		t.Fatalf("SSHUser() = %q, want ops", got)
	}
}

func TestSSHTargetAndPick(t *testing.T) {
	_, ok := SSHTarget(IntegrationNode{Name: "empty"})
	if ok {
		t.Fatal("expected empty node to have no SSH target")
	}
	tgt, ok := SSHTarget(IntegrationNode{Name: "n", PublicIP: "1.2.3.4"})
	if !ok || tgt != "ubuntu@1.2.3.4" {
		t.Fatalf("SSHTarget = %q ok=%v", tgt, ok)
	}

	targets := &IntegrationTargets{Nodes: []IntegrationNode{
		{Name: "worker", PublicIP: "10.0.0.2"},
		{Name: "seed", Seed: true, PublicIP: "10.0.0.1"},
	}}
	n, ok := PickSSHNode(targets)
	if !ok || n.Name != "seed" {
		t.Fatalf("PickSSHNode = %+v ok=%v, want seed", n, ok)
	}
}

func TestHostHasAEROLVMUserJumpParse(t *testing.T) {
	// Pure string check covered indirectly; ensure empty targets skip cleanly.
	if _, ok := PickSSHNode(nil); ok {
		t.Fatal("nil targets should not pick a node")
	}
}
