package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// reservationWithIdentity is a cluster whose servers sign, holding a
// server's reservation of an identity create for wkr-target (team:a).
func reservationWithIdentity(t *testing.T, leader string) (*Cluster, string, func()) {
	t.Helper()
	c, cleanup := newTestCluster(t, leader, true, nil)
	waitForLeader(t, c, 10*time.Second)
	seedGossipView(t, c, []Member{workerMember("wkr-target", ""), workerMember("wkr-other", "")})
	server := ContextWithApplyPeer(context.Background(), leader, roleCert(leader, ""))
	rec, _ := encodeCommand(command{Op: opPutServerSigning, ServerSigning: &ServerSigningWrite{
		Signing: ServerSigning{Sealed: []byte("sealed"), SinceUnixNano: time.Now().UnixNano()}}})
	if err := c.ApplyEncoded(server, rec); err != nil {
		cleanup()
		t.Fatalf("signing record: %v", err)
	}
	inc, err := MintIncarnationID()
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	reserve, _ := encodeCommand(command{Op: opReserve, SandboxID: "sb-idn", OwnerNodeID: "wkr-target",
		OwnerAPIURL: "https://wkr-target:21212", IncarnationID: inc, OwnerRef: "team:a",
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
		Spec:        &models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "deploy"}}})
	if err := c.ApplyEncoded(server, reserve); err != nil {
		cleanup()
		t.Fatalf("server reserve: %v", err)
	}
	return c, inc, cleanup
}

// A server reserves a create for the worker it picked; only that worker
// places it. The reservation's spec and account are the server's, and a
// server signs the sandbox's tokens from them.
func TestOnlyTheTargetPlacesAReservation(t *testing.T) {
	c, inc, cleanup := reservationWithIdentity(t, "rv-ldr")
	defer cleanup()
	place := func(node string) error {
		cmd, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-idn", OwnerNodeID: node,
			ExpectedIncarnationID: inc, IncarnationID: inc})
		return c.ApplyEncoded(workerApplyCtx(node), cmd)
	}
	if err := place("wkr-other"); err == nil {
		t.Fatal("a worker that is not the reservation's target placed it")
	}
	if got, _ := c.fsm.placementForProposal("sb-idn", false); got.OwnerNodeID != "wkr-target" || !got.IsReserved() {
		t.Fatalf("the reservation changed: owner %q reserved %v", got.OwnerNodeID, got.IsReserved())
	}
	if err := place("wkr-target"); err != nil {
		t.Fatalf("the target's place: %v", err)
	}
	got, _ := c.fsm.placementForProposal("sb-idn", true)
	if got.OwnerNodeID != "wkr-target" || got.OwnerRef != "team:a" || got.Spec == nil || got.Spec.Identity == nil {
		t.Fatalf("placed: owner %q account %q spec %+v", got.OwnerNodeID, got.OwnerRef, got.Spec)
	}
}

// A reserve that names a live reservation's target is a retry: it comes
// from the node that reserved it or the target, and keeps the account.
func TestAReservationRetryKeepsItsAccount(t *testing.T) {
	c, inc, cleanup := reservationWithIdentity(t, "rv-ldr2")
	defer cleanup()
	expires := time.Now().Add(2 * time.Minute).Unix()
	retry := func(from, account string) error {
		cmd, _ := encodeCommand(command{Op: opReserve, SandboxID: "sb-idn", OwnerNodeID: "wkr-target",
			IncarnationID: inc, OwnerRef: account, ExpiresUnix: expires})
		return c.ApplyEncoded(workerApplyCtx(from), cmd)
	}
	if err := retry("wkr-other", "team:b"); err == nil {
		t.Error("a node that neither made nor runs the reservation retried it for another account")
	}
	if err := retry("wkr-other", ""); err == nil {
		t.Error("a node that neither made nor runs the reservation retried it")
	}
	if err := retry("wkr-target", "team:b"); err == nil {
		t.Error("the target retried the reservation for another account")
	}
	if got, _ := c.fsm.placementForProposal("sb-idn", false); got.OwnerRef != "team:a" {
		t.Fatalf("the reservation's account is %q", got.OwnerRef)
	}
	if err := retry("wkr-target", "team:a"); err != nil {
		t.Fatalf("the target's retry for the same account: %v", err)
	}
}
