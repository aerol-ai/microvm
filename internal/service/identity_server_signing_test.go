package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// identityPair is a server and a worker that share the deployment's key set
// and role lists (the Raft FSM in a cluster).
func identityPair(t *testing.T) (h *identityHarness, worker *Service, srv *signingServer, wk *signingWorker) {
	t.Helper()
	h = newIdentityHarness(t)
	h.svc.cfg.EnableCluster = true
	h.svc.identity.backend = h.st
	srv = newSigningServer("srv-1")
	h.svc.AttachCluster(srv)
	worker, _, _ = testTokenService(t, time.Hour)
	worker.cipher = h.svc.cipher
	worker.cfg.EnableCluster = true
	worker.cfg.IdentityIssuerURL = testIssuer
	worker.identity.backend = h.st
	wk = &signingWorker{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""), server: h.svc}
	worker.AttachCluster(wk)
	return h, worker, srv, wk
}

// Once servers sign, the signing key is one only servers open: the leader
// rotates the ring-sealed key out, a worker can neither open nor make one,
// and a worker's sandboxes get their tokens signed by a server from the
// placement, for the owner node only.
func TestIdentityOnceServersSign(t *testing.T) {
	h, worker, srv, _ := identityPair(t)
	ctx := context.Background()
	h.allow(t, "payments", "deploy", "runner")
	if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
		t.Fatal(err)
	}
	set, _ := h.st.ReadIdentityKeys(ctx)
	before, _ := set.Active()
	if before.Seal != "" {
		t.Fatalf("a key before servers sign is sealed %q", before.Seal)
	}
	// The upkeep does nothing until the record exists.
	if err := h.svc.UpkeepServerIdentityKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if set, _ = h.st.ReadIdentityKeys(ctx); len(set.Keys) != 1 {
		t.Fatalf("keys before the record: %d", len(set.Keys))
	}
	turnOnServerSigning(t, h.svc, time.Now())
	if err := h.svc.UpkeepServerIdentityKeys(ctx); err != nil {
		t.Fatal(err)
	}
	set, _ = h.st.ReadIdentityKeys(ctx)
	active, _ := set.Active()
	if active.Seal != cloudidentity.SealServer || active.ID == before.ID || len(set.Keys) != 2 {
		t.Fatalf("after the upkeep: active %s sealed %q, %d keys", active.ID, active.Seal, len(set.Keys))
	}
	if err := h.svc.UpkeepServerIdentityKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := h.st.ReadIdentityKeys(ctx); again.Generation != set.Generation {
		t.Fatal("a second pass rotated again")
	}
	// The ring opens no server-sealed key; the worker cannot open it.
	if _, err := h.svc.cipher.DecryptWithAAD(active.SealedPrivate, cloudidentity.SealAAD(active.ID)); err == nil {
		t.Fatal("the ring opened a server-sealed key")
	}
	if _, err := worker.openIdentityKey(active); err == nil {
		t.Fatal("a worker opened the server-sealed key")
	}
	if _, err := worker.newIdentityKeyRecord(); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("a worker made a key: %v", err)
	}
	if worker.mayMakeIdentityKeys() || !h.svc.mayMakeIdentityKeys() {
		t.Fatal("key makers")
	}
	if err := worker.resealIdentityKeys(ctx, func(uint32, bool) {}, func() { t.Fatal("a worker tried a reseal") }); err != nil {
		t.Fatal(err)
	}
	// A server's reseal after a ring rotation moves only the ring-sealed
	// key; the servers' key does not depend on the ring.
	rotateTestRing(t, h.svc.cipher)
	if err := h.svc.resealIdentityKeys(ctx, func(uint32, bool) {}, func() { t.Fatal("a key could not be opened") }); err != nil {
		t.Fatal(err)
	}
	resealed, _ := h.st.ReadIdentityKeys(ctx)
	for _, k := range resealed.Keys {
		was := set.Keys[0]
		if set.Keys[1].ID == k.ID {
			was = set.Keys[1]
		}
		if k.Seal == cloudidentity.SealServer && string(k.SealedPrivate) != string(was.SealedPrivate) {
			t.Fatal("the servers' key was resealed with the ring")
		}
		if k.Seal == "" && string(k.SealedPrivate) == string(was.SealedPrivate) {
			t.Fatal("the ring-sealed key was not moved to the new ring key")
		}
	}
	set = resealed
	active, _ = set.Active()

	// The worker's sandbox, placed by a server with an identity.
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", IncarnationID: "inc-1", OwnerRef: "team:payments",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "deploy"}}}
	sb := &models.Sandbox{ID: "sb-1", OwnerRef: "team:payments", AuditIncarnationID: "inc-1"}
	tok, err := worker.signIdentityToken(ctx, sb, storepkg.SandboxIdentity{RoleTag: "deploy"})
	if err != nil {
		t.Fatalf("sign through a server: %v", err)
	}
	claims, err := cloudidentity.Verify(tok.Raw, h.jwks(t), time.Now())
	if err != nil || claims.Team != "payments" || claims.Role != "deploy" || claims.Sandbox != "sb-1" || claims.Audience != cloudidentity.DefaultAudience || tok.KeyID != active.ID {
		t.Fatalf("token = %+v %v", claims, err)
	}

	// Refusals.
	for name, tc := range map[string]struct {
		peer   string
		server bool
		req    cluster.IdentityTokenSignRequest
		want   error
	}{
		"another node":        {"wkr-2", false, cluster.IdentityTokenSignRequest{SandboxID: "sb-1"}, ErrSignNotOwner},
		"an old lifetime":     {"wkr-1", false, cluster.IdentityTokenSignRequest{SandboxID: "sb-1", IncarnationID: "inc-0"}, storepkg.ErrNotFound},
		"an unknown sandbox":  {"wkr-1", false, cluster.IdentityTokenSignRequest{SandboxID: "sb-x"}, storepkg.ErrNotFound},
		"no identity on it":   {"wkr-1", false, cluster.IdentityTokenSignRequest{SandboxID: "sb-plain"}, ErrIdentityNotOnSandbox},
		"a server for anyone": {"srv-2", true, cluster.IdentityTokenSignRequest{SandboxID: "sb-1"}, nil},
	} {
		srv.placements["sb-plain"] = cluster.Placement{SandboxID: "sb-plain", OwnerNodeID: "wkr-1", Spec: &models.CreateSandboxRequest{Image: "alpine"}}
		_, err := h.svc.SignIdentityTokenFor(ctx, tc.peer, tc.server, tc.req)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s = %v, want %v", name, err, tc.want)
		}
	}
	// A tag taken off the list stops the refresh on the worker.
	if err := h.svc.DeleteIdentityRole(adminCtx(), "payments", "deploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.signIdentityToken(ctx, sb, storepkg.SandboxIdentity{RoleTag: "deploy"}); !errors.Is(err, errIdentityRoleRemoved) {
		t.Fatalf("removed tag = %v", err)
	}
	if !strings.Contains(ErrIdentityRoleRemoved.Error(), "removed") {
		t.Fatal("exported refusal")
	}
}
