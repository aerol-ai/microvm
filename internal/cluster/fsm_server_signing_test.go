package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for the servers' signing record in the FSM (CLAUDE.md
// "Cluster mode is fragile"): written once, resealed under compare-and-set,
// carried by snapshots, never proposed by a worker.

func applySigning(t *testing.T, f *placementFSM, idx uint64, w *ServerSigningWrite) any {
	t.Helper()
	data, err := encodeCommand(command{Op: opPutServerSigning, ServerSigning: w})
	if err != nil {
		t.Fatal(err)
	}
	return f.Apply(&raft.Log{Index: idx, Data: data})
}

func TestFSMServerSigningWrittenOnceAndResealed(t *testing.T) {
	f := newPlacementFSM()
	if _, ok := f.serverSigningRecord(); ok {
		t.Fatal("a record before any write")
	}
	first := ServerSigning{Sealed: []byte("sealed-1"), SinceUnixNano: 100}
	if res, ok := applySigning(t, f, 1, &ServerSigningWrite{Signing: first}).(serverSigningApplyResult); !ok || !res.Changed {
		t.Fatalf("first write = %+v", res)
	}
	// A second first write (another leader's race) keeps the first.
	if res, ok := applySigning(t, f, 2, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-2"), SinceUnixNano: 200}}).(serverSigningApplyResult); !ok || res.Changed || string(res.Record.Sealed) != "sealed-1" {
		t.Fatalf("racing first write = %+v", res)
	}
	// A reseal names what it replaces and keeps Since.
	if err, _ := applySigning(t, f, 3, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-3"), SinceUnixNano: 100}, Expect: []byte("stale")}).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("reseal of a stale record = %v", err)
	}
	if err, _ := applySigning(t, f, 4, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-3"), SinceUnixNano: 999}, Expect: []byte("sealed-1")}).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("reseal that moves Since = %v", err)
	}
	if res, ok := applySigning(t, f, 5, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed-3"), SinceUnixNano: 100}, Expect: []byte("sealed-1")}).(serverSigningApplyResult); !ok || !res.Changed {
		t.Fatalf("reseal = %+v", res)
	}
	if rec, _ := f.serverSigningRecord(); string(rec.Sealed) != "sealed-3" || rec.SinceUnixNano != 100 {
		t.Fatalf("record = %+v", rec)
	}
	for name, w := range map[string]*ServerSigningWrite{
		"no payload": nil,
		"no seed":    {Signing: ServerSigning{SinceUnixNano: 1}},
		"no since":   {Signing: ServerSigning{Sealed: []byte("x")}},
	} {
		if err, _ := applySigning(t, f, 6, w).(error); !errors.Is(err, ErrServerSigningInvalid) {
			t.Errorf("%s = %v", name, err)
		}
	}
	empty := newPlacementFSM()
	if err, _ := applySigning(t, empty, 1, &ServerSigningWrite{Signing: first, Expect: []byte("x")}).(error); !errors.Is(err, ErrServerSigningConflict) {
		t.Fatalf("reseal with no record = %v", err)
	}
}

func TestFSMServerSigningSnapshotRestore(t *testing.T) {
	f := newPlacementFSM()
	applySigning(t, f, 1, &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed"), SinceUnixNano: 7}})
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if rec, ok := restored.serverSigningRecord(); !ok || string(rec.Sealed) != "sealed" || rec.SinceUnixNano != 7 {
		t.Fatalf("restored = %+v %v", rec, ok)
	}
	restored.restoreServerSigningLocked(&ServerSigning{SinceUnixNano: 7})
	if _, ok := restored.serverSigningRecord(); ok {
		t.Fatal("a malformed record restored")
	}
	if newPlacementFSM().serverSigningSnapshotLocked() != nil {
		t.Fatal("a snapshot with no record carries one")
	}
}

// Only the leader writes the record, and only once every member verifies
// what servers sign; a worker cannot propose it.
func TestWriteServerSigningOnTheLeader(t *testing.T) {
	c, cleanup := newTestCluster(t, "ldr-signing", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	w := ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("sealed"), SinceUnixNano: 1}}
	if _, err := c.WriteServerSigning(ctx, w); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("before the active version = %v", err)
	}
	c.fsm.activeFV.Store(serverSigningFSMOpsVersion)
	if !c.ServerSigningAllowed() {
		t.Fatal("not allowed at the active version")
	}
	rec, err := c.WriteServerSigning(ctx, w)
	if err != nil || string(rec.Sealed) != "sealed" {
		t.Fatalf("write = %+v %v", rec, err)
	}
	if got, ok := c.ServerSigningRecord(); !ok || string(got.Sealed) != "sealed" {
		t.Fatalf("record = %+v", got)
	}
	raw, _ := encodeCommand(command{Op: opPutServerSigning, ServerSigning: &ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("mine"), SinceUnixNano: 1}, Expect: []byte("sealed")}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), raw); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("a worker's write = %v", err)
	}
	var nilCluster *Cluster
	if _, ok := nilCluster.ServerSigningRecord(); ok || nilCluster.ServerSigningAllowed() {
		t.Fatal("a nil cluster has a record")
	}
}

// Once servers sign, only a server puts a cloud identity into a
// placement's spec or changes a placement's owner: those are what a server
// signs the sandbox's identity tokens from.
func TestIdentityStaysAsServersSetIt(t *testing.T) {
	idn := &models.IdentityRequest{RoleTag: "deploy"}
	st := fakeProposalState{signing: true, placements: map[string]Placement{
		"sb-id":    {SandboxID: "sb-id", OwnerNodeID: "wkr-1", OwnerRef: "team:a", Spec: &models.CreateSandboxRequest{Identity: idn}},
		"sb-plain": {SandboxID: "sb-plain", OwnerNodeID: "wkr-1", OwnerRef: "team:a", Spec: &models.CreateSandboxRequest{}},
	}}
	spec := func(i *models.IdentityRequest) *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Image: "alpine", Identity: i}
	}
	for _, tc := range []struct {
		name string
		cmd  command
		want bool
	}{
		{"reserve with an identity", command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(idn)}, false},
		{"reserve with none", command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(nil)}, true},
		{"place a new sandbox with an identity", command{Op: opPlace, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(idn)}, false},
		{"promote with the identity it has", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", Spec: spec(&models.IdentityRequest{RoleTag: "deploy", Audience: "sts.amazonaws.com"})}, true},
		{"promote with another identity", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", Spec: spec(&models.IdentityRequest{RoleTag: "admin"})}, false},
		{"add an identity to a plain sandbox", command{Op: opUpsertSpec, SandboxID: "sb-plain", Spec: spec(idn)}, false},
		{"drop the identity", command{Op: opUpsertSpec, SandboxID: "sb-id", Spec: spec(nil)}, true},
		{"place with another owner", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", OwnerRef: "team:b"}, false},
		{"place with the same owner", command{Op: opPlace, SandboxID: "sb-id", OwnerNodeID: "wkr-1", OwnerRef: "team:a"}, true},
	} {
		if got := peerMayPropose(JoinRoleWorker, "wkr-1", tc.cmd, st); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		if !peerMayPropose(JoinRoleServer, "srv-1", tc.cmd, st) {
			t.Errorf("%s: a server may not", tc.name)
		}
	}
	// Before servers sign, nothing changes.
	st.signing = false
	if !peerMayPropose(JoinRoleWorker, "wkr-1", command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-1", Spec: spec(idn)}, st) {
		t.Fatal("a reservation with an identity refused before servers sign")
	}
}
