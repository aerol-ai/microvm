package cluster

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func TestFSMApplyPlace(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080"}
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("apply returned %v, want nil", got)
	}
	p, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("expected placement for sb1, got none")
	}
	if p.OwnerNodeID != "nodeA" || p.OwnerAPIURL != "http://a:8080" {
		t.Fatalf("unexpected placement: %+v", p)
	}
}

func TestFSMPlaceIdempotent(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080"}
	payload, _ := encodeCommand(cmd)
	fsm.Apply(&raft.Log{Data: payload})
	first, _ := fsm.get("sb1")
	// Re-apply same command — version should not bump for the placement,
	// even though the FSM-wide version counter does.
	fsm.Apply(&raft.Log{Data: payload})
	second, _ := fsm.get("sb1")
	if first.Version != second.Version {
		t.Fatalf("idempotent re-place changed placement version: %d -> %d", first.Version, second.Version)
	}
	if first.UpdatedUnix != second.UpdatedUnix {
		t.Fatalf("idempotent re-place changed UpdatedUnix: %d -> %d", first.UpdatedUnix, second.UpdatedUnix)
	}
}

func TestFSMReplaceOwner(t *testing.T) {
	fsm := newPlacementFSM()
	c1, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", OwnerAPIURL: "http://a"})
	c2, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b"})
	fsm.Apply(&raft.Log{Data: c1})
	createdFirst, _ := fsm.get("sb1")
	time.Sleep(time.Second) // allow CreatedUnix preservation to be observable
	fsm.Apply(&raft.Log{Data: c2})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B, got %q", got.OwnerNodeID)
	}
	if got.CreatedUnix != createdFirst.CreatedUnix {
		t.Fatalf("CreatedUnix should be preserved across reassign: was %d, now %d", createdFirst.CreatedUnix, got.CreatedUnix)
	}
}

func TestFSMDelete(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})
	fsm.Apply(&raft.Log{Data: c})
	d, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb1"})
	fsm.Apply(&raft.Log{Data: d})
	if _, ok := fsm.get("sb1"); ok {
		t.Fatal("placement should be gone after delete")
	}
	// Idempotent.
	fsm.Apply(&raft.Log{Data: d})
}

// TestFSMPlaceCarriesSpec verifies the spec payload survives an opPlace round
// trip and a no-op idempotent retry that omits the spec doesn't erase it.
func TestFSMPlaceCarriesSpec(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256}
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", Spec: spec})
	fsm.Apply(&raft.Log{Data: c})
	got, _ := fsm.get("sb1")
	if got.Spec == nil || got.Spec.Image != "alpine" {
		t.Fatalf("expected spec to be stored; got %+v", got.Spec)
	}
	// Idempotent retry without a spec must not erase the stored spec.
	c2, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})
	fsm.Apply(&raft.Log{Data: c2})
	got2, _ := fsm.get("sb1")
	if got2.Spec == nil || got2.Spec.Image != "alpine" {
		t.Fatalf("idempotent re-place erased spec; got %+v", got2.Spec)
	}
}

// TestFSMUpsertSpec exercises opUpsertSpec: it overwrites Placement.Spec
// without touching the owner pointer.
func TestFSMUpsertSpec(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1}})
	fsm.Apply(&raft.Log{Data: c})

	// Resize: bump CPU via opUpsertSpec.
	u, _ := encodeCommand(command{Op: opUpsertSpec, SandboxID: "sb1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 2}})
	fsm.Apply(&raft.Log{Data: u})

	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "A" {
		t.Fatalf("opUpsertSpec must not touch owner; got %q", got.OwnerNodeID)
	}
	if got.Spec == nil || got.Spec.CPU != 2 {
		t.Fatalf("expected CPU=2 after upsert; got %+v", got.Spec)
	}

	// Upsert against unknown sandbox: silent no-op.
	u2, _ := encodeCommand(command{Op: opUpsertSpec, SandboxID: "ghost",
		Spec: &models.CreateSandboxRequest{Image: "x"}})
	if got := fsm.Apply(&raft.Log{Data: u2}); got != nil {
		t.Fatalf("upsert against unknown id returned %v, want nil", got)
	}
}

// TestFSMReassignPreservesSpec asserts opReassign moves the owner but leaves
// the replicated spec intact — that's what makes auto-recreation possible.
func TestFSMReassignPreservesSpec(t *testing.T) {
	fsm := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", Spec: spec})
	fsm.Apply(&raft.Log{Data: c})
	r, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b"})
	fsm.Apply(&raft.Log{Data: r})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B, got %q", got.OwnerNodeID)
	}
	if got.Spec == nil || got.Spec.Image != "alpine" {
		t.Fatalf("reassign erased spec; got %+v", got.Spec)
	}
}

// TestFSMAddRemoveExposedPort exercises the port-intent ops. opAdd is
// idempotent for the same protocol; opRemove is idempotent for absent ports;
// the empty map collapses to nil so JSON snapshots stay clean.
func TestFSMAddRemoveExposedPort(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})
	fsm.Apply(&raft.Log{Data: c})

	add1, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", Port: 80, Protocol: "http"})
	add2, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", Port: 5432, Protocol: "tcp"})
	fsm.Apply(&raft.Log{Data: add1})
	fsm.Apply(&raft.Log{Data: add2})

	got, _ := fsm.get("sb1")
	if got.ExposedPorts[80] != "http" || got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("ports not recorded: %+v", got.ExposedPorts)
	}

	// Idempotent re-add: snapshot the version, re-apply, version must be unchanged.
	preVer := got.Version
	fsm.Apply(&raft.Log{Data: add1})
	got, _ = fsm.get("sb1")
	if got.Version != preVer {
		t.Fatalf("idempotent re-add bumped version: %d -> %d", preVer, got.Version)
	}

	// Remove one and verify the other survives.
	rem, _ := encodeCommand(command{Op: opRemoveExposedPort, SandboxID: "sb1", Port: 80})
	fsm.Apply(&raft.Log{Data: rem})
	got, _ = fsm.get("sb1")
	if _, present := got.ExposedPorts[80]; present {
		t.Fatalf("port 80 should be gone; got %+v", got.ExposedPorts)
	}
	if got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("port 5432 should remain; got %+v", got.ExposedPorts)
	}

	// Remove the last entry — the map should collapse to nil so snapshots don't
	// carry an empty container indefinitely.
	rem2, _ := encodeCommand(command{Op: opRemoveExposedPort, SandboxID: "sb1", Port: 5432})
	fsm.Apply(&raft.Log{Data: rem2})
	got, _ = fsm.get("sb1")
	if got.ExposedPorts != nil {
		t.Fatalf("empty ExposedPorts should collapse to nil; got %+v", got.ExposedPorts)
	}

	// Removing an absent port is a no-op.
	preVer = got.Version
	fsm.Apply(&raft.Log{Data: rem2})
	got, _ = fsm.get("sb1")
	if got.Version != preVer {
		t.Fatalf("idempotent re-remove bumped version: %d -> %d", preVer, got.Version)
	}
}

// TestFSMPlaceCarriesPortsThroughRetry asserts an idempotent opPlace retry
// (e.g. AssertOwnership at boot writing spec=nil) does not erase the port
// intents that had been added by opAddExposedPort calls in between.
func TestFSMPlaceCarriesPortsThroughRetry(t *testing.T) {
	fsm := newPlacementFSM()
	p, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})
	fsm.Apply(&raft.Log{Data: p})
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", Port: 8080, Protocol: "http"})
	fsm.Apply(&raft.Log{Data: add})
	// Retry place with same owner, no spec — must not erase ports.
	fsm.Apply(&raft.Log{Data: p})
	got, _ := fsm.get("sb1")
	if got.ExposedPorts[8080] != "http" {
		t.Fatalf("idempotent re-place erased ports; got %+v", got.ExposedPorts)
	}
}

// TestFSMReassignPreservesPorts pairs with TestFSMReassignPreservesSpec — port
// intents must survive a failover reassignment so the new owner can replay
// exposures during recreate.
func TestFSMReassignPreservesPorts(t *testing.T) {
	fsm := newPlacementFSM()
	p, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	fsm.Apply(&raft.Log{Data: p})
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", Port: 5432, Protocol: "tcp"})
	fsm.Apply(&raft.Log{Data: add})
	r, _ := encodeCommand(command{Op: opReassign, SandboxID: "sb1", OwnerNodeID: "B"})
	fsm.Apply(&raft.Log{Data: r})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B; got %q", got.OwnerNodeID)
	}
	if got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("reassign erased ports; got %+v", got.ExposedPorts)
	}
}

// fakeSnapshotSink lets us drive Snapshot/Restore without a real BoltStore.
type fakeSnapshotSink struct {
	*bytes.Buffer
	cancelled bool
}

func (f *fakeSnapshotSink) ID() string    { return "fake" }
func (f *fakeSnapshotSink) Cancel() error { f.cancelled = true; return nil }
func (f *fakeSnapshotSink) Close() error  { return nil }

func TestFSMSnapshotRestoreRoundTrip(t *testing.T) {
	src := newPlacementFSM()
	for _, id := range []string{"a", "b", "c"} {
		c, _ := encodeCommand(command{
			Op: opPlace, SandboxID: id, OwnerNodeID: "owner-" + id, OwnerAPIURL: "http://" + id,
			Spec: &models.CreateSandboxRequest{Image: "img-" + id, CPU: 0.5, MemoryMB: 128},
		})
		src.Apply(&raft.Log{Data: c})
	}
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if sink.cancelled {
		t.Fatal("sink should not have been cancelled on success")
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		p, ok := dst.get(id)
		if !ok {
			t.Errorf("missing placement for %s after restore", id)
			continue
		}
		if p.OwnerNodeID != "owner-"+id {
			t.Errorf("wrong owner after restore for %s: %q", id, p.OwnerNodeID)
		}
		if p.Spec == nil || p.Spec.Image != "img-"+id {
			t.Errorf("spec lost in snapshot/restore for %s: got %+v", id, p.Spec)
		}
	}
}

// TestFSMPreservesSealedSecrets covers the preserve-on-nil semantics for the
// sealed-secrets bag: write-through paths that don't touch credentials (resize,
// lifecycle, idempotent retries) must not erase the bag a previous opPlace
// stored. Without this, a single opUpsertSpec replay would silently drop the
// only copy of the registry password / mount creds the new owner needs at
// failover.
func TestFSMPreservesSealedSecrets(t *testing.T) {
	fsm := newPlacementFSM()
	sealed := []byte("ciphertext-blob-v1")

	// 1. Initial opPlace stores spec + sealed bag.
	place, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a",
		Spec:          &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256},
		SealedSecrets: sealed,
	})
	if got := fsm.Apply(&raft.Log{Data: place}); got != nil {
		t.Fatalf("opPlace: %v", got)
	}
	p, _ := fsm.get("sb1")
	if !bytes.Equal(p.SealedSecrets, sealed) {
		t.Fatalf("opPlace did not store SealedSecrets: %x", p.SealedSecrets)
	}

	// 2. opUpsertSpec with a NEW spec but nil SealedSecrets must keep the
	// existing bag — resize/lifecycle replication takes this code path.
	upsert, _ := encodeCommand(command{
		Op: opUpsertSpec, SandboxID: "sb1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 2, MemoryMB: 512},
	})
	if got := fsm.Apply(&raft.Log{Data: upsert}); got != nil {
		t.Fatalf("opUpsertSpec: %v", got)
	}
	p, _ = fsm.get("sb1")
	if p.Spec == nil || p.Spec.CPU != 2 {
		t.Fatalf("opUpsertSpec didn't update spec: %+v", p.Spec)
	}
	if !bytes.Equal(p.SealedSecrets, sealed) {
		t.Fatalf("opUpsertSpec erased SealedSecrets: got %x, want %x", p.SealedSecrets, sealed)
	}

	// 3. Idempotent opPlace retry (no Spec, no SealedSecrets) must keep both.
	retry, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a",
	})
	if got := fsm.Apply(&raft.Log{Data: retry}); got != nil {
		t.Fatalf("opPlace retry: %v", got)
	}
	p, _ = fsm.get("sb1")
	if !bytes.Equal(p.SealedSecrets, sealed) {
		t.Fatalf("idempotent opPlace erased SealedSecrets: %x", p.SealedSecrets)
	}
	if p.Spec == nil || p.Spec.CPU != 2 {
		t.Fatalf("idempotent opPlace erased spec: %+v", p.Spec)
	}

	// 4. opUpsertSpec with a NEW sealed bag but nil Spec must rotate the bag
	// while keeping the spec — used if we ever rotate creds without touching
	// resources.
	rotated := []byte("ciphertext-blob-v2")
	upsertSealed, _ := encodeCommand(command{
		Op: opUpsertSpec, SandboxID: "sb1", SealedSecrets: rotated,
	})
	if got := fsm.Apply(&raft.Log{Data: upsertSealed}); got != nil {
		t.Fatalf("opUpsertSpec sealed-only: %v", got)
	}
	p, _ = fsm.get("sb1")
	if !bytes.Equal(p.SealedSecrets, rotated) {
		t.Fatalf("opUpsertSpec didn't rotate SealedSecrets: %x", p.SealedSecrets)
	}
	if p.Spec == nil || p.Spec.CPU != 2 {
		t.Fatalf("sealed-only upsert erased spec: %+v", p.Spec)
	}
}

func TestFSMReadSnapshotsAreDeepCopies(t *testing.T) {
	fsm := newPlacementFSM()
	place, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb1",
		OwnerNodeID: "nodeA",
		Spec: &models.CreateSandboxRequest{
			Image: "alpine",
			Env:   map[string]string{"A": "1"},
			Mounts: []models.MountSpec{{
				Target:      "/mnt/data",
				Options:     map[string]string{"ro": "true"},
				Credentials: map[string]string{"token": "secret"},
			}},
			Tags:             map[string]string{"team": "infra"},
			ContainerCommand: []string{"sleep", "60"},
			Registry:         &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "p"},
			Lifecycle:        &models.Lifecycle{StopAtAge: time.Minute},
			GPUs:             &models.GPURequest{Vendor: models.GPUVendorNVIDIA, DeviceIDs: []string{"0"}},
		},
		SealedSecrets: []byte("sealed"),
	})
	fsm.Apply(&raft.Log{Data: place})
	add, _ := encodeCommand(command{Op: opAddExposedPort, SandboxID: "sb1", Port: 8080, Protocol: "http"})
	fsm.Apply(&raft.Log{Data: add})

	got, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("missing placement")
	}
	got.Spec.Env["A"] = "mutated"
	got.Spec.Mounts[0].Options["ro"] = "false"
	got.Spec.Mounts[0].Credentials["token"] = "mutated"
	got.Spec.Tags["team"] = "mutated"
	got.Spec.ContainerCommand[0] = "rm"
	got.Spec.Registry.Password = "mutated"
	got.Spec.Lifecycle.StopAtAge = 2 * time.Minute
	got.Spec.GPUs.DeviceIDs[0] = "1"
	got.SealedSecrets[0] = 'X'
	got.ExposedPorts[8080] = "tcp"

	again, _ := fsm.get("sb1")
	if again.Spec.Env["A"] != "1" ||
		again.Spec.Mounts[0].Options["ro"] != "true" ||
		again.Spec.Mounts[0].Credentials["token"] != "secret" ||
		again.Spec.Tags["team"] != "infra" ||
		again.Spec.ContainerCommand[0] != "sleep" ||
		again.Spec.Registry.Password != "p" ||
		again.Spec.Lifecycle.StopAtAge != time.Minute ||
		again.Spec.GPUs.DeviceIDs[0] != "0" ||
		string(again.SealedSecrets) != "sealed" ||
		again.ExposedPorts[8080] != "http" {
		t.Fatalf("mutating get() result changed FSM state: %+v", again)
	}

	snap := fsm.snapshot()
	snap["sb1"].Spec.Env["A"] = "snap-mutated"
	snap["sb1"].ExposedPorts[8080] = "tls"
	afterSnap, _ := fsm.get("sb1")
	if afterSnap.Spec.Env["A"] != "1" || afterSnap.ExposedPorts[8080] != "http" {
		t.Fatalf("mutating snapshot() result changed FSM state: %+v", afterSnap)
	}
}
