package cluster

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"
	"testing"

	"github.com/hashicorp/raft"
)

// applyCustomDomainOp is a tiny helper so each test doesn't repeat the
// encode/Apply/decode dance. Returns the FSM Apply result so failure-path
// tests can assert on the wrapped error.
func applyCustomDomainOp(t *testing.T, fsm *placementFSM, idx uint64, cmd command) interface{} {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encode op %d: %v", cmd.Op, err)
	}
	return fsm.Apply(&raft.Log{Index: idx, Data: payload})
}

func mustPlaceForCustomDomains(t *testing.T, fsm *placementFSM, idx uint64, sandboxID, owner string) {
	t.Helper()
	if res := applyCustomDomainOp(t, fsm, idx, command{
		Op:          opPlace,
		SandboxID:   sandboxID,
		OwnerNodeID: owner,
		OwnerAPIURL: "http://" + owner,
	}); res != nil {
		t.Fatalf("place %s on %s: %v", sandboxID, owner, res)
	}
}

func TestFSMAddCustomDomain_ClaimsIndex(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")

	if res := applyCustomDomainOp(t, fsm, 2, command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add: %v", res)
	}
	got, ok := fsm.sandboxIDByCustomHostname("api.acme.com")
	if !ok || got != "sb-1" {
		t.Fatalf("resolver: got=%q ok=%v, want sb-1", got, ok)
	}
	p, _ := fsm.get("sb-1")
	if len(p.CustomHostnames) != 1 || p.CustomHostnames[0] != "api.acme.com" {
		t.Fatalf("placement hostnames=%v, want [api.acme.com]", p.CustomHostnames)
	}
}

func TestFSMAddCustomDomain_Idempotent(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	if res := applyCustomDomainOp(t, fsm, 2, command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add 1: %v", res)
	}
	first, _ := fsm.get("sb-1")

	// Re-apply same op: must not mutate the placement Version or duplicate
	// the hostname.
	if res := applyCustomDomainOp(t, fsm, 3, command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add 2: %v", res)
	}
	second, _ := fsm.get("sb-1")
	if first.Version != second.Version {
		t.Fatalf("idempotent re-add changed version: %d -> %d", first.Version, second.Version)
	}
	if len(second.CustomHostnames) != 1 {
		t.Fatalf("hostnames duplicated: %v", second.CustomHostnames)
	}
}

func TestFSMAddCustomDomain_CrossSandboxConflict(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-a", "nodeA")
	mustPlaceForCustomDomains(t, fsm, 2, "sb-b", "nodeA")
	if res := applyCustomDomainOp(t, fsm, 3, command{Op: opAddCustomDomain, SandboxID: "sb-a", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add to a: %v", res)
	}
	res := applyCustomDomainOp(t, fsm, 4, command{Op: opAddCustomDomain, SandboxID: "sb-b", Hostname: "api.acme.com"})
	err, _ := res.(error)
	if err == nil || !errors.Is(err, ErrCustomHostnameConflict) {
		t.Fatalf("cross-sandbox claim = %v, want ErrCustomHostnameConflict", res)
	}
	got, _ := fsm.sandboxIDByCustomHostname("api.acme.com")
	if got != "sb-a" {
		t.Fatalf("index changed after rejected conflict: got %q, want sb-a", got)
	}
	p, _ := fsm.get("sb-b")
	if len(p.CustomHostnames) != 0 {
		t.Fatalf("sb-b acquired hostname despite conflict: %v", p.CustomHostnames)
	}
}

func TestFSMAddCustomDomain_NoPlacementIsNoop(t *testing.T) {
	fsm := newPlacementFSM()
	// Race: hostname arrives at the FSM before the local create promotes
	// (or after a delete). Must NOT crash and must NOT leak an index entry
	// that points at a nonexistent sandbox.
	if res := applyCustomDomainOp(t, fsm, 1, command{Op: opAddCustomDomain, SandboxID: "sb-missing", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("apply: %v", res)
	}
	if _, ok := fsm.sandboxIDByCustomHostname("api.acme.com"); ok {
		t.Fatal("index leaked entry for nonexistent sandbox")
	}
}

func TestFSMRemoveCustomDomain_ReleasesIndex(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	if res := applyCustomDomainOp(t, fsm, 2, command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add: %v", res)
	}
	if res := applyCustomDomainOp(t, fsm, 3, command{Op: opRemoveCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("remove: %v", res)
	}
	if _, ok := fsm.sandboxIDByCustomHostname("api.acme.com"); ok {
		t.Fatal("index still claims hostname after remove")
	}
	p, _ := fsm.get("sb-1")
	if len(p.CustomHostnames) != 0 {
		t.Fatalf("hostname still on placement: %v", p.CustomHostnames)
	}
}

func TestFSMRemoveCustomDomain_IdempotentOnMissing(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	// No prior add; remove must be a no-op rather than an error so cleanup
	// retries are safe.
	if res := applyCustomDomainOp(t, fsm, 2, command{Op: opRemoveCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("remove never-added: %v", res)
	}
}

func TestFSMOpPlacePreservesCustomHostnames(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	if res := applyCustomDomainOp(t, fsm, 2, command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add: %v", res)
	}
	// Replay the original place (boot-time AssertOwnership shape) — the
	// hostnames replicated separately MUST survive.
	if res := applyCustomDomainOp(t, fsm, 3, command{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://nodeA"}); res != nil {
		t.Fatalf("re-place: %v", res)
	}
	p, _ := fsm.get("sb-1")
	if len(p.CustomHostnames) != 1 || p.CustomHostnames[0] != "api.acme.com" {
		t.Fatalf("re-place erased hostnames: %v", p.CustomHostnames)
	}
	if got, _ := fsm.sandboxIDByCustomHostname("api.acme.com"); got != "sb-1" {
		t.Fatalf("re-place dropped index: got %q", got)
	}
}

func TestFSMOpDeleteReleasesCustomHostnames(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	for i, h := range []string{"a.example", "b.example"} {
		if res := applyCustomDomainOp(t, fsm, uint64(2+i), command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: h}); res != nil {
			t.Fatalf("add %s: %v", h, res)
		}
	}
	if res := applyCustomDomainOp(t, fsm, 10, command{Op: opDelete, SandboxID: "sb-1"}); res != nil {
		t.Fatalf("delete: %v", res)
	}
	for _, h := range []string{"a.example", "b.example"} {
		if _, ok := fsm.sandboxIDByCustomHostname(h); ok {
			t.Fatalf("index still claims %s after delete", h)
		}
	}
}

func TestFSMSnapshotRestoreRoundTripsCustomHostnames(t *testing.T) {
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	for i, h := range []string{"alpha.example.com", "beta.example.com"} {
		if res := applyCustomDomainOp(t, fsm, uint64(2+i), command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: h}); res != nil {
			t.Fatalf("add %s: %v", h, res)
		}
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var buf bytes.Buffer
	sink := &bufferSink{buf: &buf}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Sanity: gob roundtrip must carry the hostname slice.
	var decoded fsmSnapshotPayload
	if err := gob.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Rows) != 1 || len(decoded.Rows[0].Placement.CustomHostnames) != 2 {
		t.Fatalf("snapshot rows hostnames=%v", decoded.Rows)
	}

	fresh := newPlacementFSM()
	if err := fresh.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	p, ok := fresh.get("sb-1")
	if !ok {
		t.Fatal("restored placement missing")
	}
	if len(p.CustomHostnames) != 2 || p.CustomHostnames[0] != "alpha.example.com" || p.CustomHostnames[1] != "beta.example.com" {
		t.Fatalf("restored hostnames=%v", p.CustomHostnames)
	}
	for _, h := range []string{"alpha.example.com", "beta.example.com"} {
		got, ok := fresh.sandboxIDByCustomHostname(h)
		if !ok || got != "sb-1" {
			t.Fatalf("restored index for %s: got=%q ok=%v", h, got, ok)
		}
	}
}

func TestFSMCustomHostnamesSortedOnInsert(t *testing.T) {
	// Sorted slices make snapshot bytes deterministic and give every node
	// the same matcher order without per-node post-processing.
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	for i, h := range []string{"zeta.example", "alpha.example", "mu.example"} {
		if res := applyCustomDomainOp(t, fsm, uint64(2+i), command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: h}); res != nil {
			t.Fatalf("add %s: %v", h, res)
		}
	}
	p, _ := fsm.get("sb-1")
	want := []string{"alpha.example", "mu.example", "zeta.example"}
	if len(p.CustomHostnames) != 3 {
		t.Fatalf("hostnames=%v", p.CustomHostnames)
	}
	for i, h := range want {
		if p.CustomHostnames[i] != h {
			t.Fatalf("hostnames[%d]=%q, want %q (full: %v)", i, p.CustomHostnames[i], h, p.CustomHostnames)
		}
	}
}

func TestFSMCustomDomainCanonicalizationOnResolve(t *testing.T) {
	// The Cluster wrapper lowercases on the way in; the resolver lowercases
	// on the way out so mixed-case TLS-ask probes still hit.
	fsm := newPlacementFSM()
	mustPlaceForCustomDomains(t, fsm, 1, "sb-1", "nodeA")
	if res := applyCustomDomainOp(t, fsm, 2, command{Op: opAddCustomDomain, SandboxID: "sb-1", Hostname: "api.acme.com"}); res != nil {
		t.Fatalf("add: %v", res)
	}
	for _, probe := range []string{"api.acme.com", "API.ACME.COM", "  api.acme.com  "} {
		got, ok := fsm.sandboxIDByCustomHostname(probe)
		if !ok || got != "sb-1" {
			t.Fatalf("resolve(%q): got=%q ok=%v", probe, got, ok)
		}
	}
}

// bufferSink is a minimal raft.SnapshotSink that writes into a bytes.Buffer
// for snapshot/restore round-trip tests. Cancel/Close/ID are intentionally
// minimal — the FSM only writes and closes.
type bufferSink struct {
	buf *bytes.Buffer
}

func (s *bufferSink) Write(p []byte) (int, error) { return s.buf.Write(p) }
func (s *bufferSink) Close() error                { return nil }
func (s *bufferSink) ID() string                  { return "test-snapshot" }
func (s *bufferSink) Cancel() error               { return nil }
