package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func TestQualifiedSandboxNameRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		ownerRef  string
		userName  string
		wantKey   string
		qualified bool
	}{
		{name: "operator keeps plain name", ownerRef: "", userName: "my-agent", wantKey: "my-agent"},
		{name: "unnamed stays empty", ownerRef: "acct-a", userName: "", wantKey: ""},
		{name: "tenant is qualified", ownerRef: "acct-a", userName: "my-agent", wantKey: "owner:" + base64.RawURLEncoding.EncodeToString([]byte("acct-a")) + "/my-agent", qualified: true},
		{name: "owner with url-unsafe bytes", ownerRef: "org/team+1", userName: "x", wantKey: "owner:" + base64.RawURLEncoding.EncodeToString([]byte("org/team+1")) + "/x", qualified: true},
		{name: "name with slash", ownerRef: "acct-a", userName: "team/agent", wantKey: "owner:" + base64.RawURLEncoding.EncodeToString([]byte("acct-a")) + "/team/agent", qualified: true},
		{name: "whitespace trimmed", ownerRef: " acct-a ", userName: " my-agent ", wantKey: "owner:" + base64.RawURLEncoding.EncodeToString([]byte("acct-a")) + "/my-agent", qualified: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := QualifiedSandboxName(tt.ownerRef, tt.userName)
			if key != tt.wantKey {
				t.Fatalf("QualifiedSandboxName(%q, %q) = %q, want %q", tt.ownerRef, tt.userName, key, tt.wantKey)
			}
			if again := QualifiedSandboxName(tt.ownerRef, key); again != key {
				t.Fatalf("encoder is not idempotent: %q -> %q", key, again)
			}
			owner, name, qualified := DecodeSandboxNameKey(key)
			if qualified != tt.qualified {
				t.Fatalf("DecodeSandboxNameKey(%q) qualified = %v, want %v", key, qualified, tt.qualified)
			}
			if name != strings.TrimSpace(tt.userName) {
				t.Fatalf("DecodeSandboxNameKey(%q) name = %q, want %q", key, name, strings.TrimSpace(tt.userName))
			}
			if qualified && owner != strings.TrimSpace(tt.ownerRef) {
				t.Fatalf("DecodeSandboxNameKey(%q) owner = %q, want %q", key, owner, tt.ownerRef)
			}
		})
	}
}

// TestDecodeSandboxNameKeyLegacyPrefixDecodesToItself is the required proof
// for the D9 decode fallback: a legacy sandbox whose plain name already
// started with "owner:" (created before the prefix was reserved) is not a
// valid encoded key, so it decodes to itself and never errors.
func TestDecodeSandboxNameKeyLegacyPrefixDecodesToItself(t *testing.T) {
	for _, key := range []string{
		"owner:",
		"owner:abc",
		"owner:/name",
		"owner:abc/",
		"owner:!!!/name",
		"owner:" + base64.StdEncoding.EncodeToString([]byte("acct?")) + "/name",
		"owner:" + base64.RawURLEncoding.EncodeToString([]byte("acct-a")) + "/owner:nested",
	} {
		owner, name, qualified := DecodeSandboxNameKey(key)
		if qualified || owner != "" || name != key {
			t.Fatalf("DecodeSandboxNameKey(%q) = (%q, %q, %v), want (\"\", key, false)", key, owner, name, qualified)
		}
		if got := SandboxNameFromKey(key); got != key {
			t.Fatalf("SandboxNameFromKey(%q) = %q, want the key itself", key, got)
		}
		spec := DecodeSpecName(models.CreateSandboxRequest{Name: key})
		if spec.Name != key {
			t.Fatalf("DecodeSpecName(%q) = %q, want the key itself", key, spec.Name)
		}
	}
}

func TestQualifySpecNameCopiesOnlyOnRewrite(t *testing.T) {
	if QualifySpecName(nil, "acct-a") != nil {
		t.Fatal("nil spec must stay nil")
	}
	operator := &models.CreateSandboxRequest{Name: "my-agent", Image: "alpine"}
	if got := QualifySpecName(operator, ""); got != operator {
		t.Fatal("operator spec must be returned as-is (no allocation)")
	}
	unnamed := &models.CreateSandboxRequest{Image: "alpine"}
	if got := QualifySpecName(unnamed, "acct-a"); got != unnamed {
		t.Fatal("unnamed spec must be returned as-is")
	}
	tenant := &models.CreateSandboxRequest{Name: "my-agent", Image: "alpine"}
	got := QualifySpecName(tenant, "acct-a")
	if got == tenant {
		t.Fatal("tenant spec must be copied before rewriting")
	}
	if tenant.Name != "my-agent" {
		t.Fatalf("caller's spec was mutated: %q", tenant.Name)
	}
	if got.Name != QualifiedSandboxName("acct-a", "my-agent") || got.Image != "alpine" {
		t.Fatalf("qualified spec = %+v", got)
	}
	if again := QualifySpecName(got, "acct-a"); again != got {
		t.Fatal("an already-qualified spec must be returned as-is")
	}
	if decoded := DecodeSpecName(*got); decoded.Name != "my-agent" || decoded.Image != "alpine" {
		t.Fatalf("DecodeSpecName = %+v", decoded)
	}
	if specNeedsOwnerForName(nil) || specNeedsOwnerForName(unnamed) || specNeedsOwnerForName(got) || !specNeedsOwnerForName(tenant) {
		t.Fatal("specNeedsOwnerForName misclassified a spec")
	}
}

// TestFSMNameIndexPerOwner pins D4: names are unique per owner. Two tenants
// can hold the same name, the same tenant can't hold it twice, and operator
// (plain) names stay unique among themselves.
func TestFSMNameIndexPerOwner(t *testing.T) {
	fsm := newPlacementFSM()
	place := func(id, ownerRef, name string) any {
		spec := QualifySpecName(&models.CreateSandboxRequest{Name: name}, ownerRef)
		return applyOp(t, fsm, command{Op: opPlace, SandboxID: id, OwnerNodeID: "node-1", OwnerRef: ownerRef, Spec: spec})
	}
	if got := place("sb-a1", "acct-a", "agent"); got != nil {
		t.Fatalf("tenant A place: %v", got)
	}
	if got := place("sb-b1", "acct-b", "agent"); got != nil {
		t.Fatalf("tenant B must be able to reuse A's name: %v", got)
	}
	if got := place("sb-op1", "", "agent"); got != nil {
		t.Fatalf("operator must be able to reuse a tenant name: %v", got)
	}
	for _, tc := range []struct{ id, ownerRef string }{{"sb-a2", "acct-a"}, {"sb-op2", ""}} {
		err, _ := place(tc.id, tc.ownerRef, "agent").(error)
		if !errors.Is(err, ErrNameConflict) {
			t.Fatalf("second %q create of the same name = %v, want ErrNameConflict", tc.ownerRef, err)
		}
	}
	for ownerRef, want := range map[string]string{"acct-a": "sb-a1", "acct-b": "sb-b1", "": "sb-op1"} {
		if id, ok := fsm.sandboxIDByOwnerName(ownerRef, "agent"); !ok || id != want {
			t.Fatalf("sandboxIDByOwnerName(%q) = (%q, %v), want %q", ownerRef, id, ok, want)
		}
	}
	if _, ok := fsm.sandboxIDByOwnerName("acct-c", "agent"); ok {
		t.Fatal("a tenant with no such sandbox must not resolve another tenant's name")
	}
	if _, ok := fsm.sandboxIDByOwnerName("acct-a", "  "); ok {
		t.Fatal("blank name must not resolve")
	}
	if p, ok := fsm.get("sb-a1"); !ok || p.Name != QualifiedSandboxName("acct-a", "agent") {
		t.Fatalf("Placement.Name must carry the key: %+v", p)
	}
}

// TestFSMSandboxIDByOwnerNameLegacyFallback pins the upgrade path: a tenant
// sandbox created before per-owner names sits under its plain key, and it
// keeps resolving for its own owner only.
func TestFSMSandboxIDByOwnerNameLegacyFallback(t *testing.T) {
	fsm := newPlacementFSM()
	// An old proposer wrote the tenant's plain name.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-legacy", OwnerNodeID: "node-1", OwnerRef: "acct-a", Spec: &models.CreateSandboxRequest{Name: "legacy"}})
	if id, ok := fsm.sandboxIDByOwnerName("acct-a", "legacy"); !ok || id != "sb-legacy" {
		t.Fatalf("owner must resolve its legacy name, got (%q, %v)", id, ok)
	}
	for _, other := range []string{"acct-b", ""} {
		if id, ok := fsm.sandboxIDByOwnerName(other, "legacy"); ok {
			t.Fatalf("owner %q resolved acct-a's legacy sandbox %q", other, id)
		}
	}
	// During the upgrade window the same owner can end up with a legacy and a
	// new sandbox of one name (old and new proposers). The qualified key wins.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-new", OwnerNodeID: "node-2", OwnerRef: "acct-a", Spec: QualifySpecName(&models.CreateSandboxRequest{Name: "legacy"}, "acct-a")})
	if id, ok := fsm.sandboxIDByOwnerName("acct-a", "legacy"); !ok || id != "sb-new" {
		t.Fatalf("qualified key must win over the legacy plain key, got (%q, %v)", id, ok)
	}
}

// TestFSMNameIndexMixedVersionDeterminism is the D9 rolling-upgrade proof.
// The apply path is unchanged, so the index key comes from the command bytes
// alone: an FSM that applies the whole log and an FSM that applies half,
// snapshots, restores into a fresh FSM and applies the rest end with the same
// nameIndex, for a log that mixes old proposers (plain tenant names) and new
// proposers (owner-qualified keys).
func TestFSMNameIndexMixedVersionDeterminism(t *testing.T) {
	expiry := time.Now().Add(5 * time.Minute).Unix()
	qualified := func(ownerRef, name string) *models.CreateSandboxRequest {
		return QualifySpecName(&models.CreateSandboxRequest{Name: name, Image: "alpine"}, ownerRef)
	}
	plain := func(name string) *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Name: name, Image: "alpine"}
	}
	log := []command{
		// old proposer, tenant create: plain key
		{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "n1", OwnerRef: "acct-a", IncarnationID: "inc-1", Spec: plain("shared")},
		// new proposer, other tenant, same name: qualified key, no conflict
		{Op: opReserve, SandboxID: "sb-2", OwnerNodeID: "n2", OwnerRef: "acct-b", IncarnationID: "inc-2", ExpiresUnix: expiry, Spec: qualified("acct-b", "shared")},
		{Op: opPlace, SandboxID: "sb-2", OwnerNodeID: "n2", OwnerRef: "acct-b", IncarnationID: "inc-2", ExpectedIncarnationID: "inc-2", Spec: qualified("acct-b", "shared")},
		// operator create, plain
		{Op: opPlace, SandboxID: "sb-3", OwnerNodeID: "n1", IncarnationID: "inc-3", Spec: plain("ops")},
		// new proposer, tenant A reuses its legacy name under the new key
		{Op: opPlace, SandboxID: "sb-4", OwnerNodeID: "n3", OwnerRef: "acct-a", IncarnationID: "inc-4", Spec: qualified("acct-a", "shared")},
		// an old proposer replays a spec write-through for sb-2 with its key
		{Op: opUpsertSpec, SandboxID: "sb-2", IncarnationID: "inc-2", ExpectedIncarnationID: "inc-2", Spec: qualified("acct-b", "shared")},
		// a conflicting duplicate from an old proposer is rejected on every replica
		{Op: opPlace, SandboxID: "sb-5", OwnerNodeID: "n2", IncarnationID: "inc-5", Spec: plain("ops")},
		// delete releases the key
		{Op: opDelete, SandboxID: "sb-1", ExpectedIncarnationID: "inc-1"},
		{Op: opPlace, SandboxID: "sb-6", OwnerNodeID: "n2", OwnerRef: "acct-c", IncarnationID: "inc-6", Spec: qualified("acct-c", "shared")},
	}
	payloads := make([][]byte, len(log))
	for i, cmd := range log {
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		payloads[i] = payload
	}
	apply := func(fsm *placementFSM, entries [][]byte) []any {
		out := make([]any, 0, len(entries))
		for _, payload := range entries {
			out = append(out, fsm.Apply(&raft.Log{Data: payload}))
		}
		return out
	}
	full := newPlacementFSM()
	fullResults := apply(full, payloads)

	half := len(payloads) / 2
	first := newPlacementFSM()
	firstResults := apply(first, payloads[:half])
	snap, err := first.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	restored := newPlacementFSMWithRecoveryStore(first.recoveryStore)
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restoredResults := append(firstResults, apply(restored, payloads[half:])...)

	for i := range fullResults {
		fullErr, _ := fullResults[i].(error)
		restoredErr, _ := restoredResults[i].(error)
		if (fullErr == nil) != (restoredErr == nil) {
			t.Fatalf("entry %d diverged: full=%v restored=%v", i, fullErr, restoredErr)
		}
	}
	if err, _ := fullResults[6].(error); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("duplicate operator name = %v, want ErrNameConflict", fullResults[6])
	}
	full.mu.RLock()
	fullIndex := maps.Clone(full.nameIndex)
	full.mu.RUnlock()
	restored.mu.RLock()
	restoredIndex := maps.Clone(restored.nameIndex)
	restored.mu.RUnlock()
	if !maps.Equal(fullIndex, restoredIndex) {
		t.Fatalf("nameIndex diverged:\nfull     %v\nrestored %v", fullIndex, restoredIndex)
	}
	want := map[string]string{
		QualifiedSandboxName("acct-b", "shared"): "sb-2",
		"ops":                                    "sb-3",
		QualifiedSandboxName("acct-a", "shared"): "sb-4",
		QualifiedSandboxName("acct-c", "shared"): "sb-6",
	}
	if !maps.Equal(fullIndex, want) {
		t.Fatalf("nameIndex = %v, want %v", fullIndex, want)
	}
}

// TestClusterProposersQualifyTenantNames drives the real single-node Raft
// proposers: the key is written by the proposer, a promote keeps it, a spec
// write-through read back from SpecOf keeps it, and a write-through that
// carries the plain name falls back to the placement's replicated owner.
func TestClusterProposersQualifyTenantNames(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}
	c, cleanup := newTestCluster(t, "n1", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	// Reservations are admitted against gossiped capacity; give the node some.
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 8192, DiskTotalGB: 100, DiskFreeGB: 100},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	)
	c.gossip.delegate.mu.Lock()
	c.gossip.delegate.admitter = admitter
	c.gossip.delegate.mu.Unlock()
	c.gossip.refreshMemberIndex()
	c.capacityLeases.setAdmitter(admitter)
	c.capacityLeases.set(c.nodeID, admitter.Snapshot(), time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	key := QualifiedSandboxName("acct-a", "agent")
	target := PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost}
	tenantSpec := &models.CreateSandboxRequest{Name: "agent", Image: "alpine"}
	if err := c.ReserveOnTarget(ctx, "sb-tenant", target, tenantSpec, PlacementSecrets{OwnerRef: "acct-a"}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if tenantSpec.Name != "agent" {
		t.Fatalf("proposer mutated the caller's spec: %q", tenantSpec.Name)
	}
	if id, ok := c.fsm.sandboxIDByName(key); !ok || id != "sb-tenant" {
		t.Fatalf("reservation key = (%q, %v), want sb-tenant under %q", id, ok, key)
	}
	if err := c.RecordPlacement(ctx, "sb-tenant", &models.CreateSandboxRequest{Name: "agent", Image: "alpine"}, PlacementSecrets{OwnerRef: "acct-a"}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, ok := c.fsm.sandboxIDByName("agent"); ok {
		t.Fatal("promote must not claim the plain (operator) key for a tenant sandbox")
	}
	// Another tenant reuses the name on the same cluster.
	if err := c.RecordPlacement(ctx, "sb-other", &models.CreateSandboxRequest{Name: "agent", Image: "alpine"}, PlacementSecrets{OwnerRef: "acct-b"}); err != nil {
		t.Fatalf("second tenant with the same name: %v", err)
	}
	// SpecOf returns the key; replaying it keeps the key.
	spec := c.SpecOf("sb-tenant")
	if spec == nil || spec.Name != key {
		t.Fatalf("SpecOf name = %+v, want key %q", spec, key)
	}
	spec.CPU = 2
	if err := c.UpsertSpec(ctx, "sb-tenant", spec, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec(SpecOf): %v", err)
	}
	// A write-through with the plain name and no owner falls back to the
	// placement's replicated owner instead of renaming the key.
	if err := c.UpsertSpec(ctx, "sb-tenant", &models.CreateSandboxRequest{Name: "agent", Image: "alpine", CPU: 3}, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec(plain): %v", err)
	}
	if id, ok := c.fsm.sandboxIDByName(key); !ok || id != "sb-tenant" {
		t.Fatalf("key after write-throughs = (%q, %v), want sb-tenant", id, ok)
	}
	// Operator names stay plain.
	if err := c.RecordPlacement(ctx, "sb-op", &models.CreateSandboxRequest{Name: "agent", Image: "alpine"}, PlacementSecrets{}); err != nil {
		t.Fatalf("operator create: %v", err)
	}
	if id, ok := c.fsm.sandboxIDByName("agent"); !ok || id != "sb-op" {
		t.Fatalf("operator key = (%q, %v), want sb-op", id, ok)
	}

	for ownerRef, want := range map[string]string{"acct-a": "sb-tenant", "acct-b": "sb-other", "": "sb-op"} {
		id, owner, err := c.OwnerOfName(ownerRef, "agent")
		if err != nil || id != want || !owner.IsSelf {
			t.Fatalf("OwnerOfName(%q) = (%q, %+v, %v), want %q", ownerRef, id, owner, err, want)
		}
	}
	if _, _, err := c.OwnerOfName("acct-c", "agent"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfName(other tenant) error = %v, want ErrUnknownSandbox", err)
	}
	if id, _, err := c.OwnerOfNameKey(key); err != nil || id != "sb-tenant" {
		t.Fatalf("OwnerOfNameKey(key) = (%q, %v), want sb-tenant", id, err)
	}
	if _, _, err := c.OwnerOfNameKey("missing"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfNameKey(missing) error = %v, want ErrUnknownSandbox", err)
	}
}

func TestAgentOwnerOfNamePerOwner(t *testing.T) {
	keyPath := func(key string) string {
		return PublicInternalPlacementByNamePath + base64.RawURLEncoding.EncodeToString([]byte(key))
	}
	lookups := map[string]PlacementLookupResponse{
		keyPath(QualifiedSandboxName("acct-a", "agent")): {SandboxID: "sb-new", Owner: OwnerInfo{NodeID: "worker-self"}, Placement: Placement{OwnerRef: "acct-a"}},
		keyPath("legacy"): {SandboxID: "sb-legacy", Owner: OwnerInfo{NodeID: "worker-2"}, Placement: Placement{OwnerRef: "acct-a"}},
		keyPath(QualifiedSandboxName("acct-a", "gone")): {SandboxID: "sb-gone", Orphaned: true, Placement: Placement{OwnerRef: "acct-a"}},
	}
	brokenPath := keyPath(QualifiedSandboxName("acct-z", "agent"))
	var seen []string
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.URL.Path == brokenPath {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		lookup, ok := lookups[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(lookup)
	}))

	id, owner, err := agent.OwnerOfName("acct-a", "agent")
	if err != nil || id != "sb-new" || !owner.IsSelf {
		t.Fatalf("qualified lookup = (%q, %+v, %v)", id, owner, err)
	}
	if len(seen) != 1 {
		t.Fatalf("a qualified hit must cost one request, made %v", seen)
	}
	if id, owner, err := agent.OwnerOfName(" acct-a ", " legacy "); err != nil || id != "sb-legacy" || owner.IsSelf {
		t.Fatalf("legacy fallback = (%q, %+v, %v)", id, owner, err)
	}
	for _, ownerRef := range []string{"acct-b", ""} {
		if _, _, err := agent.OwnerOfName(ownerRef, "legacy"); !errors.Is(err, ErrUnknownSandbox) {
			t.Fatalf("OwnerOfName(%q, legacy) error = %v, want ErrUnknownSandbox", ownerRef, err)
		}
	}
	if id, _, err := agent.OwnerOfName("acct-a", "gone"); !errors.Is(err, ErrOrphaned) || id != "sb-gone" {
		t.Fatalf("orphaned lookup = (%q, %v), want (sb-gone, ErrOrphaned)", id, err)
	}
	if _, _, err := agent.OwnerOfName("acct-z", "agent"); err == nil || errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("a control-plane failure must surface, got %v", err)
	}
	if _, _, err := agent.OwnerOfName("acct-a", "  "); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("blank name error = %v, want ErrUnknownSandbox", err)
	}
	if id, _, err := agent.OwnerOfNameKey("legacy"); err != nil || id != "sb-legacy" {
		t.Fatalf("OwnerOfNameKey(legacy) = (%q, %v)", id, err)
	}
	if _, _, err := agent.OwnerOfNameKey("missing"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfNameKey(missing) error = %v", err)
	}
}

func TestAgentProposersQualifyTenantNames(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath) {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
			SandboxID: strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath),
			Placement: Placement{IncarnationID: "inc-1", OwnerRef: "acct-a", OwnerState: PlacementOwnerStateOrphaned},
		})
		return true
	}))
	ctx := context.Background()
	key := QualifiedSandboxName("acct-a", "agent")
	spec := func() *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Name: "agent", Image: "alpine"}
	}

	if err := agent.ReserveOnTarget(ctx, "sb-1", PlacementTarget{NodeID: "worker-self"}, spec(), PlacementSecrets{OwnerRef: "acct-a"}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}
	if err := agent.RecordPlacement(ctx, "sb-1", spec(), PlacementSecrets{OwnerRef: "acct-a", IncarnationID: "inc-1"}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	// No owner passed: the lookup the proposer already makes supplies it.
	if err := agent.RecordPlacement(ctx, "sb-1", spec(), PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement(no owner): %v", err)
	}
	if err := agent.ClaimOrphan(ctx, "sb-1", spec(), PlacementSecrets{}); err != nil {
		t.Fatalf("ClaimOrphan: %v", err)
	}
	if err := agent.UpsertSpec(ctx, "sb-1", spec(), PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec: %v", err)
	}
	if err := agent.RecordPlacement(ctx, "sb-op", spec(), PlacementSecrets{IncarnationID: "inc-op"}); err != nil {
		t.Fatalf("operator RecordPlacement: %v", err)
	}

	capture.mu.Lock()
	commands := append([]command(nil), capture.commands...)
	capture.mu.Unlock()
	if len(commands) != 6 {
		t.Fatalf("captured %d commands, want 6", len(commands))
	}
	for i, cmd := range commands[:5] {
		if cmd.Spec == nil || cmd.Spec.Name != key {
			t.Fatalf("command %d (op %d) spec name = %+v, want %q", i, cmd.Op, cmd.Spec, key)
		}
	}
	if commands[5].Spec == nil || commands[5].Spec.Name != "agent" {
		t.Fatalf("operator command spec name = %+v, want plain", commands[5].Spec)
	}
}

func TestNoopNameLookupsAreUnknown(t *testing.T) {
	n := NewNoop("node-a", "http://node-a", "")
	if _, _, err := n.OwnerOfName("acct-a", "agent"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("Noop.OwnerOfName error = %v, want ErrUnknownSandbox", err)
	}
	if _, _, err := n.OwnerOfNameKey("agent"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("Noop.OwnerOfNameKey error = %v, want ErrUnknownSandbox", err)
	}
}
