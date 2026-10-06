package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for named egress profiles in the FSM
// (plans/egress-domain-filtering.md D21, CEO D19; CLAUDE.md rule 6).

type profileLog struct {
	t   *testing.T
	fsm *placementFSM
	idx uint64
}

func newProfileLog(t *testing.T) *profileLog {
	return &profileLog{t: t, fsm: newPlacementFSM()}
}

func (l *profileLog) apply(cmd command) any {
	l.t.Helper()
	data, err := encodeCommand(cmd)
	if err != nil {
		l.t.Fatal(err)
	}
	l.idx++
	return l.fsm.Apply(&raft.Log{Index: l.idx, Data: data})
}

func (l *profileLog) put(owner, name string, count int, allow ...string) any {
	return l.apply(command{Op: opPutEgressProfile, StampUnixNano: int64(l.idx + 1),
		EgressProfile: &EgressProfileRecord{Owner: owner, Name: name, AllowOut: allow, HostnameCount: count}})
}

func (l *profileLog) del(owner, name string) any {
	return l.apply(command{Op: opDeleteEgressProfile, EgressProfile: &EgressProfileRecord{Owner: owner, Name: name}})
}

func (l *profileLog) place(id, owner string, spec *models.CreateSandboxRequest) {
	l.t.Helper()
	if got := l.apply(command{Op: opPlace, SandboxID: id, OwnerNodeID: "node-a", OwnerRef: owner, IncarnationID: "inc-" + id, Spec: spec}); got != nil {
		l.t.Fatalf("place %s: %v", id, got)
	}
}

func (l *profileLog) remove(id string) {
	l.t.Helper()
	if got := l.apply(command{Op: opDelete, SandboxID: id, ExpectedIncarnationID: "inc-" + id}); got != nil {
		l.t.Fatalf("delete %s: %v", id, got)
	}
}

func asApplyErr(v any) error {
	err, _ := v.(error)
	return err
}

func TestFSMEgressProfilePutGenerations(t *testing.T) {
	l := newProfileLog(t)
	res, ok := l.put("acct", "python", 1, "pypi.org").(egressProfileApplyResult)
	if !ok || !res.Changed || res.Profile.Generation != 1 || res.Profile.CreatedUnixNano == 0 {
		t.Fatalf("create = %+v", res)
	}
	created := res.Profile.CreatedUnixNano
	if res := l.put("acct", "python", 1, "pypi.org").(egressProfileApplyResult); res.Changed || res.Profile.Generation != 1 {
		t.Fatalf("a retry of the same write must not bump the generation: %+v", res)
	}
	res = l.put("acct", "python", 2, "pypi.org", "*.pythonhosted.org").(egressProfileApplyResult)
	if !res.Changed || res.Profile.Generation != 2 || res.Profile.CreatedUnixNano != created || res.Profile.UpdatedUnixNano == created {
		t.Fatalf("update = %+v", res)
	}
	if _, ok := l.fsm.egressProfile("other", "python"); ok {
		t.Fatal("owners are separate namespaces")
	}
	if err := asApplyErr(l.del("acct", "missing")); err != nil {
		t.Fatalf("deleting a missing profile is a no-op: %v", err)
	}
	if err := asApplyErr(l.apply(command{Op: opPutEgressProfile})); err == nil {
		t.Fatal("a put without a profile must fail")
	}
	if err := asApplyErr(l.apply(command{Op: opDeleteEgressProfile})); err == nil {
		t.Fatal("a delete without a profile must fail")
	}
}

// TestFSMEgressProfileDeleteInUse: the reference index follows every
// placement write and delete, so delete-in-use holds however creates and
// deletes interleave.
func TestFSMEgressProfileDeleteInUse(t *testing.T) {
	l := newProfileLog(t)
	l.put("acct", "python", 1, "pypi.org")
	l.place("sb-1", "acct", &models.CreateSandboxRequest{NetworkAllowOut: []string{"10.0.0.0/8"}, EgressProfiles: []string{"python"}})
	// The same name under another owner is a different profile.
	l.place("sb-2", "other", &models.CreateSandboxRequest{EgressProfiles: []string{"python"}})
	if err := asApplyErr(l.del("acct", "python")); !errors.Is(err, ErrEgressProfileInUse) {
		t.Fatalf("referenced: %v", err)
	}
	// A spec update that drops the reference frees it.
	if got := l.apply(command{Op: opUpsertSpec, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1", Spec: &models.CreateSandboxRequest{}}); got != nil {
		t.Fatalf("upsert: %v", got)
	}
	if err := asApplyErr(l.del("acct", "python")); err != nil {
		t.Fatalf("after the spec dropped it: %v", err)
	}
	l.put("acct", "python", 1, "pypi.org")
	if got := l.apply(command{Op: opUpsertSpec, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1", Spec: &models.CreateSandboxRequest{EgressProfiles: []string{"python"}}}); got != nil {
		t.Fatalf("upsert: %v", got)
	}
	if err := asApplyErr(l.del("acct", "python")); !errors.Is(err, ErrEgressProfileInUse) {
		t.Fatalf("referenced again: %v", err)
	}
	l.remove("sb-1")
	if err := asApplyErr(l.del("acct", "python")); err != nil {
		t.Fatalf("after the sandbox was deleted: %v", err)
	}
	if len(l.fsm.egressProfileRefs[EgressProfileKey{"acct", "python"}]) != 0 {
		t.Fatal("index kept a deleted sandbox")
	}
}

func TestFSMEgressProfileUnionCap(t *testing.T) {
	l := newProfileLog(t)
	var inline []string
	for i := 0; i < 24; i++ {
		inline = append(inline, fmt.Sprintf("h%d.example.com", i))
	}
	l.put("acct", "big", egresspolicy.MaxProfileHostnames)
	l.put("acct", "small", 1, "a.example.com")
	l.place("sb-cap", "acct", &models.CreateSandboxRequest{NetworkAllowOut: inline, EgressProfiles: []string{"big", "small"}})
	if p := l.fsm.placements["sb-cap"]; p.EgressInlineHostnames != 24 || len(p.EgressProfiles) != 2 {
		t.Fatalf("hot row = %+v", p)
	}
	// 24 + 512 + 488 = 1024: at the cap.
	atCap := egresspolicy.MaxUnionHostnames - 24 - egresspolicy.MaxProfileHostnames
	if res, ok := l.put("acct", "small", atCap, "at-cap.example.com").(egressProfileApplyResult); !ok || !res.Changed {
		t.Fatalf("at the cap: %v", res)
	}
	err := asApplyErr(l.put("acct", "small", atCap+1, "over-cap.example.com"))
	if !errors.Is(err, ErrEgressProfileCapExceeded) || !strings.Contains(err.Error(), "sb-cap") {
		t.Fatalf("over the cap: %v", err)
	}
	if rec, _ := l.fsm.egressProfile("acct", "small"); rec.Generation != 2 {
		t.Fatalf("a refused change must leave the profile as it was: %+v", rec)
	}
}

// TestFSMEgressProfileReplayIsDeterministic: two replicas applying the same
// log, refusals included, end in the same state. This is what makes a
// race between a create and a delete resolve the same way everywhere.
func TestFSMEgressProfileReplayIsDeterministic(t *testing.T) {
	a, b := newProfileLog(t), newProfileLog(t)
	for _, l := range []*profileLog{a, b} {
		l.put("acct", "python", 1, "pypi.org")
		l.place("sb-1", "acct", &models.CreateSandboxRequest{EgressProfiles: []string{"python"}})
		if err := asApplyErr(l.del("acct", "python")); !errors.Is(err, ErrEgressProfileInUse) {
			t.Fatalf("delete racing a create: %v", err)
		}
		l.put("acct", "python", 2, "pypi.org", "files.pythonhosted.org")
	}
	if !reflect.DeepEqual(a.fsm.egressProfiles, b.fsm.egressProfiles) || !reflect.DeepEqual(a.fsm.egressProfileRefs, b.fsm.egressProfileRefs) {
		t.Fatal("replicas diverged")
	}
}

func TestFSMEgressProfileSnapshotRestore(t *testing.T) {
	l := newProfileLog(t)
	l.put("acct", "python", 1, "pypi.org")
	l.put("acct", "go", 1, "proxy.golang.org")
	l.place("sb-1", "acct", &models.CreateSandboxRequest{EgressProfiles: []string{"python"}})
	snap, err := l.fsm.Snapshot()
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
	if !reflect.DeepEqual(restored.egressProfiles, l.fsm.egressProfiles) {
		t.Fatal("profiles did not survive the snapshot")
	}
	if _, ok := restored.egressProfileRefs[EgressProfileKey{"acct", "python"}]["sb-1"]; !ok {
		t.Fatal("the reference index must be rebuilt from the placements")
	}
	page := restored.egressProfilesPage("acct", "", 0)
	if len(page) != 2 || page[0].Name != "go" {
		t.Fatalf("page = %+v", page)
	}
	if page := restored.egressProfilesPage("acct", "go", 1); len(page) != 1 || page[0].Name != "python" {
		t.Fatalf("page after go = %+v", page)
	}

	// A snapshot from a build without profiles restores to none.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 1}); err != nil {
		t.Fatal(err)
	}
	old := newPlacementFSM()
	if err := old.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if len(old.egressProfiles) != 0 {
		t.Fatal("an old snapshot must restore to no profiles")
	}
}

type memSnapshotSink struct{ bytes.Buffer }

func (s *memSnapshotSink) ID() string    { return "mem" }
func (s *memSnapshotSink) Cancel() error { return nil }
func (s *memSnapshotSink) Close() error  { return nil }

func TestEgressInlineHostnames(t *testing.T) {
	if n := egressInlineHostnames(nil); n != 0 {
		t.Fatal(n)
	}
	if n := egressInlineHostnames(&models.CreateSandboxRequest{NetworkAllowOut: []string{"a.example.com"}}); n != 0 {
		t.Fatalf("without profiles the count isn't needed: %d", n)
	}
	spec := &models.CreateSandboxRequest{NetworkAllowOut: []string{"a.example.com", "10.0.0.0/8", "b.example.com:22"}, EgressProfiles: []string{"p"}}
	if n := egressInlineHostnames(spec); n != 2 {
		t.Fatalf("count = %d", n)
	}
	spec.NetworkAllowOut = []string{"bad host!", "a.example.com"}
	if n := egressInlineHostnames(spec); n != 2 {
		t.Fatalf("an unparsable list counts every entry: %d", n)
	}
}

// TestEgressProfileWritesGate covers the rolling-upgrade gate (D19): mixed
// fv refuses with ErrClusterVersion, all upgraded is accepted, and a failed
// server counts at its last-known version.
func TestEgressProfileWritesGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	write := func() error {
		_, err := c.WriteEgressProfile(ctx, EgressProfileWriteRequest{Profile: EgressProfileRecord{Owner: "acct", Name: "python", AllowOut: []string{"pypi.org"}, HostnameCount: 1}})
		return err
	}
	if err := write(); err != nil {
		t.Fatalf("a one-server cluster on this build: %v", err)
	}
	// A second Raft server this leader has never seen in gossip counts as an
	// old build.
	if err := c.raft.raft.AddNonvoter("gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	if err := write(); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("unknown server: %v", err)
	}
	index := c.gossip.currentMemberIndex()
	index.upsert(Member{NodeID: "gate-b", Alive: false, FSMOpsVersion: 0})
	if err := write(); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("failed server on an old build: %v", err)
	}
	index.upsert(Member{NodeID: "gate-b", Alive: false, FSMOpsVersion: fsmOpsVersion})
	resp, err := c.WriteEgressProfile(ctx, EgressProfileWriteRequest{Profile: EgressProfileRecord{Owner: "acct", Name: "python", AllowOut: []string{"pypi.org", "files.pythonhosted.org"}, HostnameCount: 2}})
	if err != nil || resp.Profile.Generation != 2 || !resp.Changed {
		t.Fatalf("all upgraded: %+v %v", resp, err)
	}
	read, err := c.ReadEgressProfiles(ctx, EgressProfileReadRequest{Owner: "acct", Names: []string{"python", "missing"}})
	if err != nil || len(read.Profiles) != 1 || !read.Authoritative {
		t.Fatalf("read = %+v %v", read, err)
	}
	if _, err := c.WriteEgressProfile(ctx, EgressProfileWriteRequest{Delete: true, Profile: EgressProfileRecord{Owner: "acct", Name: "python"}}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// TestNodeMetaWithFSMOpsVersionFitsMetaSize is the 512-byte trap (D1): the
// meta with every field at a long realistic length stays under memberlist's
// MetaMaxSize, so fv never pushes RaftAddr out.
func TestNodeMetaWithFSMOpsVersionFitsMetaSize(t *testing.T) {
	long := func(prefix string, n int) string { return prefix + strings.Repeat("x", n) }
	d := &gossipDelegate{
		nodeID:        long("node-", 59),
		nodeName:      long("name-", 59),
		apiURL:        "https://" + long("api-", 60) + ".example.com:21212",
		dataPlaneHost: long("dp-", 40) + ".example.com",
		raftAddr:      "10.255.255.255:7946",
		internalURL:   "https://" + long("int-", 50) + ".example.com:21443",
		role:          "server",
		publicHost:    long("pub-", 30) + ".example.com",
	}
	d.refreshMeta()
	enc := d.NodeMeta(memberlist.MetaMaxSize)
	if len(enc) > memberlist.MetaMaxSize {
		t.Fatalf("meta is %d bytes", len(enc))
	}
	var meta nodeMeta
	if err := json.Unmarshal(enc, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.RaftAddr == "" || meta.FSMOpsVersion != fsmOpsVersion {
		t.Fatalf("decoded meta lost RaftAddr or fv: %+v (%d bytes)", meta, len(enc))
	}
}
