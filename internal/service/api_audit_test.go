package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// apiAuditService is a single-node service whose records land in memory.
func apiAuditService(t *testing.T, cfg config.Config) (*Service, *memSecretAuditSink) {
	t.Helper()
	sink := &memSecretAuditSink{}
	s := &Service{cfg: cfg, cluster: cluster.NewNoop("node-a", "", "")}
	s.secretAudit = sink
	s.secretAuditOnce.Do(func() {})
	return s, sink
}

func tokenCtx() context.Context {
	ctx := controlplane.ContextWithAccess(context.Background(), paymentsToken())
	return auditlog.ContextWithCorrelationID(ctx, "corr-api-1")
}

func TestAPIAuditPolicy(t *testing.T) {
	gated := &gateCluster{Noop: cluster.NewNoop("n1", "", "")}
	cases := []struct {
		name string
		svc  *Service
		want APIAuditPolicy
	}{
		{"nil service records nothing", nil, APIAuditPolicy{}},
		{"default: mutations, digest only, buffered", &Service{}, APIAuditPolicy{Enabled: true}},
		{"off", &Service{cfg: config.Config{AuditAPIRecords: config.AuditAPIRecordsOff}}, APIAuditPolicy{}},
		{"all reads, full argv, durable", &Service{cfg: config.Config{
			AuditAPIRecords: config.AuditAPIRecordsAll, AuditExecCommand: config.AuditExecCommandFull, AuditAPIDurable: true,
		}}, APIAuditPolicy{Enabled: true, AllReads: true, ExecArgv: true, Durable: true}},
		{"cluster gate closed: a member could not verify the records", &Service{cfg: config.Config{EnableCluster: true}, cluster: gated}, APIAuditPolicy{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.svc.APIAuditPolicy(); got != c.want {
				t.Fatalf("policy = %+v, want %+v", got, c.want)
			}
		})
	}
	if (*Service)(nil).APIRecordsConfigured() || (&Service{cfg: config.Config{AuditAPIRecords: "off"}}).APIRecordsConfigured() || !(&Service{}).APIRecordsConfigured() {
		t.Fatal("APIRecordsConfigured is false only for off (and a nil service)")
	}
}

// TestRecordAPICall pins the record shape: the caller from ctx, the route
// pattern as ref, the request block, the sandbox's lifecycle and owner so
// the per-sandbox read finds it, and the request's correlation id.
func TestRecordAPICall(t *testing.T) {
	s, sink := apiAuditService(t, config.Config{})
	s.auditIdentityCache = map[string]auditIdentity{"sb-1": {incarnationID: "inc-1", ownerRef: "team:payments", complete: true}}
	s.RecordAPICall(tokenCtx(), APICall{
		Method: "post", Route: "/v1/sandboxes/{id}/toolbox/{path...}", Status: 200,
		SandboxID: "sb-1", Target: "process/execute", Digest: "abc", Surface: auditlog.SurfaceMCP,
	})
	s.RecordAPICall(tokenCtx(), APICall{Method: "DELETE", Route: "/v1/egress-profiles/{name}", Status: 404, Target: "corp"})
	s.RecordAPICall(tokenCtx(), APICall{Method: "POST", Route: "/v1/templates", Status: 200, Denied: true})
	evs := sink.Events()
	if len(evs) != 3 {
		t.Fatalf("records = %d, want 3", len(evs))
	}
	ev := evs[0]
	if ev.Kind != auditlog.KindAPI || ev.Ref != "POST /v1/sandboxes/{id}/toolbox/{path...}" || ev.Result != auditlog.APIResultOK ||
		ev.SandboxID != "sb-1" || ev.IncarnationID != "inc-1" || ev.OwnerRef != "team:payments" ||
		ev.CorrelationID != "corr-api-1" || ev.Actor != "node-a" || ev.NodeID != "node-a" {
		t.Fatalf("record = %+v", ev)
	}
	if ev.Caller == nil || ev.Caller.ID != "tok_7Hq2" || ev.Caller.Team != "payments" {
		t.Fatalf("caller = %+v", ev.Caller)
	}
	want := auditlog.Request{Method: "POST", Route: "/v1/sandboxes/{id}/toolbox/{path...}", Status: 200, Digest: "abc", Surface: "mcp", Target: "process/execute"}
	if ev.Request == nil || ev.Request.Method != want.Method || ev.Request.Route != want.Route || ev.Request.Status != want.Status ||
		ev.Request.Digest != want.Digest || ev.Request.Surface != want.Surface || ev.Request.Target != want.Target {
		t.Fatalf("request = %+v, want %+v", ev.Request, want)
	}
	if evs[1].Result != auditlog.APIResultError || evs[1].SandboxID != "" || evs[1].Request.Target != "corp" || evs[1].IncarnationID != "" {
		t.Fatalf("non-sandbox record = %+v", evs[1])
	}
	if evs[2].Result != auditlog.APIResultDenied {
		t.Fatalf("denied record result = %q", evs[2].Result)
	}
	if got := expvarMapInt(t, "aerolvm_audit_api_records_total", auditlog.APIResultOK); got < 1 {
		t.Fatalf("records metric = %d", got)
	}

	// A pre-resolved identity (a delete resolves it before the lifecycle
	// ends) wins over the cache.
	s.RecordAPICall(tokenCtx(), APICall{Method: "DELETE", Route: "/v1/sandboxes/{id}", Status: 204, SandboxID: "sb-1", IncarnationID: "inc-old", OwnerRef: "team:payments"})
	if last := sink.Events()[3]; last.IncarnationID != "inc-old" {
		t.Fatalf("pre-resolved identity lost: %+v", last)
	}

	// No correlation id on the context: a fresh one, never empty.
	s.RecordAPICall(controlplane.ContextWithAccess(context.Background(), paymentsToken()), APICall{Method: "POST", Route: "/v1/x", Status: 200})
	if last := sink.Events()[4]; last.CorrelationID == "" {
		t.Fatal("a record without a correlation id")
	}
}

func expvarMapInt(t *testing.T, name, key string) int64 {
	t.Helper()
	m, ok := expvar.Get(name).(*expvar.Map)
	if !ok {
		t.Fatalf("%s is not a map", name)
	}
	v, ok := m.Get(key).(*expvar.Int)
	if !ok {
		return 0
	}
	return v.Value()
}

// TestAPIRecordsRespectTheGate: the kind, the request field and every new
// record are hash-covered and unknown to an older member, so nothing is
// written while the cluster gate is closed, or with records off.
func TestAPIRecordsRespectTheGate(t *testing.T) {
	gated := &gateCluster{Noop: cluster.NewNoop("n1", "", "")}
	s, sink := apiAuditService(t, config.Config{EnableCluster: true})
	s.cluster = gated
	write := func() {
		s.RecordAPICall(tokenCtx(), APICall{Method: "POST", Route: "/v1/sandboxes", Status: 201, SandboxID: "sb-1"})
		s.RecordAuthDenied(context.Background(), "GET", "/v1/sandboxes", "rejected", "203.0.113.9", 1)
		s.RecordSSHSession(context.Background(), "sb-1", "default")
		s.beginSystemAction(withAuditSubsystem(context.Background(), auditSubsystemLifecycle), "sb-1", systemActionAutoStop)(nil)
	}
	write()
	if n := len(sink.Events()); n != 0 {
		t.Fatalf("%d records written behind a closed gate", n)
	}
	gated.open.Store(true)
	write()
	if n := len(sink.Events()); n != 4 {
		t.Fatalf("%d records once the gate opened, want 4", n)
	}

	off, offSink := apiAuditService(t, config.Config{AuditAPIRecords: config.AuditAPIRecordsOff})
	off.RecordAPICall(tokenCtx(), APICall{Method: "POST", Route: "/v1/sandboxes", Status: 201})
	off.RecordAuthDenied(context.Background(), "GET", "/v1/x", "rejected", "1.2.3.4", 1)
	off.RecordSSHSession(context.Background(), "sb-1", "")
	off.beginSystemAction(context.Background(), "sb-1", systemActionAutoStop)(nil)
	var nilSvc *Service
	nilSvc.RecordAPICall(tokenCtx(), APICall{})
	nilSvc.RecordAuthDenied(context.Background(), "", "", "", "", 1)
	nilSvc.RecordSSHSession(context.Background(), "sb", "")
	nilSvc.beginSystemAction(context.Background(), "sb", "x")(nil)
	nilSvc.NoteLocalOwnersChanged()
	if inc, owner := nilSvc.AuditIdentityForSandbox("sb"); inc != "" || owner != "" {
		t.Fatal("nil service resolves nothing")
	}
	if n := len(offSink.Events()); n != 0 {
		t.Fatalf("SB_AUDIT_API_RECORDS=off wrote %d records", n)
	}
}

// TestRecordAuthDenied: a refused credential names no caller (there is
// none), only the source address and how many 401s the record stands for.
func TestRecordAuthDenied(t *testing.T) {
	s, sink := apiAuditService(t, config.Config{})
	s.RecordAuthDenied(context.Background(), "POST", "/v1/sandboxes", "expired", "203.0.113.9", 5)
	ev := sink.Events()[0]
	if ev.Kind != auditlog.KindAuthDenied || ev.Result != auditlog.APIResultDenied || ev.Reason != "expired" ||
		ev.Caller != nil || ev.Dropped != 4 || ev.Request.Source != "203.0.113.9" || ev.Request.Status != 401 || ev.Ref != "POST /v1/sandboxes" {
		t.Fatalf("auth_denied record = %+v (request %+v)", ev, ev.Request)
	}
}

// TestRecordSSHSession is the gateway half of UC-287: one api record, ref
// ssh, attributed to the sandbox key (the create record names the person).
func TestRecordSSHSession(t *testing.T) {
	s, sink := apiAuditService(t, config.Config{})
	s.RecordSSHSession(context.Background(), "sb-ssh", "default")
	evs := sink.Events()
	if len(evs) != 1 {
		t.Fatalf("records = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Kind != auditlog.KindAPI || ev.Ref != auditlog.RefSSH || ev.SandboxID != "sb-ssh" || ev.Result != auditlog.APIResultOK {
		t.Fatalf("ssh record = %+v", ev)
	}
	if ev.Caller == nil || ev.Caller.Kind != "sandbox_key" || ev.Caller.ID != "sb-ssh" {
		t.Fatalf("ssh caller = %+v", ev.Caller)
	}
	if ev.Request.Surface != auditlog.SurfaceSSH || ev.Request.Target != "default" {
		t.Fatalf("ssh request = %+v", ev.Request)
	}
}

// TestRecordSSHSessionOnOwner: the owner writes the record of a session
// another node's gateway bridged to it under the request that opened it, so
// the caller is still the sandbox key, now via the gateway's node.
func TestRecordSSHSessionOnOwner(t *testing.T) {
	s, sink := apiAuditService(t, config.Config{})
	via := controlplane.OperatorAccess()
	via.Via = "edge-1"
	s.RecordSSHSession(controlplane.ContextWithAccess(context.Background(), via), "sb-ssh", "")
	evs := sink.Events()
	if len(evs) != 1 {
		t.Fatalf("records = %d, want 1", len(evs))
	}
	want := &auditlog.Caller{Kind: "sandbox_key", ID: "sb-ssh", Via: "edge-1"}
	if ev := evs[0]; ev.Ref != auditlog.RefSSH || !reflect.DeepEqual(ev.Caller, want) || ev.Request.Target != "" {
		t.Fatalf("ssh record = %+v caller %+v, want caller %+v and no session (a one-shot exec)", ev, ev.Caller, want)
	}
}

// sshRecordGateCluster answers the owner-record gate the way the gossip
// view does during a rolling upgrade.
type sshRecordGateCluster struct {
	*cluster.Noop
	open bool
}

func (c *sshRecordGateCluster) SSHSessionOwnerRecordAllowed() bool { return c.open }

// TestSSHSessionsRecordedByOwner: the gateway leaves a bridged session's
// record to the owner only in cluster mode with the gate open. A single
// node, a cluster client that cannot answer and a closed gate all keep
// the record on the gateway's node.
func TestSSHSessionsRecordedByOwner(t *testing.T) {
	cases := []struct {
		name    string
		cluster bool
		client  cluster.Client
		want    bool
	}{
		{name: "single node bridges nothing", client: &sshRecordGateCluster{Noop: cluster.NewNoop("n1", "", ""), open: true}},
		{name: "cluster client that cannot answer", cluster: true, client: cluster.NewNoop("n1", "", "")},
		{name: "rolling upgrade in progress", cluster: true, client: &sshRecordGateCluster{Noop: cluster.NewNoop("n1", "", "")}},
		{name: "every member honours the marker", cluster: true, client: &sshRecordGateCluster{Noop: cluster.NewNoop("n1", "", ""), open: true}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := apiAuditService(t, config.Config{EnableCluster: tc.cluster})
			s.cluster = tc.client
			if got := s.SSHSessionsRecordedByOwner(); got != tc.want {
				t.Fatalf("SSHSessionsRecordedByOwner = %v, want %v", got, tc.want)
			}
		})
	}
	var nilSvc *Service
	if nilSvc.SSHSessionsRecordedByOwner() {
		t.Fatal("a nil service handed the record away")
	}
}

// fakeDurableSink records which path each event took.
type fakeDurableSink struct {
	memSecretAuditSink
	durable []SecretAuditEvent
	err     error
}

func (f *fakeDurableSink) EmitDurable(ev SecretAuditEvent) error {
	f.durable = append(f.durable, ev)
	return f.err
}

func TestRecordAPICallDurable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		configured  bool
		call        bool
		err         error
		wantDurable int
	}{
		{"durable configured and asked", true, true, nil, 1},
		{"a failed durable write is logged, not retried as buffered", true, true, errors.New("disk full"), 1},
		{"asked but not configured stays buffered", false, true, nil, 0},
		{"configured but not a durable call stays buffered", true, false, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &fakeDurableSink{err: tc.err}
			s := &Service{cfg: config.Config{AuditAPIDurable: tc.configured}, cluster: cluster.NewNoop("n", "", ""), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			s.secretAudit = sink
			s.secretAuditOnce.Do(func() {})
			s.RecordAPICall(tokenCtx(), APICall{Method: "DELETE", Route: "/v1/sandboxes/{id}", Status: 204, SandboxID: "sb", Durable: tc.call})
			if len(sink.durable) != tc.wantDurable || len(sink.durable)+len(sink.Events()) != 1 {
				t.Fatalf("durable %d buffered %d", len(sink.durable), len(sink.Events()))
			}
		})
	}
}

// TestSystemActionRecords: destructive work the daemon does on its own
// names system:<subsystem>, and the record keeps the identity resolved
// before the action ended the lifecycle.
func TestSystemActionRecords(t *testing.T) {
	s, sink := apiAuditService(t, config.Config{})
	s.auditIdentityCache = map[string]auditIdentity{"sb-1": {incarnationID: "inc-1", ownerRef: "team:payments", complete: true}}
	ctx := withAuditSubsystem(context.Background(), auditSubsystemLifecycle)
	done := s.beginSystemAction(ctx, "sb-1", systemActionAutoDelete)
	s.invalidateAuditIdentity("sb-1") // the delete forgets the lifecycle
	done(nil)
	s.beginSystemAction(withAuditSubsystem(context.Background(), auditSubsystemReconcile), "sb-gone", systemActionOrphanReap)(errors.New("runtime refused"))
	evs := sink.Events()
	if len(evs) != 2 {
		t.Fatalf("records = %d", len(evs))
	}
	if ev := evs[0]; ev.Ref != "SYSTEM lifecycle.auto_delete" || ev.Caller.ID != "system:lifecycle" || ev.IncarnationID != "inc-1" || ev.Result != auditlog.APIResultOK {
		t.Fatalf("auto-delete record = %+v caller %+v", ev, ev.Caller)
	}
	if ev := evs[1]; ev.Ref != "SYSTEM reconcile.orphan_delete" || ev.Caller.ID != "system:reconcile" || ev.Result != auditlog.APIResultError || ev.Request.Status != 500 {
		t.Fatalf("orphan record = %+v caller %+v", ev, ev.Caller)
	}
}

// TestLifecycleSweepWritesSystemRecords drives the real sweep: an idle
// sandbox is auto-stopped and an old one auto-deleted, and each leaves a
// record naming system:lifecycle.
func TestLifecycleSweepWritesSystemRecords(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	sink := &memSecretAuditSink{}
	svc.secretAudit = sink
	svc.secretAuditOnce.Do(func() {})
	old := time.Now().UTC().Add(-2 * time.Minute)
	stop := seedSandbox(t, st, "sb-idle-stop", models.SandboxStatusStarted, 1, 512)
	stop.Lifecycle = models.Lifecycle{StopIfIdleFor: time.Minute}
	stop.LastActiveAt = old
	del := seedSandbox(t, st, "sb-idle-delete", models.SandboxStatusStarted, 1, 512)
	del.Lifecycle = models.Lifecycle{DestroyIfIdleFor: time.Minute}
	del.LastActiveAt = old
	for _, sb := range []*models.Sandbox{stop, del} {
		if err := st.Upsert(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	svc.runLifecycleSweep(withAuditSubsystem(ctx, auditSubsystemLifecycle))
	got := map[string]SecretAuditEvent{}
	for _, ev := range sink.Events() {
		if ev.Kind == auditlog.KindAPI {
			got[ev.SandboxID] = ev
		}
	}
	if ev, ok := got["sb-idle-stop"]; !ok || ev.Ref != "SYSTEM lifecycle.auto_stop" || ev.Caller.ID != "system:lifecycle" {
		t.Fatalf("auto-stop record = %+v (all %+v)", ev, sink.Events())
	}
	if ev, ok := got["sb-idle-delete"]; !ok || ev.Ref != "SYSTEM lifecycle.auto_delete" || ev.IncarnationID != "inc-sb-idle-delete" {
		t.Fatalf("auto-delete record = %+v", ev)
	}
}

// ownerStoreService is a service over a real store, for the shared-node
// rule, which counts owners among the node's sandboxes.
func ownerStoreService(t *testing.T, mode string) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := &Service{cfg: config.Config{AuditAPIFloodControl: mode}, store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cluster: cluster.NewNoop("node-a", "", "")}
	return s, st
}

func seedOwned(t *testing.T, st *store.Store, id, owner string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{ID: id, Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: owner, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
}

// TestAPIFloodModeSharedNode is UC-289's unit half: a coalesce node alone
// with one customer merges and never caps; once a second owner has a
// sandbox there it runs as both, the switch is a chain record, and the
// gauge says so.
func TestAPIFloodModeSharedNode(t *testing.T) {
	ctx := context.Background()
	s, st := ownerStoreService(t, config.AuditAPIFloodCoalesce)
	sink := &memSecretAuditSink{}
	s.secretAudit = sink
	s.secretAuditOnce.Do(func() {})
	fc := s.newAPIFloodControlFor()
	if fc.currentMode() != apiFloodBoth {
		t.Fatalf("a coalesce node starts as %s, want both until it knows it is alone", fc.currentMode())
	}
	seedOwned(t, st, "sb-a1", "team:a")
	seedOwned(t, st, "sb-a2", "team:a")
	s.reevaluateAPIFloodMode(ctx)
	if fc.currentMode() != apiFloodCoalesce {
		t.Fatalf("one owner: effective %s, want coalesce", fc.currentMode())
	}
	s.reevaluateAPIFloodMode(ctx) // unchanged: no second record
	seedOwned(t, st, "sb-b1", "team:b")
	s.reevaluateAPIFloodMode(ctx)
	if fc.currentMode() != apiFloodBoth {
		t.Fatalf("two owners: effective %s, want both", fc.currentMode())
	}
	var modes []SecretAuditEvent
	for _, ev := range sink.Events() {
		if ev.Kind == auditlog.KindAPIFloodMode {
			modes = append(modes, ev)
		}
	}
	if len(modes) != 2 {
		t.Fatalf("mode records = %+v, want two (coalesce, then both)", modes)
	}
	if modes[0].Ref != "coalesce:coalesce" || modes[0].Reason != "single_owner" || modes[1].Ref != "coalesce:both" || modes[1].Reason != "shared_node" {
		t.Fatalf("mode records = %+v", modes)
	}
	if modes[1].Caller == nil || modes[1].Caller.ID != "system:audit" {
		t.Fatalf("mode change caller = %+v", modes[1].Caller)
	}
	inner, _ := expvar.Get("aerolvm_audit_api_flood_mode").(*expvar.Map).Get("coalesce").(*expvar.Map)
	if inner == nil || inner.Get("both").String() != "1" || inner.Get("coalesce").String() != "0" {
		t.Fatalf("flood mode gauge = %v", inner)
	}
	// Back to one owner: coalesce again, recorded.
	if err := st.Delete(ctx, "sb-b1"); err != nil {
		t.Fatal(err)
	}
	s.reevaluateAPIFloodMode(ctx)
	if fc.currentMode() != apiFloodCoalesce {
		t.Fatal("the node did not return to coalesce when it became single-owner again")
	}

	// A budget node never changes mode and starts no evaluator.
	b, _ := ownerStoreService(t, "")
	b.secretAudit = &memSecretAuditSink{}
	b.secretAuditOnce.Do(func() {})
	if b.newAPIFloodControlFor().currentMode() != apiFloodBudget {
		t.Fatal("default mode is budget")
	}
	b.startAPIFloodEvaluator()
	if b.apiFlood.nudge.Load() != nil {
		t.Fatal("a budget node started the shared-node evaluator")
	}
	b.stopAPIFloodEvaluator()
}

// TestAPIFloodEvaluatorNudge: a create's nudge reaches the evaluator, which
// re-counts owners off the request path; stop is idempotent.
func TestAPIFloodEvaluatorNudge(t *testing.T) {
	s, st := ownerStoreService(t, config.AuditAPIFloodCoalesce)
	s.secretAudit = &memSecretAuditSink{}
	s.secretAuditOnce.Do(func() {})
	fc := s.newAPIFloodControlFor()
	seedOwned(t, st, "sb-a", "")
	s.startAPIFloodEvaluator()
	waitFloodMode(t, fc, apiFloodCoalesce)
	seedOwned(t, st, "sb-b", "team:b")
	s.NoteLocalOwnersChanged()
	s.NoteLocalOwnersChanged() // a pending nudge absorbs the second
	waitFloodMode(t, fc, apiFloodBoth)
	s.stopAPIFloodEvaluator()
	s.stopAPIFloodEvaluator()

	// A store error keeps the current mode.
	_ = st.Close()
	s.reevaluateAPIFloodMode(context.Background())
	if fc.currentMode() != apiFloodBoth {
		t.Fatal("a failed owner count changed the mode")
	}
	(&Service{}).reevaluateAPIFloodMode(context.Background()) // no store: nothing to count
	(&Service{}).applyAPIFloodMode(context.Background(), apiFloodBoth, 2)
}

func waitFloodMode(t *testing.T, fc *apiFloodControl, want apiFloodMode) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for fc.currentMode() != want {
		if time.Now().After(deadline) {
			t.Fatalf("effective mode %s, want %s", fc.currentMode(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFileSinkAppliesAPIFlood is the writer funnel end to end: a flood on
// one sandbox under the default budget is written up to the burst and
// summarised in one rate_limited record, a durable delete is never charged,
// and the file still verifies.
func TestFileSinkAppliesAPIFlood(t *testing.T) {
	dir := t.TempDir()
	fc := newAPIFloodControl(apiFloodBudget, 1, 5, 5*time.Second)
	clk := newFloodClock()
	fc.now = clk.now
	sink, err := newFileAuditSinkFrom(dir, fileAuditSinkOptions{apiFlood: fc})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		ev := apiCall("sb-1", "tok_flood", execRoute, string(rune('a'+i%26))+strings.Repeat("x", i), 200)
		ev.Time = time.Now().UTC()
		sink.Emit(ev)
	}
	del := apiCall("sb-1", "tok_flood", "/v1/sandboxes/{id}", "", 204)
	del.Time = time.Now().UTC()
	if err := sink.EmitDurable(del); err != nil {
		t.Fatalf("durable delete: %v", err)
	}
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	clk.advance(6 * time.Second)
	sink.Close()

	f, err := os.Open(filepath.Join(dir, secretAuditFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var kept, markers int
	var dropped int64
	sawDelete := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var ev SecretAuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		switch {
		case ev.Reason == auditlog.ReasonRateLimited:
			markers++
			dropped += ev.Dropped
		case ev.Request != nil && ev.Request.Route == "/v1/sandboxes/{id}":
			sawDelete = true
		case ev.Kind == auditlog.KindAPI:
			kept++
		}
	}
	if kept != 5 || markers != 1 || dropped != 45 || !sawDelete {
		t.Fatalf("kept %d, markers %d (dropped %d), delete written %v; want 5 kept, one marker for 45, the durable delete", kept, markers, dropped, sawDelete)
	}
	if _, err := scanSecretAuditChain(filepath.Join(dir, secretAuditFileName)); err != nil {
		t.Fatalf("chain no longer verifies: %v", err)
	}
}

// TestNoteSandboxCreated: a create's new id reaches the edge's record, and
// the flood evaluator hears about a possible new owner.
func TestNoteSandboxCreated(t *testing.T) {
	s := &Service{}
	ctx, st := auditlog.ContextWithCallState(context.Background())
	s.noteSandboxCreated(ctx, nil)
	if st.SandboxID() != "" {
		t.Fatal("a failed create must not name a sandbox")
	}
	s.noteSandboxCreated(ctx, &models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-new", AuditIncarnationID: "inc-new", OwnerRef: "team:payments"}})
	if id, inc, owner := st.SandboxIdentity(); id != "sb-new" || inc != "inc-new" || owner != "team:payments" {
		t.Fatalf("noted %q %q %q: the create record needs the id and its identity, with no lookup", id, inc, owner)
	}
}

func TestAPIAuditConcurrentRecords(t *testing.T) {
	s, sink := apiAuditService(t, config.Config{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.RecordAPICall(tokenCtx(), APICall{Method: "POST", Route: "/v1/sandboxes/{id}/stop", Status: 200, SandboxID: "sb-1"})
		}()
	}
	wg.Wait()
	if n := len(sink.Events()); n != 16 {
		t.Fatalf("records = %d", n)
	}
}

// TestListSecretAuditCallerFilter is the §5.10 per-sandbox caller filter:
// GET /v1/sandboxes/{id}/audit?kind=api&caller=<id> keeps the caller's
// records, by id or display name, from this node and from peers (a peer
// that ignores the filter is filtered again here), and never hides a gap.
func TestListSecretAuditCallerFilter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ana := controlplane.Access{Fleet: true, Role: controlplane.RoleAdmin, Principal: controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1", Name: "ana@acme.com"}}
	peerEvents := []cluster.AuditEventDTO{
		{Time: time.Unix(5, 0).UTC(), SandboxID: "sb-1", Kind: auditlog.KindAPI, Result: auditlog.APIResultOK, EventID: "peer-ana", NodeID: "node-b", Caller: &auditlog.Caller{Kind: "oidc", ID: "oidc:okta:00u1", Name: "ana@acme.com"}},
		{Time: time.Unix(6, 0).UTC(), SandboxID: "sb-1", Kind: auditlog.KindAPI, Result: auditlog.APIResultOK, EventID: "peer-ci", NodeID: "node-b", Caller: &auditlog.Caller{Kind: "token", ID: "tok_7Hq2"}},
	}
	s := &Service{
		cfg:   config.Config{DBPath: dbPath},
		store: st,
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("node-a", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "node-a", APIURL: "http://self", Alive: true},
				{NodeID: "node-b", InternalURL: "https://peer-b.example", Alive: true},
			},
			acl:       cluster.AuditACL{SandboxID: "sb-1", AuditNodeIDs: []string{"node-a", "node-b"}},
			aclExists: true,
		},
		testAuditFetcher: &fakeAuditFetcher{pages: map[string]cluster.AuditPeerPage{"node-b": {Events: peerEvents}}},
	}
	t.Cleanup(s.CloseSecretAuditSink)
	s.RecordAPICall(tokenCtx(), APICall{Method: "POST", Route: "/v1/sandboxes/{id}/stop", Status: 200, SandboxID: "sb-1"})
	s.RecordAPICall(controlplane.ContextWithAccess(context.Background(), ana), APICall{Method: "POST", Route: "/v1/sandboxes/{id}/start", Status: 200, SandboxID: "sb-1"})
	s.secretAuditSink().Emit(SecretAuditEvent{Time: time.Now().UTC(), Kind: secretAuditKindGap, Result: secretAuditResultGap, Reason: secretAuditReasonOverflow, Dropped: 2})
	if err := s.secretAuditFile.Sync(); err != nil {
		t.Fatal(err)
	}

	local, _, err := s.ListSecretAuditLocal(context.Background(), "sb-1", SecretAuditQuery{Kind: auditlog.KindAPI, Caller: "tok_7Hq2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(local) != 2 || local[0].Caller.ID != "tok_7Hq2" || local[1].Kind != secretAuditKindGap {
		t.Fatalf("local caller page = %+v, want the token's record and the gap", local)
	}
	page, err := s.ListSecretAudit(context.Background(), "sb-1", SecretAuditQuery{Kind: auditlog.KindAPI, Caller: "ANA@acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, ev := range page.Events {
		if ev.Kind == secretAuditKindGap {
			continue
		}
		if ev.Caller == nil || ev.Caller.ID != "oidc:okta:00u1" {
			t.Fatalf("another caller's record passed the filter: %+v", ev)
		}
		ids = append(ids, ev.EventID)
	}
	if len(ids) != 2 || !strings.Contains(strings.Join(ids, ","), "peer-ana") {
		t.Fatalf("fan-out caller page = %v, want ana's local record and peer-ana", ids)
	}
	if !secretAuditCallerMatches(SecretAuditEvent{Kind: "x"}, "") {
		t.Fatal("an empty filter matches everything")
	}
}
