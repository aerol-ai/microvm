package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeAuditFetcher struct {
	pages map[string]cluster.AuditPeerPage
	errs  map[string]error
}

type boundedAuditFetcher struct {
	active atomic.Int32
	max    atomic.Int32
	delay  time.Duration
}

func (f *boundedAuditFetcher) FetchSandboxAuditFromPeer(ctx context.Context, _ string, _ string, _ int, _, _ string) (cluster.AuditPeerPage, error) {
	active := f.active.Add(1)
	defer f.active.Add(-1)
	for observed := f.max.Load(); active > observed && !f.max.CompareAndSwap(observed, active); observed = f.max.Load() {
	}
	timer := time.NewTimer(f.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return cluster.AuditPeerPage{}, ctx.Err()
	case <-timer.C:
		return cluster.AuditPeerPage{}, nil
	}
}

func (f *fakeAuditFetcher) FetchSandboxAuditFromPeer(_ context.Context, apiURL, _ string, _ int, _, _ string) (cluster.AuditPeerPage, error) {
	if err, ok := f.errs[apiURL]; ok {
		return cluster.AuditPeerPage{}, err
	}
	if page, ok := f.pages[apiURL]; ok {
		return page, nil
	}
	return cluster.AuditPeerPage{}, fmt.Errorf("unexpected peer %s", apiURL)
}

type stubMembersCluster struct {
	*cluster.Noop
	members   []cluster.Member
	placement cluster.Placement
	acl       cluster.AuditACL
	aclExists bool
}

func (s *stubMembersCluster) Members() []cluster.Member      { return s.members }
func (s *stubMembersCluster) LocalMembers() []cluster.Member { return s.Members() }
func (s *stubMembersCluster) PlacementOf(string) (cluster.Placement, bool) {
	return s.placement, s.placement.SandboxID != ""
}
func (s *stubMembersCluster) AuditACLForSandbox(context.Context, string) (cluster.AuditACL, bool, error) {
	return s.acl, s.aclExists, nil
}

func TestListSecretAuditLocalReturnsWrittenEvents(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	s := &Service{
		cfg:         config.Config{DBPath: dbPath, SecretAuditRetentionDays: 30},
		store:       st,
		cluster:     cluster.NewNoop("node-a", "http://a", ""),
		secretAudit: nil,
	}
	t.Cleanup(s.CloseSecretAuditSink)

	sink := s.secretAuditSink()
	emitSecretAudit(sink, "sb-1", "env:sb-1", "node-a", "corr-1", "", nil)
	emitSecretAudit(sink, "sb-other", "env:sb-other", "node-a", "corr-x", "", nil)
	if f, ok := sink.(*fileAuditSink); ok {
		f.Sync()
	}

	events, next, err := s.ListSecretAuditLocal(context.Background(), "sb-1", SecretAuditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListSecretAuditLocal: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1: %+v", len(events), events)
	}
	if events[0].SandboxID != "sb-1" || events[0].CorrelationID != "corr-1" || events[0].NodeID != "node-a" {
		t.Fatalf("event = %+v", events[0])
	}
	if next != "" {
		t.Fatalf("nextCursor = %q, want empty", next)
	}
}

func TestListSecretAuditLocalPaginatesOutOfOrderInput(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := &Service{cfg: config.Config{DBPath: dbPath}, store: st}
	t.Cleanup(s.CloseSecretAuditSink)
	sink := s.secretAuditSink().(*fileAuditSink)
	base := time.Unix(1_800_000_000, 0).UTC()
	for i := 49; i >= 0; i-- {
		sink.Emit(SecretAuditEvent{
			Time:          base.Add(time.Duration(i) * time.Second),
			SandboxID:     "sb-page",
			EventID:       fmt.Sprintf("event-%02d", i),
			CorrelationID: fmt.Sprintf("corr-%02d", i),
			Result:        secretAuditResultSuccess,
			Reason:        secretAuditReasonOK,
		})
	}
	sink.Sync()

	first, cursor, err := s.ListSecretAuditLocal(context.Background(), "sb-page", SecretAuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first) != 10 || first[0].EventID != "event-00" || first[9].EventID != "event-09" || cursor == "" {
		t.Fatalf("first page = %+v, cursor=%q", first, cursor)
	}
	second, next, err := s.ListSecretAuditLocal(context.Background(), "sb-page", SecretAuditQuery{Limit: 10, Cursor: cursor})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second) != 10 || second[0].EventID != "event-10" || second[9].EventID != "event-19" || next == "" {
		t.Fatalf("second page = %+v, cursor=%q", second, next)
	}
}

func TestListSecretAuditFanoutMergeCoveragePartial(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	peerURL := "http://peer-b.example"
	noop := cluster.NewNoop("node-a", "http://self", "")
	s := &Service{
		cfg:   config.Config{DBPath: dbPath},
		store: st,
		cluster: &stubMembersCluster{Noop: noop, members: []cluster.Member{
			{NodeID: "node-a", APIURL: "http://self", Alive: true},
			{NodeID: "node-b", APIURL: peerURL, Alive: true},
			{NodeID: "node-c", APIURL: "http://dead.invalid", Alive: true},
		}},
		testAuditFetcher: &fakeAuditFetcher{
			pages: map[string]cluster.AuditPeerPage{
				peerURL: {Events: []cluster.AuditEventDTO{{
					Time: time.Unix(2, 0).UTC(), Actor: "node-b", SandboxID: "sb-1",
					Ref: "env:sb-1", Result: secretAuditResultSuccess, CorrelationID: "peer-corr", NodeID: "node-b",
				}}},
			},
			errs: map[string]error{
				"http://dead.invalid": errors.New("dial timeout"),
			},
		},
	}
	t.Cleanup(s.CloseSecretAuditSink)

	emitSecretAudit(s.secretAuditSink(), "sb-1", "env:sb-1", "node-a", "local-corr", "", nil)
	if f := s.secretAuditFile; f != nil {
		f.Sync()
	}

	page, err := s.ListSecretAudit(context.Background(), "sb-1", SecretAuditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if !page.Coverage.Partial {
		t.Fatalf("expected partial coverage: %+v", page.Coverage)
	}
	if len(page.Coverage.Missing) != 1 || page.Coverage.Missing[0] != "node-c" {
		t.Fatalf("missing = %v, want [node-c]", page.Coverage.Missing)
	}
	if len(page.Events) < 2 {
		t.Fatalf("events = %d, want >= 2: %+v", len(page.Events), page.Events)
	}
}

func TestListSecretAuditAfterDeleteTargetsRetainedOwnerHistory(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	noop := cluster.NewNoop("node-self", "http://self", "")
	s := &Service{
		cfg:   config.Config{DBPath: dbPath},
		store: st,
		cluster: &stubMembersCluster{
			Noop: noop,
			members: []cluster.Member{
				{NodeID: "node-self", APIURL: "http://self", Alive: true},
				{NodeID: "node-old", APIURL: "http://old", Alive: true},
				{NodeID: "node-current", APIURL: "http://current", Alive: true},
				{NodeID: "node-unrelated", APIURL: "http://unrelated", Alive: true},
			},
			acl: cluster.AuditACL{
				SandboxID:    "sb-deleted",
				OwnerRef:     "tenant-a",
				AuditNodeIDs: []string{"node-old", "node-current"},
			},
			aclExists: true,
		},
		testAuditFetcher: &fakeAuditFetcher{pages: map[string]cluster.AuditPeerPage{
			"http://old":     {Events: []cluster.AuditEventDTO{{Time: time.Unix(1, 0), SandboxID: "sb-deleted", EventID: "old"}}},
			"http://current": {Events: []cluster.AuditEventDTO{{Time: time.Unix(2, 0), SandboxID: "sb-deleted", EventID: "current"}}},
		}},
	}
	t.Cleanup(s.CloseSecretAuditSink)

	page, err := s.ListSecretAudit(context.Background(), "sb-deleted", SecretAuditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if page.Coverage.Partial || len(page.Coverage.Missing) != 0 {
		t.Fatalf("coverage = %+v, unrelated worker must not be queried", page.Coverage)
	}
	if len(page.Events) != 2 {
		t.Fatalf("events = %+v, want retained history from both prior owners", page.Events)
	}
}

func TestListSecretAuditTruncatedHistoryFallsBackToAllWorkers(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	noop := cluster.NewNoop("node-self", "http://self", "")
	s := &Service{
		cfg:   config.Config{DBPath: dbPath},
		store: st,
		cluster: &stubMembersCluster{
			Noop: noop,
			members: []cluster.Member{
				{NodeID: "node-self", APIURL: "http://self", Alive: true},
				{NodeID: "node-a", APIURL: "http://a", Alive: true},
				{NodeID: "node-b", APIURL: "http://b", Alive: true},
			},
			acl: cluster.AuditACL{
				SandboxID:           "sb-truncated",
				AuditNodeIDs:        []string{"node-a"},
				AuditNodesTruncated: true,
			},
			aclExists: true,
		},
		testAuditFetcher: &fakeAuditFetcher{pages: map[string]cluster.AuditPeerPage{
			"http://a": {},
			"http://b": {},
		}},
	}
	t.Cleanup(s.CloseSecretAuditSink)

	page, err := s.ListSecretAudit(context.Background(), "sb-truncated", SecretAuditQuery{})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if page.Coverage.Partial || len(page.Coverage.Answered) != 3 {
		t.Fatalf("coverage = %+v, truncated history must query every worker", page.Coverage)
	}
}

func TestListSecretAuditFanoutHasBoundedWorkersAndCompleteCoverage(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const peerCount = 200
	members := make([]cluster.Member, 0, peerCount+1)
	members = append(members, cluster.Member{NodeID: "self", APIURL: "http://self", Alive: true})
	for i := range peerCount {
		members = append(members, cluster.Member{
			NodeID: fmt.Sprintf("worker-%03d", i),
			APIURL: fmt.Sprintf("http://worker-%03d", i),
			Alive:  true,
		})
	}
	fetcher := &boundedAuditFetcher{delay: 2 * time.Millisecond}
	s := &Service{
		cfg:              config.Config{DBPath: dbPath},
		store:            st,
		cluster:          &stubMembersCluster{Noop: cluster.NewNoop("self", "http://self", ""), members: members},
		testAuditFetcher: fetcher,
	}
	t.Cleanup(s.CloseSecretAuditSink)

	page, err := s.ListSecretAudit(context.Background(), "sb-scale", SecretAuditQuery{})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if page.Coverage.Partial || len(page.Coverage.Answered) != peerCount+1 {
		t.Fatalf("coverage = %+v, want all peers plus self", page.Coverage)
	}
	if got := fetcher.max.Load(); got > secretAuditFanoutParallel {
		t.Fatalf("max concurrent fetches = %d, limit = %d", got, secretAuditFanoutParallel)
	}
}

func TestListSecretAuditDeadlineMarksUnscheduledPeersMissing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const peerCount = 100
	members := make([]cluster.Member, 0, peerCount+1)
	members = append(members, cluster.Member{NodeID: "self", APIURL: "http://self", Alive: true})
	for i := range peerCount {
		members = append(members, cluster.Member{
			NodeID: fmt.Sprintf("worker-%03d", i),
			APIURL: fmt.Sprintf("http://worker-%03d", i),
			Alive:  true,
		})
	}
	s := &Service{
		cfg:              config.Config{DBPath: dbPath},
		store:            st,
		cluster:          &stubMembersCluster{Noop: cluster.NewNoop("self", "http://self", ""), members: members},
		testAuditFetcher: &boundedAuditFetcher{delay: time.Second},
	}
	t.Cleanup(s.CloseSecretAuditSink)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	page, err := s.ListSecretAudit(ctx, "sb-timeout", SecretAuditQuery{})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if !page.Coverage.Partial || len(page.Coverage.Missing) != peerCount {
		t.Fatalf("coverage = %+v, every unanswered peer must be explicit", page.Coverage)
	}
}

func TestEmitSecretAuditCorrelationIDPresent(t *testing.T) {
	mem := &memSecretAuditSink{}
	emitSecretAudit(mem, "sb", "ref", "node-a", "explicit-id", "", nil)
	evs := mem.Events()
	if len(evs) != 1 || evs[0].CorrelationID != "explicit-id" || evs[0].NodeID != "node-a" {
		t.Fatalf("event = %+v", evs)
	}
	emitSecretAudit(mem, "sb", "ref", "node-a", "", "", nil)
	evs = mem.Events()
	if len(evs) != 2 || evs[1].CorrelationID == "" {
		t.Fatalf("auto correlation missing: %+v", evs[1])
	}
}

func TestPruneSecretAuditDropsOldLines(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	s := &Service{
		cfg:     config.Config{DBPath: dbPath, SecretAuditRetentionDays: 1},
		store:   st,
		cluster: cluster.NewNoop("node-a", "", ""),
	}
	t.Cleanup(s.CloseSecretAuditSink)

	sink := s.secretAuditSink().(*fileAuditSink)
	old := SecretAuditEvent{
		Time: time.Now().UTC().Add(-48 * time.Hour), SandboxID: "sb-1",
		Ref: "env:sb-1", Result: secretAuditResultSuccess, Reason: secretAuditReasonOK,
		CorrelationID: "old", Actor: "node-a", NodeID: "node-a",
	}
	fresh := SecretAuditEvent{
		Time: time.Now().UTC(), SandboxID: "sb-1",
		Ref: "env:sb-1", Result: secretAuditResultSuccess, Reason: secretAuditReasonOK,
		CorrelationID: "new", Actor: "node-a", NodeID: "node-a",
	}
	sink.Emit(old)
	sink.Emit(fresh)
	sink.Sync()

	if err := s.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("PruneSecretAudit: %v", err)
	}
	events, _, err := s.ListSecretAuditLocal(context.Background(), "sb-1", SecretAuditQuery{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 || events[0].CorrelationID != "new" {
		t.Fatalf("after prune: %+v", events)
	}
	raw, _ := os.ReadFile(sink.path)
	if len(raw) == 0 {
		t.Fatal("expected rewritten file")
	}
}

func TestListSecretAuditRequiresSandboxLocallyForOwnerScope(t *testing.T) {
	// Smoke: create sandbox then audit — used by handler tests too.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := &Service{cfg: config.Config{DBPath: dbPath}, store: st, cluster: cluster.NewNoop("n", "", "")}
	t.Cleanup(s.CloseSecretAuditSink)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-own", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker, OwnerRef: "acme",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	page, err := s.ListSecretAudit(context.Background(), "sb-own", SecretAuditQuery{})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if page.Coverage.Partial {
		t.Fatalf("single-node should not be partial: %+v", page.Coverage)
	}
}
