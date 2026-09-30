package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type cov96aExporter struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (e *cov96aExporter) ExportEvents(context.Context, controlplane.AuditEventBatch) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return "", e.err
}

type cov96aWitness struct {
	mu      sync.Mutex
	head    string
	ok      bool
	shipErr error
}

func (w *cov96aWitness) WitnessHeads(_ context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.shipErr != nil {
		return controlplane.WitnessReceipt{}, w.shipErr
	}
	if len(heads) > 0 {
		w.head, w.ok = heads[len(heads)-1].HeadHex, true
	}
	return controlplane.WitnessReceipt{ReceiptID: "r-cov96a"}, nil
}

func (w *cov96aWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, w.ok, nil
}

// cov96aFileSink is a sink over path with only the lock sidecar set; the
// Service paths under test open the file themselves.
func cov96aFileSink(t *testing.T, data []byte) *fileAuditSink {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	if data != nil {
		cov96aWrite(t, path, data)
	}
	return &fileAuditSink{path: path, lockPath: filepath.Join(dir, auditlog.LockFileName)}
}

func cov96aBlockDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestCov96AuditExportBatchOnce(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	svcFor := func(sink *fileAuditSink, ex *cov96aExporter) *Service {
		return &Service{secretAudit: sink, secretAuditFile: sink, auditExporter: ex, logger: slog.New(slog.DiscardHandler)}
	}
	cursorPath := func(sink *fileAuditSink) string {
		return filepath.Join(filepath.Dir(sink.path), secretAuditExportOffset)
	}

	t.Run("missing file", func(t *testing.T) {
		sink := cov96aFileSink(t, nil)
		if n, err := svcFor(sink, &cov96aExporter{}).exportSecretAuditBatchOnce(ctx); err != nil || n != 0 {
			t.Fatalf("missing file = %d, %v", n, err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		sink := &fileAuditSink{path: dir, lockPath: filepath.Join(t.TempDir(), "lock")}
		if _, err := svcFor(sink, &cov96aExporter{}).exportSecretAuditBatchOnce(ctx); err == nil {
			t.Fatal("directory exported")
		}
	})

	t.Run("stale cursor, blank line, cluster node id", func(t *testing.T) {
		lines := cov96aChain(t, cov96aOpen("sb-exp", now), cov96aOpen("sb-exp", now.Add(time.Second)))
		data := append(append(append([]byte{}, lines[0]...), '\n', '\n'), append(lines[1], '\n')...)
		sink := cov96aFileSink(t, data)
		f, err := os.Open(sink.path)
		if err != nil {
			t.Fatal(err)
		}
		gen, err := auditFileGeneration(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := persistAuditExportCursor(cursorPath(sink), auditExportCursor{Generation: gen, Offset: 1 << 30, Head: "h"}); err != nil {
			t.Fatal(err)
		}
		svc := svcFor(sink, &cov96aExporter{})
		svc.cluster = cluster.NewNoop("node-cov96a", "", "")
		if n, err := svc.exportSecretAuditBatchOnce(ctx); err != nil || n != 2 {
			t.Fatalf("export = %d, %v", n, err)
		}
		if got := loadAuditExportCursor(cursorPath(sink)); got.Offset != int64(len(data)) {
			t.Fatalf("cursor = %+v, want offset %d", got, len(data))
		}
	})

	t.Run("record past the scanner buffer", func(t *testing.T) {
		data := cov96aJoin(cov96aChain(t, cov96aOpen("sb-exp", now))...)
		data = append(append(data, cov96aBig(1024*1024+64)...), '\n')
		sink := cov96aFileSink(t, data)
		if _, err := svcFor(sink, &cov96aExporter{}).exportSecretAuditBatchOnce(ctx); err == nil {
			t.Fatal("oversized record exported")
		}
	})

	t.Run("receiver fails", func(t *testing.T) {
		sink := cov96aFileSink(t, cov96aJoin(cov96aChain(t, cov96aOpen("sb-exp", now))...))
		svc := svcFor(sink, &cov96aExporter{err: errors.New("receiver down")})
		if _, err := svc.exportSecretAuditBatchOnce(ctx); err == nil {
			t.Fatal("receiver failure swallowed")
		}
		if svc.auditExportNotBefore.IsZero() {
			t.Fatal("no backoff after a receiver failure")
		}
	})

	t.Run("cursor cannot be persisted", func(t *testing.T) {
		sink := cov96aFileSink(t, cov96aJoin(cov96aChain(t, cov96aOpen("sb-exp", now))...))
		cov96aBlockDir(t, cursorPath(sink))
		ex := &cov96aExporter{}
		if _, err := svcFor(sink, ex).exportSecretAuditBatchOnce(ctx); err == nil {
			t.Fatal("cursor persist failure swallowed")
		}
		if ex.calls != 1 {
			t.Fatalf("exporter calls = %d, want 1", ex.calls)
		}
	})
}

func TestCov96AuditShipWitnessHead(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).shipSecretAuditHeadNow(ctx); err != nil {
		t.Fatalf("nil service = %v", err)
	}
	if err := (&Service{}).shipSecretAuditHeadNow(ctx); err != nil {
		t.Fatalf("no audit file = %v", err)
	}

	// closedSvc marks the manual sink closed so Sync is a no-op and no writer
	// goroutine is needed.
	closedSvc := func(t *testing.T, w controlplane.Witness) (*Service, *fileAuditSink) {
		t.Helper()
		sink := cov96aManualSink(t)
		if err := sink.writeEventBatch([]SecretAuditEvent{cov96aOpen("sb-wit", time.Time{})}, true, false); err != nil {
			t.Fatal(err)
		}
		sink.closed.Store(true)
		return &Service{secretAudit: sink, secretAuditFile: sink, auditWitness: w, logger: slog.New(slog.DiscardHandler)}, sink
	}

	t.Run("sync fails", func(t *testing.T) {
		sink := cov96aManualSink(t)
		if err := sink.writeEventBatch([]SecretAuditEvent{cov96aOpen("sb-wit", time.Time{})}, true, false); err != nil {
			t.Fatal(err)
		}
		blocker := filepath.Join(t.TempDir(), "blocker")
		cov96aWrite(t, blocker, []byte("x"))
		sink.tipPath = filepath.Join(blocker, "secrets.tip")
		go sink.loop()
		t.Cleanup(sink.Close)
		svc := &Service{secretAudit: sink, secretAuditFile: sink, auditWitness: &cov96aWitness{}, logger: slog.New(slog.DiscardHandler)}
		if err := svc.shipSecretAuditHeadNow(ctx); err == nil {
			t.Fatal("sync failure swallowed")
		}
	})

	t.Run("confirmed with a nil context", func(t *testing.T) {
		w := &cov96aWitness{}
		svc, sink := closedSvc(t, w)
		head, eventID := sink.chainTip()
		w.head, w.ok = head, true
		if err := persistWitnessReceipt("", svc.secretAuditWitnessTipPath(), witnessReceiptRecord{HeadHex: head, EventID: eventID}); err != nil {
			t.Fatal(err)
		}
		var nilCtx context.Context
		if err := svc.shipSecretAuditHeadNow(nilCtx); err != nil {
			t.Fatalf("confirmed head = %v", err)
		}
	})

	t.Run("witness rejects", func(t *testing.T) {
		svc, _ := closedSvc(t, &cov96aWitness{shipErr: errors.New("witness down")})
		if err := svc.shipSecretAuditHeadNow(ctx); err == nil {
			t.Fatal("witness failure swallowed")
		}
	})

	t.Run("receipt cannot be persisted", func(t *testing.T) {
		svc, _ := closedSvc(t, &cov96aWitness{})
		cov96aBlockDir(t, svc.secretAuditWitnessTipPath())
		if err := svc.shipSecretAuditHeadNow(ctx); err == nil {
			t.Fatal("receipt persist failure swallowed")
		}
	})
}

func TestCov96AuditVerifyChain(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	svcFor := func(sink *fileAuditSink) *Service {
		return &Service{secretAudit: sink, secretAuditFile: sink}
	}

	t.Run("missing file", func(t *testing.T) {
		rep, err := svcFor(cov96aFileSink(t, nil)).VerifySecretAuditChain(ctx)
		if err != nil || !rep.OK || !rep.WriterTipMatches {
			t.Fatalf("missing file = %+v, %v", rep, err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		sink := &fileAuditSink{path: t.TempDir(), lockPath: filepath.Join(t.TempDir(), "lock")}
		if _, err := svcFor(sink).VerifySecretAuditChain(ctx); err == nil {
			t.Fatal("directory verified")
		}
	})

	t.Run("unterminated tail", func(t *testing.T) {
		data := append(cov96aJoin(cov96aChain(t, cov96aOpen("sb-v", now))...), []byte(`{"torn":`)...)
		rep, err := svcFor(cov96aFileSink(t, data)).VerifySecretAuditChain(ctx)
		if err != nil || rep.OK || rep.Error == "" {
			t.Fatalf("torn tail = %+v, %v", rep, err)
		}
	})

	t.Run("writer tip drift", func(t *testing.T) {
		sink := cov96aFileSink(t, cov96aJoin(cov96aChain(t, cov96aOpen("sb-v", now))...))
		sink.chainHead = "someone-elses-head"
		rep, err := svcFor(sink).VerifySecretAuditChain(ctx)
		if err != nil || rep.OK || rep.WriterTipMatches || rep.Error == "" {
			t.Fatalf("tip drift = %+v, %v", rep, err)
		}
	})
}

// cov96aNoFetchCluster exposes only cluster.Client, so the service finds no
// peer fetcher behind it.
type cov96aNoFetchCluster struct {
	cluster.Client
	members   []cluster.Member
	placement cluster.Placement
}

func (c *cov96aNoFetchCluster) Members() []cluster.Member      { return c.members }
func (c *cov96aNoFetchCluster) LocalMembers() []cluster.Member { return c.members }
func (c *cov96aNoFetchCluster) PlacementOf(string) (cluster.Placement, bool) {
	return c.placement, c.placement.SandboxID != ""
}

func TestCov96AuditListSecretAudit(t *testing.T) {
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0).UTC()
	local := cov96aOpen("sb-list", base)
	local.EventID = "local-1"
	data := cov96aJoin(cov96aChain(t, local)...)
	svcFor := func(t *testing.T) *Service {
		sink := cov96aFileSink(t, data)
		return &Service{secretAudit: sink, secretAuditFile: sink, logger: slog.New(slog.DiscardHandler)}
	}
	q := func(limit int) SecretAuditQuery { return SecretAuditQuery{IncarnationID: "inc", Limit: limit} }

	t.Run("invalid cursor", func(t *testing.T) {
		opts := q(10)
		opts.Cursor = "no-separator"
		if _, err := svcFor(t).ListSecretAudit(ctx, "sb-list", opts); err == nil {
			t.Fatal("invalid cursor accepted")
		}
	})

	t.Run("limit clamps", func(t *testing.T) {
		page, err := svcFor(t).ListSecretAudit(ctx, "sb-list", q(maxSecretAuditLimit*5))
		if err != nil || len(page.Events) != 1 {
			t.Fatalf("clamped page = %+v, %v", page, err)
		}
	})

	t.Run("dead self and no fetcher", func(t *testing.T) {
		svc := svcFor(t)
		svc.cluster = &cov96aNoFetchCluster{
			Client: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: false},
				{NodeID: "peer", InternalURL: "https://peer", Alive: true},
			},
			placement: cluster.Placement{SandboxID: "sb-list", OwnerNodeID: "self", AuditNodeIDs: []string{"peer"}},
		}
		page, err := svc.ListSecretAudit(ctx, "sb-list", q(10))
		if err != nil {
			t.Fatalf("list = %v", err)
		}
		if !page.Coverage.Partial || len(page.Coverage.Missing) != 1 || page.Coverage.Missing[0] != "peer" {
			t.Fatalf("coverage = %+v, want only the unreachable peer missing", page.Coverage)
		}
	})

	t.Run("fan-out deadline before a slot frees", func(t *testing.T) {
		held := 0
		for held < cap(secretAuditFanoutSlots) {
			select {
			case secretAuditFanoutSlots <- struct{}{}:
				held++
				continue
			default:
			}
			break
		}
		t.Cleanup(func() {
			for range held {
				<-secretAuditFanoutSlots
			}
		})
		svc := svcFor(t)
		svc.cluster = &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "peer", InternalURL: "https://peer", Alive: true},
			},
			acl:       cluster.AuditACL{SandboxID: "sb-list", AuditNodeIDs: []string{"peer"}},
			aclExists: true,
		}
		svc.testAuditFetcher = &fakeAuditFetcher{pages: map[string]cluster.AuditPeerPage{"peer": {}}}
		deadline, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		page, err := svc.ListSecretAudit(deadline, "sb-list", q(10))
		if err != nil {
			t.Fatalf("list = %v", err)
		}
		if !page.Coverage.Partial || len(page.Coverage.Missing) != 1 {
			t.Fatalf("coverage = %+v, want the starved peer missing", page.Coverage)
		}
	})

	t.Run("equal times, truncated to limit", func(t *testing.T) {
		svc := svcFor(t)
		svc.cluster = &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "peer", InternalURL: "https://peer", Alive: true},
			},
			acl:       cluster.AuditACL{SandboxID: "sb-list", AuditNodeIDs: []string{"peer"}},
			aclExists: true,
		}
		svc.testAuditFetcher = &fakeAuditFetcher{pages: map[string]cluster.AuditPeerPage{"peer": {Events: []cluster.AuditEventDTO{
			{Time: base, SandboxID: "sb-list", IncarnationID: "inc", EventID: "peer-0", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess},
			{Time: base, SandboxID: "sb-list", IncarnationID: "inc", EventID: "peer-2", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess},
		}}}}
		page, err := svc.ListSecretAudit(ctx, "sb-list", q(2))
		if err != nil {
			t.Fatalf("list = %v", err)
		}
		if len(page.Events) != 2 || page.NextCursor == "" {
			t.Fatalf("page = %+v, want two events and a cursor", page)
		}
		if page.Coverage.Partial {
			t.Fatalf("coverage = %+v", page.Coverage)
		}
	})
}
