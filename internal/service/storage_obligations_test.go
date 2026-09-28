package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

type obligationReportingCluster struct {
	*cluster.Noop
	reports []cluster.StorageObligationReport
	err     error
	views   []cluster.StorageObligationView
	viewErr error
}

func (c *obligationReportingCluster) ReportStorageObligations(_ context.Context, r cluster.StorageObligationReport) error {
	if c.err != nil {
		return c.err
	}
	c.reports = append(c.reports, r)
	return nil
}

func (c *obligationReportingCluster) StorageObligations(context.Context) ([]cluster.StorageObligationView, error) {
	return c.views, c.viewErr
}

// The owner reports its whole outbox as a snapshot, heartbeats an unchanged
// one on the refresh, and never lets Seq go backwards.
func TestReportStorageObligations(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cl := &obligationReportingCluster{Noop: cluster.NewNoop("worker-a", "http://a", "")}
	svc := &Service{cfg: config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, store: st, cluster: cl}
	t0 := time.Unix(1_000, 0)

	// First report goes out even when nothing is owed: the heartbeat is what
	// separates "owes nothing" from "stopped checking in".
	svc.reportStorageObligations(ctx, t0)
	if len(cl.reports) != 1 || cl.reports[0].Reporter != "worker-a" || len(cl.reports[0].Owed) != 0 {
		t.Fatalf("first report = %+v", cl.reports)
	}
	// Unchanged and not due: nothing sent.
	svc.reportStorageObligations(ctx, t0.Add(time.Minute))
	if len(cl.reports) != 1 {
		t.Fatalf("an unchanged report was re-sent before the refresh: %d", len(cl.reports))
	}
	// Changed: sent at once.
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-1", "inc-1", []string{"worker-x"}, 1); err != nil {
		t.Fatal(err)
	}
	svc.reportStorageObligations(ctx, t0.Add(2*time.Minute))
	if len(cl.reports) != 2 || cl.reports[1].Owed["worker-x"] != 1 {
		t.Fatalf("a changed report was not sent: %+v", cl.reports)
	}
	// Unchanged but due: heartbeat.
	svc.reportStorageObligations(ctx, t0.Add(2*time.Minute+storageObligationReportRefresh))
	if len(cl.reports) != 3 {
		t.Fatalf("the refresh heartbeat was not sent: %d", len(cl.reports))
	}
	for i := 1; i < len(cl.reports); i++ {
		if cl.reports[i].Seq <= cl.reports[i-1].Seq {
			t.Fatalf("Seq went backwards: %d then %d", cl.reports[i-1].Seq, cl.reports[i].Seq)
		}
	}
	// A clock stepped backwards still yields an increasing Seq.
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-2", "inc-2", []string{"worker-y"}, 1); err != nil {
		t.Fatal(err)
	}
	svc.reportStorageObligations(ctx, t0)
	if last := cl.reports[len(cl.reports)-1]; last.Seq <= cl.reports[len(cl.reports)-2].Seq {
		t.Fatal("a backwards clock produced a non-increasing Seq")
	}
	// A failed send is retried next tick (state not advanced).
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-3", "inc-3", []string{"worker-z"}, 1); err != nil {
		t.Fatal(err)
	}
	n := len(cl.reports)
	cl.err = errors.New("control plane down")
	svc.reportStorageObligations(ctx, t0.Add(10*time.Minute))
	cl.err = nil
	svc.reportStorageObligations(ctx, t0.Add(10*time.Minute+time.Second))
	if len(cl.reports) != n+1 || cl.reports[n].Owed["worker-z"] != 1 {
		t.Fatalf("a report that failed was not retried: %+v", cl.reports[n:])
	}
}

func TestReportStorageObligationsGuards(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cl := &obligationReportingCluster{Noop: cluster.NewNoop("ingress-a", "http://a", "")}
	for _, svc := range []*Service{
		nil,
		{cfg: config.Config{EnableCluster: false}, store: st, cluster: cl},                                                           // cluster off
		{cfg: config.Config{EnableCluster: true, NodeRole: config.NodeRoleIngress}, store: st, cluster: cl},                          // cannot own sandboxes
		{cfg: config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, store: st, cluster: cluster.NewNoop("w", "", "")}, // no reporter
		{cfg: config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, cluster: cl},                                      // no store
	} {
		svc.reportStorageObligations(ctx, time.Now())
	}
	if len(cl.reports) != 0 {
		t.Fatalf("a guarded node reported: %+v", cl.reports)
	}
	if !owedMapsEqual(map[string]int{"a": 1, "b": 0}, map[string]int{"a": 1}) || owedMapsEqual(map[string]int{"a": 1}, map[string]int{"a": 2}) {
		t.Fatal("owedMapsEqual must ignore zero entries and compare counts")
	}
}

func TestServiceStorageObligations(t *testing.T) {
	ctx := context.Background()
	cl := &obligationReportingCluster{Noop: cluster.NewNoop("s", "", ""), views: []cluster.StorageObligationView{{NodeID: "worker-x"}}}
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cl}
	if v, err := svc.StorageObligations(ctx); err != nil || len(v) != 1 {
		t.Fatalf("view = %+v %v", v, err)
	}
	cl.viewErr = errors.New("control plane down")
	if _, err := svc.StorageObligations(ctx); err == nil {
		t.Fatal("a failed read was not surfaced; it would render as all-clear")
	}
	if v, _ := (&Service{cfg: config.Config{EnableCluster: false}}).StorageObligations(ctx); v != nil {
		t.Fatal("cluster off must report nothing")
	}
	if v, _ := (&Service{cfg: config.Config{EnableCluster: true}, cluster: cluster.NewNoop("n", "", "")}).StorageObligations(ctx); v != nil {
		t.Fatal("a client with no view must report nothing")
	}
}
