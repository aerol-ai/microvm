package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage97CheckpointPoolCancelWhileQueued(t *testing.T) {
	svc := &Service{cfg: config.Config{WasmCheckpointMaxParallel: 1}}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- svc.runWasmCheckpointPool(ctx, []*models.Sandbox{{ID: "a"}, {ID: "b"}}, func(sb *models.Sandbox) error {
			if sb.ID == "a" {
				close(started)
				<-release
			}
			return nil
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("checkpoint worker did not start")
	}
	cancel()
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runWasmCheckpointPool = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("checkpoint pool did not return")
	}
}

func TestCoverage97PruneWasmCheckpointDisabledAndListError(t *testing.T) {
	svc := &Service{logger: slog.New(slog.DiscardHandler)}
	svc.pruneWasmCheckpointPushes(context.Background(), "sb", "inc")

	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc.store = st
	svc.cfg.WasmCheckpointKeepLastN = 2
	svc.pruneWasmCheckpointPushes(context.Background(), "sb", "inc")
}

func TestCoverage97AuditIngestKeyEdges(t *testing.T) {
	if key, err := (*Service)(nil).auditIngestSigningKey(); err != nil || key != "" {
		t.Fatalf("nil service = %q %v", key, err)
	}

	missingParent := &Service{cfg: config.Config{
		EgressAttributionEnabled: true,
		DBPath:                   filepath.Join(t.TempDir(), "missing", "state.db"),
	}}
	if _, err := missingParent.auditIngestSigningKey(); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key dir = %v", err)
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, auditIngestKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	dirKey := &Service{cfg: config.Config{
		EgressAttributionEnabled: true,
		DBPath:                   filepath.Join(dir, "state.db"),
	}}
	if _, err := dirKey.auditIngestSigningKey(); err == nil {
		t.Fatal("directory key file was accepted")
	}
}

func TestCoverage97PruneMalformedAuditLine(t *testing.T) {
	dir := t.TempDir()
	sink, err := newFileAuditSink(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	f, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{not-json}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.pruneLocked(time.Now().Add(time.Hour), "", ""); err == nil {
		t.Fatal("malformed audit line was retained")
	}

	if err := os.Remove(sink.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sink.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sink.pruneLocked(time.Now(), "", ""); err == nil {
		t.Fatal("directory audit file was opened")
	}
}

func TestCoverage97ExpandAndResealGuards(t *testing.T) {
	svc := &Service{}
	ctx := context.Background()
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cluster.NewNoop("self", "", ""), cluster.Placement{}); err == nil {
		t.Fatal("empty placement was accepted")
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cluster.NewNoop("self", "", ""), cluster.Placement{
		SandboxID: "sb", IncarnationID: "inc", State: cluster.PlacementStateDeleting,
	}); err != nil {
		t.Fatalf("deleting placement = %v", err)
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cluster.NewNoop("self", "", ""), cluster.Placement{
		SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: "other",
	}); err != nil {
		t.Fatalf("foreign owner = %v", err)
	}
}

func TestCoverage97PutOutboxLoadFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		logger:  slog.New(slog.DiscardHandler),
		store:   st,
		cluster: &cov97SecretPusher{Noop: cluster.NewNoop("self", "", "")},
	}
	rec := &store.SecretPutOutboxRecord{SandboxID: "sb", IncarnationID: "inc", SealGeneration: 1, Recipients: []string{"peer"}}
	svc.reconcileSecretPutOutboxRecord(context.Background(), rec, nil)
	svc.reconcileSecretPutOutboxRecord(context.Background(), &store.SecretPutOutboxRecord{
		SandboxID: "sb", IncarnationID: "inc", SealGeneration: 1,
	}, nil)
}

func TestCoverage97Layer4AlreadyReadyUnderLock(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	var last error
	for i := 0; i < 20; i++ {
		svc.l4Ready.Store(false)
		svc.l4Mu.Lock()
		errCh := make(chan error, 1)
		go func() { errCh <- svc.EnsureLayer4Ready(context.Background()) }()
		time.Sleep(15 * time.Millisecond)
		svc.l4Ready.Store(true)
		svc.l4Mu.Unlock()
		last = <-errCh
		if last == nil {
			return
		}
	}
	t.Fatalf("EnsureLayer4Ready = %v", last)
}
