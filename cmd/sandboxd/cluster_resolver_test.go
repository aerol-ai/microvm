package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stubClusterResolver embeds *cluster.Noop so the full cluster.Client surface
// is satisfied by Noop's empty stubs — we override only ResolveCustomDomain
// to drive the "cluster has it" branch without standing up a real raft.
type stubClusterResolver struct {
	*cluster.Noop
	hits map[string]string
}

func (s *stubClusterResolver) ResolveCustomDomain(hostname string) (string, bool) {
	id, ok := s.hits[hostname]
	return id, ok
}

// TestClusterAwareDomainResolver_ClusterHitSkipsStore: an FSM-known hostname
// must short-circuit the store. The hot path for SNI floods has to stay
// in-memory once the cluster has the mapping; falling through to SQLite per
// packet defeats the whole point of the FSM index.
func TestClusterAwareDomainResolver_ClusterHitSkipsStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	resolver := clusterAwareDomainResolver{
		cluster: &stubClusterResolver{
			Noop: cluster.NewNoop("test", "http://test"),
			hits: map[string]string{"api.acme.com": "sb-from-cluster"},
		},
		store: st,
	}

	got, err := resolver.ResolveCustomDomain(context.Background(), "api.acme.com")
	if err != nil {
		t.Fatalf("ResolveCustomDomain: %v", err)
	}
	if got != "sb-from-cluster" {
		t.Fatalf("got %q, want sb-from-cluster", got)
	}
}

// TestClusterAwareDomainResolver_NoopFallsBackToStore: Noop always reports
// miss (no FSM in single-node mode), so we must consult the store. This is
// the single-node regression guard required by CLAUDE.md.
func TestClusterAwareDomainResolver_NoopFallsBackToStore(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// sandbox_custom_domains has an FK on sandbox_id; seed a minimal row.
	if err := st.Create(ctx, &models.Sandbox{
		ID:        "sb-local",
		Image:     "ubuntu:22.04",
		Status:    models.SandboxStatusStarted,
		Runtime:   models.RuntimeGvisor,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-local", "api.local.example"); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}

	resolver := clusterAwareDomainResolver{
		cluster: cluster.NewNoop("test", "http://test"),
		store:   st,
	}

	got, err := resolver.ResolveCustomDomain(ctx, "api.local.example")
	if err != nil {
		t.Fatalf("ResolveCustomDomain: %v", err)
	}
	if got != "sb-local" {
		t.Fatalf("got %q, want sb-local", got)
	}
}

// TestClusterAwareDomainResolver_MissReturnsErrNotFound: when neither layer
// knows the hostname, the adapter must surface store.ErrNotFound so the
// TLSAsk handler folds it into the negative cache + 403 path without
// emitting a resolver-outage warning.
func TestClusterAwareDomainResolver_MissReturnsErrNotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	resolver := clusterAwareDomainResolver{
		cluster: cluster.NewNoop("test", "http://test"),
		store:   st,
	}

	_, err = resolver.ResolveCustomDomain(context.Background(), "unknown.example")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want store.ErrNotFound", err)
	}
}
