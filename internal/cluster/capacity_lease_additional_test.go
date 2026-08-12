package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestCapacityLeaseCacheRefreshLocal(t *testing.T) {
	admitter := capacity.New(capacity.HostInfo{CPUCores: 4}, capacity.Limits{}, nil)
	cache := newCapacityLeaseCache("self", admitter, time.Second, nil)
	cache.SetLocalTemplateIDsProvider(func() ([]string, bool) {
		return []string{"tpl-1"}, true
	})

	cache.refreshLocal(time.Now())

	cache.mu.RLock()
	lease := cache.leases["self"]
	cache.mu.RUnlock()

	if !lease.snapshot.LocalTemplateInventoryKnown {
		t.Errorf("expected template inventory known")
	}
}

func TestFetchCapacitySnapshot(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	_, err := fetchCapacitySnapshot(context.Background(), ts.Client(), ts.URL, "")
	if err == nil {
		t.Errorf("expected error on 404")
	}
	var stErr statusError
	if !errors.As(err, &stErr) || stErr.status != http.StatusNotFound {
		t.Errorf("expected statusError 404, got %v", err)
	}

	// Test bad json
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer ts2.Close()

	_, err = fetchCapacitySnapshot(context.Background(), ts2.Client(), ts2.URL, "")
	if err == nil {
		t.Errorf("expected error on bad json")
	}
}

func TestFetchMemberCapacityNoUrl(t *testing.T) {
	c := &Cluster{}
	_, err := c.fetchMemberCapacity(context.Background(), Member{NodeID: "m1", APIURL: ""})
	if err == nil || !strings.Contains(err.Error(), "no reachable peer URL") {
		t.Errorf("expected missing url error, got %v", err)
	}
}

func TestFetchMemberCapacityFailClosedOnInternal503(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("try public"))
	}))
	defer internal.Close()

	publicHits := 0
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits++
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384})
	}))
	defer public.Close()

	c := &Cluster{
		httpClient:     public.Client(),
		internalClient: internal.Client(),
	}
	_, err := c.fetchMemberCapacity(context.Background(), Member{
		NodeID:      "m1",
		APIURL:      public.URL,
		InternalURL: internal.URL,
	})
	if err == nil {
		t.Fatal("expected internal 503 to fail closed (no public downgrade)")
	}
	if publicHits != 0 {
		t.Fatalf("public hits = %d, want 0", publicHits)
	}
}

func TestRefreshCapacityLeasesHandlesErrorsAndFallbacks(t *testing.T) {
	internalError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer internalError.Close()

	internalUnavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer internalUnavailable.Close()

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 6, HostMemoryTotalMB: 12288})
	}))
	defer public.Close()

	c := &Cluster{
		nodeID:         "self",
		httpClient:     public.Client(),
		internalClient: &http.Client{}, // shared dialer; PeerDial selects each peer's InternalURL
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		capacityLeases: newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil), time.Second, nil),
		gossip: &gossipNode{
			memberIndex: newGossipMemberIndex(),
		},
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "skip-empty", Alive: true, Role: config.NodeRoleWorker})
	c.gossip.memberIndex.upsert(Member{NodeID: "dead-node", Alive: false, Role: config.NodeRoleWorker, APIURL: public.URL})
	c.gossip.memberIndex.upsert(Member{NodeID: "error-node", Alive: true, Role: config.NodeRoleWorker, APIURL: public.URL, InternalURL: internalError.URL})
	c.gossip.memberIndex.upsert(Member{NodeID: "no-public-downgrade", Alive: true, Role: config.NodeRoleWorker, APIURL: public.URL, InternalURL: internalUnavailable.URL})

	c.refreshCapacityLeases(context.Background())

	// With TLS loaded, a 503 on the internal channel must not silently
	// downgrade to the public capacity endpoint.
	if _, ok := c.capacityLeases.leases["no-public-downgrade"]; ok {
		t.Fatal("refreshCapacityLeases() downgraded 503 internal to public capacity")
	}
	if _, ok := c.capacityLeases.leases["skip-empty"]; ok {
		t.Fatal("refreshCapacityLeases() created a lease for skip-empty member")
	}
}
