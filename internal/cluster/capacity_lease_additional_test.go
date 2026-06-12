package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	if err == nil || err.Error() != "node m1 has no API URL for capacity heartbeat" {
		t.Errorf("expected missing url error, got %v", err)
	}
}

func TestFetchMemberCapacityFallsBackToPublicAPI(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("try public"))
	}))
	defer internal.Close()

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384})
	}))
	defer public.Close()

	c := &Cluster{
		httpClient:     public.Client(),
		internalClient: internal.Client(),
	}
	snap, err := c.fetchMemberCapacity(context.Background(), Member{
		NodeID:      "m1",
		APIURL:      public.URL,
		InternalURL: internal.URL,
	})
	if err != nil {
		t.Fatalf("fetchMemberCapacity() error = %v", err)
	}
	if snap.HostCPUCores != 8 || snap.HostMemoryTotalMB != 16384 {
		t.Fatalf("fetchMemberCapacity() snapshot = %+v", snap)
	}
}
