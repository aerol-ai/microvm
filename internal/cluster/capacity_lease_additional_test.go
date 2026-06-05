package cluster

import (
	"context"
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
