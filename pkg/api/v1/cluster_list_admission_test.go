package v1

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestClusterListAdmissionBoundsConcurrentSweeps pins the global sweep bound.
// singleflight only coalesces identical owner keys, so without this bound every
// distinct tenant missing the 2s cache starts its own fleet-wide sweep and the
// leader's fan-out scales with the number of tenants polling.
func TestClusterListAdmissionBoundsConcurrentSweeps(t *testing.T) {
	cache := &clusterListCache[int]{}

	release := make(chan struct{})
	var inFlight sync.WaitGroup
	started := make(chan struct{}, clusterListMaxConcurrentSweeps+1)

	sweep := func(*http.Request) (clusterListAggregate[int], error) {
		started <- struct{}{}
		<-release
		return clusterListAggregate[int]{rows: []int{1}}, nil
	}

	// Fill every slot with a distinct owner so singleflight cannot merge them.
	for i := range clusterListMaxConcurrentSweeps {
		inFlight.Add(1)
		go func(i int) {
			defer inFlight.Done()
			_, _ = cache.cached(ownerRequest(t, "tenant-"+string(rune('a'+i))), sweep)
		}(i)
	}
	for range clusterListMaxConcurrentSweeps {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("sweeps did not start")
		}
	}

	// One more distinct owner has no slot left and must be shed, not queued.
	_, err := cache.cached(ownerRequest(t, "tenant-overflow"), sweep)
	if !errors.Is(err, ErrClusterListBusy) {
		close(release)
		t.Fatalf("overflow sweep error = %v, want ErrClusterListBusy", err)
	}

	close(release)
	inFlight.Wait()

	// Slots are returned: a later caller succeeds.
	agg, err := cache.cached(ownerRequest(t, "tenant-after"), sweep)
	if err != nil || len(agg.rows) != 1 {
		t.Fatalf("post-drain sweep = %v, %v", agg.rows, err)
	}
}

// TestWriteClusterListErrorSheds pins the wire shape of the backpressure: a
// retryable 429, not a 500 the SDKs treat as fatal.
func TestWriteClusterListErrorSheds(t *testing.T) {
	rr := httptest.NewRecorder()
	writeClusterListError(nil, rr, ErrClusterListBusy)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Fatal("missing Retry-After on a shed list")
	}
}

func ownerRequest(t *testing.T, owner string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	return req.WithContext(controlplane.ContextWithAccess(req.Context(),
		controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}}))
}
