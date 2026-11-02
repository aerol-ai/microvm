package apihttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A full network-slot pool answers exactly like every other capacity refusal:
// 503, the capacity Retry-After, no code, and a message that names the pool
// and says capacity. The bank density run saw these as the catch-all 400, so
// a client could not tell "node full, retry" from "broken". No Classify case
// was added for them: the pools' errors are capacity.ErrCapacityExceeded.
func TestSlotPoolExhaustionClassifiesAsCapacity(t *testing.T) {
	want := Classify(capacity.ErrCapacityExceeded)
	cases := []struct {
		name string
		err  error
		pool string
	}{
		{"containerd netns", fmt.Errorf("provision netns: %w", store.ErrNoFreeContainerNetnsSlot), "container netns pool"},
		{"firecracker tap", fmt.Errorf("firecracker runtime: tap allocate: %w", store.ErrNoFreeFirecrackerTapSlot), "firecracker tap pool"},
		{"isolate egress", fmt.Errorf("isolate: %w", isolate.ErrEgressPoolExhausted), "isolate egress pool"},
		{"docker bridge admission", fullDockerBridgeAdmit(t), capacity.DockerBridgePool},
		// The backstop: dockerd refused the start on a full bridge.
		{"docker bridge exchange full", capacity.AsNetworkSlotExhausted(capacity.DockerBridgePool, errors.New(`start container: docker API POST /containers/c1/start failed with status 500: {"message":"failed to set up container networking: adding interface veth5f0e1a2 to bridge docker0 failed: exchange full"}`)), capacity.DockerBridgePool},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.err)
			if got.Status != http.StatusServiceUnavailable || got.Status != want.Status || got.RetryAfter != want.RetryAfter || got.Code != want.Code || got.Kind != want.Kind {
				t.Fatalf("Classify = %+v, want the capacity rendering %+v", got, want)
			}
			if got.RetryAfter != cluster.CapacityRetryAfterSeconds {
				t.Fatalf("Retry-After = %d, want %d", got.RetryAfter, cluster.CapacityRetryAfterSeconds)
			}
			rr := httptest.NewRecorder()
			WriteStoreAwareError(discardLogger(), rr, tc.err)
			if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") != strconv.Itoa(cluster.CapacityRetryAfterSeconds) {
				t.Fatalf("response = %d Retry-After=%q", rr.Code, rr.Header().Get("Retry-After"))
			}
			var body models.ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(body.Error, tc.pool) || !strings.Contains(body.Error, "capacity") {
				t.Fatalf("body error %q must name the pool and say capacity", body.Error)
			}
		})
	}
}

// fullDockerBridgeAdmit is the admitter's refusal on a full docker bridge.
func fullDockerBridgeAdmit(t *testing.T) error {
	t.Helper()
	a := capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, capacity.Limits{}, nil)
	a.SetSlotLimit(capacity.SlotLimit{Name: capacity.SlotPoolDockerBridge, Pool: capacity.DockerBridgePool, Runtimes: []string{models.RuntimeDocker}, Total: 1})
	a.Reserve("sb-1", capacity.Request{Runtime: models.RuntimeDocker})
	err := a.Admit("sb-2", capacity.Request{Runtime: models.RuntimeDocker})
	if err == nil {
		t.Fatal("admit on a full docker bridge succeeded")
	}
	return err
}

// Every worker full is a 503 like "no target", and its message says capacity.
func TestClusterAtCapacityClassifiesAsUnavailable(t *testing.T) {
	got := Classify(cluster.ErrClusterAtCapacity)
	if got.Status != http.StatusServiceUnavailable || !strings.Contains(got.Message, "capacity") {
		t.Fatalf("Classify(ErrClusterAtCapacity) = %+v, want 503 naming capacity", got)
	}
}
