package clustercreate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

type clusterStub struct {
	*cluster.Noop
	owner      cluster.OwnerInfo
	ownerErr   error
	forwards   int
	lastTarget cluster.Endpoint
	deletes    int
	cancels    int
}

func (s *clusterStub) OwnerOf(_ string) (cluster.OwnerInfo, error) {
	if s.ownerErr != nil {
		return cluster.OwnerInfo{}, s.ownerErr
	}
	return s.owner, nil
}

func (s *clusterStub) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	s.forwards++
	s.lastTarget = target
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("forwarded"))
}

func (s *clusterStub) DeletePlacement(_ context.Context, _ string) error {
	s.deletes++
	return nil
}

func (s *clusterStub) CancelReservation(_ context.Context, _ string) error {
	s.cancels++
	return nil
}

func testServiceWithCluster(c cluster.Client) *service.Service {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	return svc
}

func TestCapacityRequestFromCreate_DefaultsAndGPU(t *testing.T) {
	got := CapacityRequestFromCreate(models.CreateSandboxRequest{
		Runtime: models.RuntimeFirecracker,
		GPUs: &models.GPURequest{
			Vendor: models.GPUVendorNVIDIA,
			Count:  0,
		},
	})
	if got.CPU != models.DefaultCPU || got.MemoryMB != models.DefaultMemoryMB || got.DiskGB != models.DefaultDiskGB {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if got.GPUs != 1 || got.GPUVendor != string(models.GPUVendorNVIDIA) {
		t.Fatalf("gpu fields mismatch: %+v", got)
	}
	if got.Runtime != models.RuntimeFirecracker {
		t.Fatalf("runtime mismatch: %q", got.Runtime)
	}
}

func TestRouteExistingPlacement(t *testing.T) {
	tests := []struct {
		name        string
		stub        *clusterStub
		wantHandled bool
		wantLocal   bool
		wantCode    int
		wantForward bool
	}{
		{
			name:        "owner_lookup_error_is_unhandled",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), ownerErr: errors.New("boom")},
			wantHandled: false,
			wantLocal:   false,
		},
		{
			name:        "self_owner_returns_local",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), owner: cluster.OwnerInfo{NodeID: "node-a", IsSelf: true}},
			wantHandled: false,
			wantLocal:   true,
		},
		{
			name:        "remote_owner_without_urls_is_handled_error",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), owner: cluster.OwnerInfo{NodeID: "node-b"}},
			wantHandled: true,
			wantLocal:   false,
			wantCode:    http.StatusServiceUnavailable,
		},
		{
			name:        "remote_owner_forwards",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), owner: cluster.OwnerInfo{NodeID: "node-b", APIURL: "https://node-b.example", InternalURL: "https://node-b.internal"}},
			wantHandled: true,
			wantLocal:   false,
			wantForward: true,
			wantCode:    http.StatusAccepted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
			w := httptest.NewRecorder()
			var status int
			var message string

			handled, local := routeExistingPlacement(w, r, tc.stub, "sb-1", func(_ http.ResponseWriter, code int, msg string) {
				status = code
				message = msg
				w.WriteHeader(code)
			})

			if handled != tc.wantHandled || local != tc.wantLocal {
				t.Fatalf("(handled,local) = (%v,%v), want (%v,%v)", handled, local, tc.wantHandled, tc.wantLocal)
			}
			if tc.stub.ownerErr == nil {
				if got := r.Header.Get(HeaderID); got != "sb-1" {
					t.Fatalf("%s = %q, want sb-1", HeaderID, got)
				}
				if got := r.Header.Get(HeaderTarget); tc.stub.owner.NodeID != "" && got != tc.stub.owner.NodeID {
					t.Fatalf("%s = %q, want %q", HeaderTarget, got, tc.stub.owner.NodeID)
				}
			}
			if tc.wantForward {
				if tc.stub.forwards != 1 {
					t.Fatalf("ForwardHTTP calls = %d, want 1", tc.stub.forwards)
				}
				if tc.stub.lastTarget.APIURL != tc.stub.owner.APIURL || tc.stub.lastTarget.InternalURL != tc.stub.owner.InternalURL {
					t.Fatalf("forward target mismatch: %+v", tc.stub.lastTarget)
				}
			}
			if tc.wantCode != 0 {
				if w.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
				}
				if tc.wantCode == http.StatusServiceUnavailable && !strings.Contains(message, "URL unknown") {
					t.Fatalf("message = %q, want URL unknown", message)
				}
			}
			if tc.wantCode == 0 && status != 0 {
				t.Fatalf("unexpected error status: %d", status)
			}
		})
	}
}

func TestPrepare_ForwardedHeaderValidation(t *testing.T) {
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "https://node-a.example", "")}
	svc := testServiceWithCluster(stub)
	baseReq := models.CreateSandboxRequest{Image: "alpine:3.20"}

	t.Run("wrong_target_rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-b")
		w := httptest.NewRecorder()
		var status int
		_, ok := Prepare(w, r, svc, baseReq, func(_ http.ResponseWriter, code int, _ string) {
			status = code
		}, PrepareOptions{})
		if ok {
			t.Fatal("Prepare returned ok=true, want false")
		}
		if status != http.StatusMisdirectedRequest {
			t.Fatalf("status = %d, want %d", status, http.StatusMisdirectedRequest)
		}
	})

	t.Run("forwarded_missing_id_rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-a")
		w := httptest.NewRecorder()
		var status int
		_, ok := Prepare(w, r, svc, baseReq, func(_ http.ResponseWriter, code int, _ string) {
			status = code
		}, PrepareOptions{})
		if ok {
			t.Fatal("Prepare returned ok=true, want false")
		}
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("forwarded_self_with_id_accepted", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-a")
		r.Header.Set(HeaderID, "sb-fixed")
		w := httptest.NewRecorder()
		decision, ok := Prepare(w, r, svc, baseReq, nil, PrepareOptions{})
		if !ok {
			t.Fatal("Prepare returned ok=false, want true")
		}
		if decision.ReservationID != "sb-fixed" {
			t.Fatalf("ReservationID = %q, want sb-fixed", decision.ReservationID)
		}
	})
}

func TestDeleteAndCancelReservationBestEffort(t *testing.T) {
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
	svc := testServiceWithCluster(stub)

	DeletePlacementBestEffort(context.Background(), svc, nil, "sb-1")
	if stub.deletes != 1 {
		t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
	}
	CancelReservationBestEffort(context.Background(), svc, nil, "sb-1")
	if stub.cancels != 1 {
		t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
	}

	DeletePlacementBestEffort(context.Background(), nil, nil, "sb-1")
	DeletePlacementBestEffort(context.Background(), svc, nil, "")
	CancelReservationBestEffort(context.Background(), nil, nil, "sb-1")
	CancelReservationBestEffort(context.Background(), svc, nil, "")

	if stub.deletes != 1 || stub.cancels != 1 {
		t.Fatalf("guard calls changed counts: deletes=%d cancels=%d", stub.deletes, stub.cancels)
	}
}
