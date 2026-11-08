package clustercreate

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// timedForwardStub answers a forwarded create the way a target node does: its
// own Server-Timing on a 201, after a short create.
type timedForwardStub struct {
	*clusterStub
	targetTiming string
	createTime   time.Duration
}

func (s *timedForwardStub) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	s.forwards++
	s.lastTarget = target
	time.Sleep(s.createTime)
	w.Header().Set("Server-Timing", s.targetTiming)
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"id":"sb-remote"}`))
}

// Plan PR #1000 item L1: when the router reserves on another node and
// forwards, the client gets the target's Server-Timing. The router's own
// steps (pick a node, write the reservation, the forwarded round trip) must
// be added to that same header line, so a reader that takes the first
// Server-Timing value still sees create;dur and the router's stages.
func TestPrepareForwardAddsRouterStagesToTargetTiming(t *testing.T) {
	stub := &timedForwardStub{
		clusterStub: &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", InternalURL: "http://node-b.internal"},
		},
		targetTiming: "create;dur=42.0, containerd_start;dur=9.0",
		createTime:   15 * time.Millisecond,
	}
	svc := testServiceWithCluster(stub)
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	w := httptest.NewRecorder()
	if _, ok := Prepare(w, r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{PreferredSandboxID: "sb-remote"}); ok {
		t.Fatal("Prepare returned ok=true, want false after forwarding")
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if n := len(w.Header().Values("Server-Timing")); n != 1 {
		t.Fatalf("Server-Timing header lines = %d (%q), want 1", n, w.Header().Values("Server-Timing"))
	}
	st := w.Header().Get("Server-Timing")
	if !strings.HasPrefix(st, stub.targetTiming) {
		t.Fatalf("Server-Timing = %q, want the target's entries kept first", st)
	}
	for _, want := range []string{"cluster_place;dur=", "cluster_reserve;dur=", "cluster_forward;dur="} {
		if !strings.Contains(st, want) {
			t.Fatalf("Server-Timing = %q, missing %q", st, want)
		}
	}
	fwd := stageMS(t, st, "cluster_forward")
	if fwd < float64(stub.createTime.Milliseconds()) {
		t.Fatalf("cluster_forward = %.1f ms, want at least the target's %v", fwd, stub.createTime)
	}
}

func stageMS(t *testing.T, header, name string) float64 {
	t.Helper()
	for _, metric := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(metric), ";")
		if fields[0] != name {
			continue
		}
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(f, "dur="); ok {
				ms, err := strconv.ParseFloat(v, 64)
				if err != nil {
					t.Fatalf("%s dur %q: %v", name, v, err)
				}
				return ms
			}
		}
	}
	t.Fatalf("no %s in %q", name, header)
	return 0
}

// When the router reserves on itself, Prepare hands its two steps to the
// local create through the Decision; RecordReserveStages puts them on the
// create's recorder. A forwarded create's target gets a Decision with none:
// the router reports its own.
func TestPrepareReserveSelfCarriesReserveStages(t *testing.T) {
	stub := &clusterStub{
		Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
		selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	svc := testServiceWithCluster(stub)
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	decision, ok := Prepare(httptest.NewRecorder(), r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{PreferredSandboxID: "sb-self"})
	if !ok {
		t.Fatal("Prepare returned ok=false, want true")
	}
	timing := &createtiming.CreateTiming{}
	decision.RecordReserveStages(timing)
	var names []string
	for _, st := range timing.Stages() {
		names = append(names, st.Name)
	}
	if strings.Join(names, ",") != "cluster_place,cluster_reserve" {
		t.Fatalf("reserve stages = %v, want [cluster_place cluster_reserve]", names)
	}

	// The target side of a forward: the header names this node and the id.
	fwd := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	fwd.Header.Set(HeaderTarget, "node-a")
	fwd.Header.Set(HeaderID, "sb-self")
	target, ok := Prepare(httptest.NewRecorder(), fwd, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{})
	if !ok {
		t.Fatal("forwarded Prepare returned ok=false, want true")
	}
	empty := &createtiming.CreateTiming{}
	target.RecordReserveStages(empty)
	if got := empty.Stages(); len(got) != 0 {
		t.Fatalf("forwarded create's reserve stages = %+v, want none", got)
	}
}
