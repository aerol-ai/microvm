package harness

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// multiLineStub answers with one Server-Timing header line per value.
type multiLineStub struct{ values []string }

func (s multiLineStub) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	for _, v := range s.values {
		h.Add("Server-Timing", v)
	}
	return &http.Response{StatusCode: http.StatusCreated, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// Plan PR #1000 item L1: a cold containerd create now reports every step as a
// Server-Timing stage, and containerd_netns says in its desc whether the warm
// namespace queue served it. The bench groups stages by name, so the harness
// also files containerd_netns under containerd_netns_hit or _miss, and a live
// run reports the two medians apart instead of mixing them. Other stages that
// carry a desc (containerd_pool, fc_warm) keep one key each, as before.
func TestParseServerTimingStagesColdContainerdCreate(t *testing.T) {
	header := "create;dur=180.0, engine;desc=containerd, toolbox_wait;dur=12.0, readiness;desc=socket, " +
		"cluster_place;dur=0.6, cluster_reserve;dur=8.1, " +
		"svc_validate;dur=0.3, svc_quota;dur=0.1, svc_policy;dur=0.4, svc_keygen;dur=0.2, svc_admit;dur=0.1, svc_pre_driver;dur=0.5, " +
		"containerd_pool;dur=0.0;desc=miss, containerd_netns;dur=3.5;desc=hit, containerd_image;dur=1.0;desc=resolved, " +
		"containerd_spec;dur=6.0, containerd_lease;dur=2.0, containerd_container;dur=40.0, containerd_task;dur=55.0, " +
		"containerd_create;dur=96.0, containerd_start;dur=9.0, containerd_address;dur=0.4, cluster_promote;dur=11.0"
	want := map[string]float64{
		"create": 180, "toolbox_wait": 12,
		"cluster_place": 0.6, "cluster_reserve": 8.1,
		"svc_validate": 0.3, "svc_quota": 0.1, "svc_policy": 0.4, "svc_keygen": 0.2, "svc_admit": 0.1, "svc_pre_driver": 0.5,
		"containerd_pool":  0,
		"containerd_netns": 3.5, "containerd_netns_hit": 3.5,
		"containerd_image": 1,
		"containerd_spec":  6, "containerd_lease": 2, "containerd_container": 40, "containerd_task": 55,
		"containerd_create": 96, "containerd_start": 9, "containerd_address": 0.4, "cluster_promote": 11,
	}
	if got := parseServerTimingStages(header); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseServerTimingStages:\n got %v\nwant %v", got, want)
	}

	miss := parseServerTimingStages("containerd_netns;dur=31.0;desc=miss")
	if want := map[string]float64{"containerd_netns": 31, "containerd_netns_miss": 31}; !reflect.DeepEqual(miss, want) {
		t.Fatalf("miss: got %v, want %v", miss, want)
	}
}

// A forwarded create carries the router's stages after the target's, and a
// server may send them as separate Server-Timing lines: the transport must
// read every line, not just the first.
func TestServerTimingTransportReadsEveryHeaderLine(t *testing.T) {
	tr := &serverTimingTransport{base: multiLineStub{values: []string{"create;dur=50.0", "readiness;desc=socket, cluster_forward;dur=61.0"}}}
	if _, err := tr.RoundTrip(newReq(t, http.MethodPost, "https://x/v1/sandboxes")); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if ms, ok := tr.takeCreateMS(); !ok || ms != 50 {
		t.Fatalf("takeCreateMS = (%v, %v), want (50, true)", ms, ok)
	}
	if src, ok := tr.takeCreateReadinessSource(); !ok || src != "socket" {
		t.Fatalf("takeCreateReadinessSource = (%q, %v), want (socket, true) from the second line", src, ok)
	}
	if _, ok := tr.takeCreateReadinessSource(); ok {
		t.Fatal("takeCreateReadinessSource should be empty after consumption")
	}
	stages, ok := tr.takeCreateStages()
	if !ok || stages["cluster_forward"] != 61 {
		t.Fatalf("stages = %v, want cluster_forward=61 from the second line", stages)
	}
}
