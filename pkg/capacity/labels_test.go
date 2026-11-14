package capacity

import (
	"encoding/json"
	"strings"
	"testing"
)

// Labels are what placement rules match on, and the snapshot is the
// heartbeat payload peers decode: the labels must reach it, as a copy, and
// survive the JSON round trip of GET /v1/capacity.
func TestSnapshotCarriesHostLabels(t *testing.T) {
	labels := map[string]string{"zone": "eu-west-1a", "gpu": "a10"}
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 8192, Labels: labels}, Limits{}, fakeProbe{free: 8000})
	snap := a.Snapshot()
	if snap.Labels["zone"] != "eu-west-1a" || snap.Labels["gpu"] != "a10" || len(snap.Labels) != 2 {
		t.Fatalf("snapshot labels = %v", snap.Labels)
	}
	snap.Labels["zone"] = "mutated"
	if again := a.Snapshot(); again.Labels["zone"] != "eu-west-1a" {
		t.Fatalf("a reader's mutation reached the admitter: %v", again.Labels)
	}
	b, err := json.Marshal(a.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Labels["gpu"] != "a10" {
		t.Fatalf("labels lost on the wire: %s", b)
	}
}

// An unlabelled node sends no labels key at all, so its heartbeat is byte
// for byte what an older build sends.
func TestSnapshotWithoutLabelsOmitsField(t *testing.T) {
	a := New(HostInfo{CPUCores: 4, MemoryTotalMB: 8192}, Limits{}, fakeProbe{free: 8000})
	if a.Snapshot().Labels != nil {
		t.Fatal("unlabelled host reported labels")
	}
	b, _ := json.Marshal(a.Snapshot())
	if strings.Contains(string(b), `"labels"`) {
		t.Fatalf("unlabelled snapshot carries a labels key: %s", b)
	}
	// The select-placement RPC carries Request as JSON; a request without a
	// rule must not grow a Labels key either.
	rb, _ := json.Marshal(Request{CPU: 1})
	if strings.Contains(string(rb), "Labels") {
		t.Fatalf("request without a rule carries Labels: %s", rb)
	}
	rb, _ = json.Marshal(Request{CPU: 1, Labels: map[string]string{"zone": "z"}})
	var rq Request
	if err := json.Unmarshal(rb, &rq); err != nil || rq.Labels["zone"] != "z" {
		t.Fatalf("request labels lost on the wire: %s (%v)", rb, err)
	}
}
