package upgradewire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSHA256Re(t *testing.T) {
	good := strings.Repeat("ab", 32)
	cases := []struct {
		in   string
		want bool
	}{
		{good, true},
		{strings.ToUpper(good), false},
		{good[:63], false},
		{good + "a", false},
		{"../" + good[3:], false},
		{"", false},
	}
	for _, c := range cases {
		if got := SHA256Re.MatchString(c.in); got != c.want {
			t.Errorf("SHA256Re(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The JSON names are the wire contract between sandboxd and aerolvm; a
// rename here breaks an older CLI against a newer server.
func TestWireNames(t *testing.T) {
	b, err := json.Marshal(ApplyRequest{Version: "v1", Files: map[string]string{"a": "b"}, Source: SourceUpload, Hold: true, Batch: "10%", PauseAfter: 2, NodeTimeout: "10m", AllowDowntime: true, AllowUnversioned: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"v1","files":{"a":"b"},"source":"upload","hold":true,"batch":"10%","pause_after":2,"node_timeout":"10m","allow_downtime":true,"allow_unversioned":true}`
	if string(b) != want {
		t.Fatalf("ApplyRequest JSON\n got %s\nwant %s", b, want)
	}
	var r Rollout
	if err := json.Unmarshal([]byte(`{"id":"r1","state":"paused","direction":"upgrade","target_version":"v2","nodes":[{"node_id":"w1","state":"manual","manual_command":"sudo sandboxd upgrade node v2"}]}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.State != StatePaused || r.Direction != DirectionUpgrade || len(r.Nodes) != 1 || r.Nodes[0].State != NodeManual || r.Nodes[0].ManualCommand == "" {
		t.Fatalf("Rollout decode: %+v", r)
	}
}
