package gatewayd

import "testing"

// C6: the peer-cgroup check is sandboxd.service unless set; "none" turns it
// off for a gateway in its own container; an empty value keeps the default.
func TestPeerCgroupFromEnv(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"", "sandboxd.service"},
		{"none", ""},
		{"NONE", ""},
		{" none ", ""},
		{"aerolvm-agent.scope", "aerolvm-agent.scope"},
	} {
		t.Setenv("SB_EGRESS_PEER_CGROUP", tc.value)
		cfg, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PeerCgroup != tc.want {
			t.Errorf("SB_EGRESS_PEER_CGROUP=%q: PeerCgroup %q, want %q", tc.value, cfg.PeerCgroup, tc.want)
		}
	}
}
