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

// M1 PR 10: privilege mode split names sandboxd's own uid; unset is root,
// as before.
func TestPeerUIDsFromEnv(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []uint32
		err   bool
	}{
		{"", []uint32{0}, false},
		{"65531", []uint32{65531}, false},
		{" 65531 , 0 ", []uint32{65531, 0}, false},
		{"sandboxd", nil, true},
		{"65531,", nil, true},
		{"-1", nil, true},
	} {
		t.Setenv("SB_EGRESS_PEER_UIDS", tc.value)
		cfg, err := FromEnv()
		if tc.err {
			if err == nil {
				t.Errorf("SB_EGRESS_PEER_UIDS=%q: no error", tc.value)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.PeerUIDs) != len(tc.want) {
			t.Fatalf("SB_EGRESS_PEER_UIDS=%q: %v, want %v", tc.value, cfg.PeerUIDs, tc.want)
		}
		for i := range tc.want {
			if cfg.PeerUIDs[i] != tc.want[i] {
				t.Errorf("SB_EGRESS_PEER_UIDS=%q: %v, want %v", tc.value, cfg.PeerUIDs, tc.want)
			}
		}
	}
}
