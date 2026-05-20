package cluster

import (
	"testing"

	"github.com/hashicorp/raft"
)

func TestRaftConfigurationFromPeersJSON(t *testing.T) {
	cfg, err := raftConfigurationFromPeersJSON([]byte(`[
		{"id":"server-a","address":"10.0.0.1:7000","suffrage":"Voter"},
		{"id":"server-b","address":"10.0.0.2:7000","non_voter":true}
	]`))
	if err != nil {
		t.Fatalf("raftConfigurationFromPeersJSON error = %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(cfg.Servers))
	}
	if cfg.Servers[0].ID != "server-a" || cfg.Servers[0].Address != "10.0.0.1:7000" || cfg.Servers[0].Suffrage != raft.Voter {
		t.Fatalf("unexpected first server: %+v", cfg.Servers[0])
	}
	if cfg.Servers[1].ID != "server-b" || cfg.Servers[1].Suffrage != raft.Nonvoter {
		t.Fatalf("unexpected second server: %+v", cfg.Servers[1])
	}
}

func TestRaftConfigurationFromPeersJSONRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty", body: `[]`},
		{name: "missing_address", body: `[{"id":"server-a"}]`},
		{name: "duplicate_id", body: `[
			{"id":"server-a","address":"10.0.0.1:7000"},
			{"id":"server-a","address":"10.0.0.2:7000"}
		]`},
		{name: "bad_suffrage", body: `[{"id":"server-a","address":"10.0.0.1:7000","suffrage":"leader"}]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := raftConfigurationFromPeersJSON([]byte(tc.body)); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}
