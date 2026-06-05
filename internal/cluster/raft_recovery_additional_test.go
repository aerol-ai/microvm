package cluster

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
)

func TestPeerSuffrage(t *testing.T) {
	cases := []struct {
		peer    raftRecoveryPeer
		want    string // raft.ServerSuffrage string representation basically, we just check error or not
		wantErr bool
	}{
		{raftRecoveryPeer{NonVoter: true}, "Nonvoter", false},
		{raftRecoveryPeer{Suffrage: ""}, "Voter", false},
		{raftRecoveryPeer{Suffrage: "voter"}, "Voter", false},
		{raftRecoveryPeer{Suffrage: "nonvoter"}, "Nonvoter", false},
		{raftRecoveryPeer{Suffrage: "non_voter"}, "Nonvoter", false},
		{raftRecoveryPeer{Suffrage: "staging"}, "Staging", false},
		{raftRecoveryPeer{Suffrage: "invalid"}, "", true},
	}

	for _, tc := range cases {
		suf, err := peerSuffrage(tc.peer)
		if (err != nil) != tc.wantErr {
			t.Errorf("peerSuffrage(%+v) err = %v, wantErr %v", tc.peer, err, tc.wantErr)
		}
		if !tc.wantErr && suf.String() != tc.want {
			t.Errorf("peerSuffrage(%+v) = %v, want %v", tc.peer, suf.String(), tc.want)
		}
	}
}

func TestRaftConfigurationFromPeersJSONAdditional(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{"invalid json", `[{"id":}]`, true},
		{"empty list", `[]`, true},
		{"missing id", `[{"address":"1.2.3.4"}]`, true},
		{"missing addr", `[{"id":"node1"}]`, true},
		{"duplicate id", `[{"id":"n1","address":"1"},{"id":"n1","address":"2"}]`, true},
		{"invalid suffrage", `[{"id":"n1","address":"1","suffrage":"bad"}]`, true},
		{"valid", `[{"id":"n1","address":"1","suffrage":"voter"}]`, false},
	}

	for _, tc := range cases {
		_, err := raftConfigurationFromPeersJSON([]byte(tc.payload))
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestMaybeRecoverRaftClusterFromPeersFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dir := t.TempDir()
	path := raftRecoveryPeersPath(dir)
	fsm := newPlacementFSM()

	// 1. Not exist -> no error
	err := maybeRecoverRaftClusterFromPeersFile(raftSetupConfig{DataDir: dir}, raft.DefaultConfig(), fsm, nil, nil, nil, nil, logger)
	if err != nil {
		t.Errorf("expected no error for missing peers file")
	}

	// 2. Invalid JSON -> error
	_ = os.WriteFile(path, []byte("invalid"), 0600)
	err = maybeRecoverRaftClusterFromPeersFile(raftSetupConfig{DataDir: dir}, raft.DefaultConfig(), fsm, nil, nil, nil, nil, logger)
	if err == nil {
		t.Errorf("expected error for invalid json")
	}

	// 3. Valid JSON but RecoverCluster fails (nil stores/transport)
	_ = os.WriteFile(path, []byte(`[{"id":"n1","address":"1"}]`), 0600)
	err = maybeRecoverRaftClusterFromPeersFile(raftSetupConfig{DataDir: dir}, raft.DefaultConfig(), fsm, nil, nil, nil, nil, logger)
	if err == nil {
		t.Errorf("expected error from RecoverCluster due to nil stores")
	}

	// 4. File read error (directory instead of file)
	os.Remove(path)
	os.Mkdir(path, 0700)
	err = maybeRecoverRaftClusterFromPeersFile(raftSetupConfig{DataDir: dir}, raft.DefaultConfig(), fsm, nil, nil, nil, nil, logger)
	if err == nil {
		t.Errorf("expected error for unreadable peers file")
	}
}

func TestSetupRaftStoreErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fsm := newPlacementFSM()

	// Bad log store
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "raft-log.bolt"), 0700) // directory where file should be
	_, err := setupRaft(raftSetupConfig{NodeID: "n1", DataDir: dir, BindAddr: "127.0.0.1:0"}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for bad log store")
	}

	// Bad stable store
	dir2 := t.TempDir()
	os.Mkdir(filepath.Join(dir2, "raft-stable.bolt"), 0700)
	_, err = setupRaft(raftSetupConfig{NodeID: "n1", DataDir: dir2, BindAddr: "127.0.0.1:0"}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for bad stable store")
	}

	// Bad recovery file causes error
	dir3 := t.TempDir()
	os.Mkdir(raftRecoveryPeersPath(dir3), 0700) // directory where peers.json should be
	_, err = setupRaft(raftSetupConfig{NodeID: "n1", DataDir: dir3, BindAddr: "127.0.0.1:0"}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for bad recovery peers file during setupRaft")
	}
}
