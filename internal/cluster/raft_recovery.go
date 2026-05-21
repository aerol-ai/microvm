package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

const raftRecoveryPeersFilename = "peers.json"

type raftRecoveryPeer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	NonVoter bool   `json:"non_voter"`
	Suffrage string `json:"suffrage"`
}

func maybeRecoverRaftClusterFromPeersFile(
	cfg raftSetupConfig,
	rcfg *raft.Config,
	fsm *placementFSM,
	logStore *raftboltdb.BoltStore,
	stableStore *raftboltdb.BoltStore,
	snaps raft.SnapshotStore,
	transport raft.Transport,
	logger *slog.Logger,
) error {
	path := raftRecoveryPeersPath(cfg.DataDir)
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("raft recovery: read %s: %w", path, err)
	}
	configuration, err := raftConfigurationFromPeersJSON(payload)
	if err != nil {
		return fmt.Errorf("raft recovery: parse %s: %w", path, err)
	}
	recoveryFSM := newPlacementFSMWithRecoveryStore(fsm.recoveryStore)
	if err := raft.RecoverCluster(rcfg, recoveryFSM, logStore, stableStore, snaps, transport, configuration); err != nil {
		return fmt.Errorf("raft recovery: recover cluster from %s: %w", path, err)
	}
	appliedPath := path + ".applied." + strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.Rename(path, appliedPath); err != nil {
		return fmt.Errorf("raft recovery: mark %s applied: %w", path, err)
	}
	if logger != nil {
		logger.Warn("raft lost-quorum recovery peers file applied",
			"path", path,
			"applied_path", appliedPath,
			"servers", len(configuration.Servers),
		)
	}
	return nil
}

func raftRecoveryPeersPath(dataDir string) string {
	return filepath.Join(dataDir, raftRecoveryPeersFilename)
}

func raftConfigurationFromPeersJSON(payload []byte) (raft.Configuration, error) {
	var peers []raftRecoveryPeer
	if err := json.Unmarshal(payload, &peers); err != nil {
		return raft.Configuration{}, err
	}
	if len(peers) == 0 {
		return raft.Configuration{}, fmt.Errorf("no peers in recovery file")
	}
	servers := make([]raft.Server, 0, len(peers))
	seen := make(map[raft.ServerID]struct{}, len(peers))
	for _, peer := range peers {
		id := raft.ServerID(strings.TrimSpace(peer.ID))
		address := raft.ServerAddress(strings.TrimSpace(peer.Address))
		if id == "" || address == "" {
			return raft.Configuration{}, fmt.Errorf("peer id and address are required")
		}
		if _, ok := seen[id]; ok {
			return raft.Configuration{}, fmt.Errorf("duplicate peer id %q", id)
		}
		seen[id] = struct{}{}
		suffrage, err := peerSuffrage(peer)
		if err != nil {
			return raft.Configuration{}, err
		}
		servers = append(servers, raft.Server{
			ID:       id,
			Address:  address,
			Suffrage: suffrage,
		})
	}
	return raft.Configuration{Servers: servers}, nil
}

func peerSuffrage(peer raftRecoveryPeer) (raft.ServerSuffrage, error) {
	if peer.NonVoter {
		return raft.Nonvoter, nil
	}
	switch strings.ToLower(strings.TrimSpace(peer.Suffrage)) {
	case "", "voter":
		return raft.Voter, nil
	case "nonvoter", "non_voter", "non-voter":
		return raft.Nonvoter, nil
	case "staging":
		return raft.Staging, nil
	default:
		return raft.Voter, fmt.Errorf("invalid suffrage %q for peer %q", peer.Suffrage, peer.ID)
	}
}
