package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Run by hand on a Raft server, `sandboxd upgrade node` takes the same two
// safety steps the rollout leader takes before it restarts a server
// (plans/kubectl-style-cluster-ops.md §6.2, §6.3 last paragraph):
//
//  1. It refuses when the voters left up would not be a majority, so a
//     hand-run upgrade never loses quorum while a safer order exists (bring
//     the down servers back first). --allow-downtime overrides it. A
//     cluster with ONE voting server only warns: it has no way to upgrade
//     without the API going down, and refusing would break the documented
//     `install.sh` re-run on it. `aerolvm upgrade apply` still asks for
//     --allow-downtime there (eng D8).
//  2. If this node leads, it hands leadership to another voter first, so
//     the cluster is not leaderless while sandboxd restarts.
//
// It asks the local sandboxd over its API, as `sandboxd key rotate` does,
// because only a server's Raft view knows who votes and who leads. The
// voters come from the Raft configuration (raft_voters), not the member
// list: gossip drops a node that has been down a while, so with 5 voters
// and 2 long dead it would see 3 of 3 up and allow a stop that leaves 2
// of 5.

// stopGuardTimeout bounds each call to the local daemon.
const stopGuardTimeout = 15 * time.Second

// stopGuardAPI is the local daemon's API: the members list and the leader
// hand-off. Tests replace newStopGuardAPI.
type stopGuardAPI interface {
	// ClusterMode asks /health whether the running daemon is in cluster
	// mode: the env files alone can be overridden by a systemd drop-in.
	ClusterMode(ctx context.Context) (bool, error)
	Members(ctx context.Context) (memberList, error)
	TransferLeadership(ctx context.Context) (upgradewire.LeaderTransferResponse, error)
}

// memberList is the local daemon's GET /v1/cluster/members answer.
type memberList struct {
	Members []cluster.Member `json:"members"`
	// RaftVoters is the Raft configuration's voters. nil means the daemon
	// did not send it (a build from before the field).
	RaftVoters []string `json:"raft_voters"`
}

// stopGuardEnv is what the guard reads from the node's env files.
type stopGuardEnv struct {
	cluster bool
	nodeID  string
	apiURL  string
	pat     string
}

// readStopGuardEnv reads sandboxd.env, then cluster.env beside it (a later
// file wins, as systemd loads them).
func readStopGuardEnv(envFile string) stopGuardEnv {
	env := map[string]string{}
	for _, p := range []string{envFile, filepath.Join(filepath.Dir(envFile), "cluster.env")} {
		m, err := nodeupgrade.ReadEnvFile(p)
		if err != nil {
			continue
		}
		for k, v := range m {
			env[k] = v
		}
	}
	host := strings.TrimSpace(env["SB_API_HOST"])
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	port := strings.TrimSpace(env["SB_API_PORT"])
	if port == "" {
		port = "21212"
	}
	return stopGuardEnv{
		cluster: strings.EqualFold(strings.TrimSpace(env["SB_ENABLE_CLUSTER"]), "true") || strings.TrimSpace(env["SB_ENABLE_CLUSTER"]) == "1",
		nodeID:  strings.TrimSpace(env["SB_NODE_ID"]),
		apiURL:  "http://" + net.JoinHostPort(host, port),
		pat:     strings.TrimSpace(env["SB_PAT_TOKEN"]),
	}
}

var newStopGuardAPI = func(e stopGuardEnv) stopGuardAPI {
	return &localAPI{base: e.apiURL, pat: e.pat, http: &http.Client{Timeout: stopGuardTimeout}}
}

// serverStopGuard returns the Upgrader.BeforeStop hook for this node. It is
// a no-op off cluster mode and on members that do not vote.
func serverStopGuard(paths nodeupgrade.Paths, out io.Writer) func(context.Context, bool) error {
	return func(ctx context.Context, allowDowntime bool) error {
		e := readStopGuardEnv(paths.EnvFile)
		if !e.cluster {
			return nil
		}
		api := newStopGuardAPI(e)
		// The env files say cluster mode, but a later drop-in may turn it
		// off (a node taken out of its cluster). The running daemon is the
		// truth; when it can't be asked, keep the safe answer and check.
		if inCluster, err := api.ClusterMode(ctx); err == nil && !inCluster {
			return nil
		}
		return guardServerStop(ctx, e, api, allowDowntime, out)
	}
}

func guardServerStop(ctx context.Context, e stopGuardEnv, api stopGuardAPI, allowDowntime bool, out io.Writer) error {
	list, err := api.Members(ctx)
	if err != nil {
		if allowDowntime {
			fmt.Fprintf(out, "warning: could not check quorum before stopping sandboxd (--allow-downtime given): %v\n", err)
			return nil
		}
		return fmt.Errorf("refusing to stop sandboxd: cannot ask the local sandboxd who votes and who leads, so quorum cannot be checked (pass --allow-downtime to stop it anyway): %w", err)
	}
	var self *cluster.Member
	alive := map[string]bool{}
	for i := range list.Members {
		m := &list.Members[i]
		alive[m.NodeID] = m.Alive
		if m.NodeID == e.nodeID {
			self = m
		}
	}
	voters := list.RaftVoters
	if voters == nil {
		// An older daemon: the gossip view is all there is, and it misses
		// a voter gossip has forgotten. Say so rather than refuse, so the
		// documented install.sh re-run keeps working on it.
		fmt.Fprintf(out, "warning: the local sandboxd does not list the Raft voters; counting voters from gossip, which leaves out servers that have been down a while\n")
		for _, m := range list.Members {
			if m.Voter {
				voters = append(voters, m.NodeID)
			}
		}
	}
	selfVotes := slices.Contains(voters, e.nodeID)
	if self == nil && selfVotes {
		// Gossip always lists the node it runs on; if it does not, this
		// node is still the one about to stop.
		self = &cluster.Member{NodeID: e.nodeID, Alive: true, Voter: true}
		alive[e.nodeID] = true
	}
	if self == nil {
		if allowDowntime {
			return nil
		}
		return fmt.Errorf("refusing to stop sandboxd: node %q is not in the local member list, so quorum cannot be checked (pass --allow-downtime to stop it anyway)", e.nodeID)
	}
	if !selfVotes {
		return nil
	}
	up := 0
	var down []string
	for _, id := range voters {
		if alive[id] {
			up++
		} else {
			down = append(down, id)
		}
	}
	sort.Strings(down)
	majority := len(voters)/2 + 1
	if left := up - 1; left < majority {
		msg := fmt.Sprintf("stopping %s leaves %d of %d voting servers up, and Raft needs %d", e.nodeID, left, len(voters), majority)
		if len(down) > 0 {
			msg += "; these servers are down: " + strings.Join(down, ", ")
		}
		switch {
		case len(voters) == 1:
			fmt.Fprintf(out, "warning: %s is the only voting server; the cluster API is down until sandboxd is back\n", e.nodeID)
		case !allowDowntime:
			return fmt.Errorf("refusing to stop sandboxd: %s. The cluster API would stop answering until it is back. Bring the down servers back first, or pass --allow-downtime", msg)
		default:
			fmt.Fprintf(out, "warning: %s; going on because --allow-downtime was given\n", msg)
		}
	}
	if !self.Leader || len(voters) < 2 || up < 2 {
		return nil
	}
	resp, err := api.TransferLeadership(ctx)
	switch {
	case err != nil && allowDowntime:
		fmt.Fprintf(out, "warning: could not hand off leadership before stopping sandboxd (--allow-downtime given): %v\n", err)
		return nil
	case err != nil:
		return fmt.Errorf("refusing to stop sandboxd: this node leads and handing leadership to another server failed (pass --allow-downtime to stop it anyway): %w", err)
	case resp.Leader == e.nodeID:
		if allowDowntime {
			return nil
		}
		return fmt.Errorf("refusing to stop sandboxd: this node still leads after the hand-off; retry, or pass --allow-downtime")
	}
	fmt.Fprintf(out, "handed leadership to %s (term %d)\n", resp.Leader, resp.Term)
	return nil
}

// localAPI calls this node's own sandboxd with the node's PAT.
type localAPI struct {
	base string
	pat  string
	http *http.Client
}

func (a *localAPI) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, stopGuardTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return err
	}
	if a.pat != "" {
		req.Header.Set("Authorization", "Bearer "+a.pat)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	return nil
}

func (a *localAPI) ClusterMode(ctx context.Context) (bool, error) {
	var h struct {
		Version         string `json:"version"`
		ClusterTopology string `json:"cluster_topology"`
		ClusterNodes    int    `json:"cluster_nodes"`
	}
	if err := a.do(ctx, http.MethodGet, "/health", nil, &h); err != nil {
		return false, err
	}
	if h.Version == "" {
		return false, errors.New("the local sandboxd's /health has no version")
	}
	return h.ClusterTopology != "" || h.ClusterNodes > 0, nil
}

func (a *localAPI) Members(ctx context.Context) (memberList, error) {
	var body memberList
	if err := a.do(ctx, http.MethodGet, "/v1/cluster/members", nil, &body); err != nil {
		return memberList{}, err
	}
	if body.Members == nil {
		return memberList{}, errors.New("the local sandboxd listed no members")
	}
	return body, nil
}

func (a *localAPI) TransferLeadership(ctx context.Context) (upgradewire.LeaderTransferResponse, error) {
	var out upgradewire.LeaderTransferResponse
	err := a.do(ctx, http.MethodPost, upgradewire.ClusterLeaderTransferPath, upgradewire.LeaderTransferRequest{}, &out)
	return out, err
}
