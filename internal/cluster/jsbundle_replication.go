package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// PublicInternalJSBundlesPath is mounted only with the internal peer
	// authorization middleware. Public callers must never be able to assert an
	// arbitrary replica owner or suppress fan-out with a header.
	PublicInternalJSBundlesPath = "/v1/cluster/internal/js-bundles"

	// Bound upload latency and socket pressure when a bundle must reach a large
	// isolate-worker tier. Work remains O(eligible workers) because stores are
	// node-local, but it is no longer serialized across the fleet.
	jsBundleReplicationConcurrency = 32
)

// ReplicateJSBundle fans a just-uploaded JS bundle out to every other live
// isolate worker. Isolate's bundle store is per-node with no cluster
// distribution, so without this an isolate create placed on a node other than
// the upload node fails "bundle not found". An unreachable peer is returned
// to the service; enterprise mode fails the upload while self-hosted mode logs
// the partial replication. Retries are safe because the content-addressed
// store deduplicates the local write. Replication is loop-safe (replicas use a
// dedicated internal handler that never re-fans out). No-op with no peers
// (single-node / lone node).
func (c *Cluster) ReplicateJSBundle(ctx context.Context, owner string, req models.CreateJSBundleRequest) error {
	if c == nil || c.gossip == nil {
		return nil
	}
	return replicateJSBundleToPeers(ctx, c.gossip.members(), c.PeerDialMember, c.patToken, c.nodeID, owner, req)
}

// ReplicateJSBundle mirrors *Cluster's for worker/ingress agents: an upload can
// land on any node (caddy routes /v1/js-bundles to whichever answers), so the
// fan-out must work from an agent too.
func (a *Agent) ReplicateJSBundle(ctx context.Context, owner string, req models.CreateJSBundleRequest) error {
	if a == nil || a.gossip == nil {
		return nil
	}
	return replicateJSBundleToPeers(ctx, a.gossip.members(), a.PeerDialMember, a.patToken, a.nodeID, owner, req)
}

func replicateJSBundleToPeers(ctx context.Context, members []Member, dial peerMemberDialer, pat, selfID, owner string, req models.CreateJSBundleRequest) error {
	if dial == nil {
		return nil
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("cluster: marshal js-bundle for replication: %w", err)
	}
	targets := make([]Member, 0, len(members))
	for _, m := range members {
		if !jsBundleReplicaTarget(m, selfID) {
			continue
		}
		targets = append(targets, m)
	}
	if len(targets) == 0 {
		return nil
	}

	errs := make([]error, len(targets))
	jobs := make(chan int, len(targets))
	for i := range targets {
		jobs <- i
	}
	close(jobs)

	workers := min(jsBundleReplicationConcurrency, len(targets))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				m := targets[i]
				client, base, err := dial(m)
				if err == nil && client == nil {
					err = errors.New("peer mTLS client unavailable")
				}
				if err == nil {
					endpoint := strings.TrimRight(base, "/") + PublicInternalJSBundlesPath
					err = postJSBundleReplica(ctx, client, endpoint, pat, selfID, owner, body)
				}
				if err != nil {
					errs[i] = fmt.Errorf("replicate js-bundle to %s: %w", m.NodeID, err)
				}
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func jsBundleReplicaTarget(m Member, selfID string) bool {
	if m.NodeID == "" || m.NodeID == selfID || !m.Alive || m.InternalURL == "" || strings.TrimSpace(m.Role) == "" || !CanOwnSandboxRole(m.Role) {
		return false
	}
	for _, runtimeName := range m.Capacity.SupportedRuntimes {
		if strings.TrimSpace(runtimeName) == models.RuntimeIsolate {
			return true
		}
	}
	return false
}

func postJSBundleReplica(ctx context.Context, client *http.Client, endpoint, pat, selfID, owner string, body []byte) error {
	if client == nil {
		return errors.New("peer mTLS client unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(models.HeaderJSBundleOwner, owner)
	SetPeerNodeIDHeader(req, selfID)
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("peer %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
