package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// jsBundlesPath is the public route the replication POST targets. Hardcoded
// (not imported from pkg/api/v1) to keep the cluster->api dependency one-way.
const jsBundlesPath = "/v1/js-bundles"

// ReplicateJSBundle fans a just-uploaded JS bundle out to every other live
// cluster member. Isolate's bundle store is per-node with no cluster
// distribution, so without this an isolate create placed on a node other than
// the upload node fails "bundle not found". Best-effort: an unreachable peer is
// returned as an error for the caller to log, but the bundle is already stored
// locally so replication failure is non-fatal to the upload. Idempotent (the
// content-addressed store dedups a re-push) and loop-safe (the replicated POST
// carries HeaderJSBundleReplicated so the receiver stores it without fanning
// out again). No-op with no peers (single-node / lone node).
func (c *Cluster) ReplicateJSBundle(ctx context.Context, owner string, req models.CreateJSBundleRequest) error {
	if c == nil || c.gossip == nil {
		return nil
	}
	return replicateJSBundleToPeers(ctx, c.gossip.members(), c.httpClient, c.patToken, c.nodeID, owner, req)
}

// ReplicateJSBundle mirrors *Cluster's for worker/ingress agents: an upload can
// land on any node (caddy routes /v1/js-bundles to whichever answers), so the
// fan-out must work from an agent too.
func (a *Agent) ReplicateJSBundle(ctx context.Context, owner string, req models.CreateJSBundleRequest) error {
	if a == nil || a.gossip == nil {
		return nil
	}
	return replicateJSBundleToPeers(ctx, a.gossip.members(), a.httpClient, a.patToken, a.nodeID, owner, req)
}

func replicateJSBundleToPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, owner string, req models.CreateJSBundleRequest) error {
	if client == nil {
		return nil
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("cluster: marshal js-bundle for replication: %w", err)
	}
	var firstErr error
	for _, m := range members {
		if m.NodeID == "" || m.NodeID == selfID || !m.Alive || m.APIURL == "" {
			continue
		}
		endpoint := strings.TrimRight(m.APIURL, "/") + jsBundlesPath
		if err := postJSBundleReplica(ctx, client, endpoint, pat, owner, body); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("replicate js-bundle to %s: %w", m.NodeID, err)
		}
	}
	return firstErr
}

func postJSBundleReplica(ctx context.Context, client *http.Client, endpoint, pat, owner string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(models.HeaderJSBundleReplicated, "1")
	req.Header.Set(models.HeaderJSBundleOwner, owner)
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
