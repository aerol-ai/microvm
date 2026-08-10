package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// secretFanoutMaxAttempts bounds async peer pushes / deletes. Create never
// waits on these; failures increment aerolvm_secret_fanout_failures_total.
const secretFanoutMaxAttempts = 4

// PushSecretBlobToPeers POSTs the sealed blob to each non-self recipient that
// is alive and advertises a reachable internal or public API URL. The internal
// mTLS transport is preferred whenever it is configured. Best-effort with
// bounded backoff; returns the
// node IDs that ACK'd (callers intersect with live membership for
// failover_ready). No-op when c is nil / has no gossip (Noop path never
// reaches here).
func (c *Cluster) PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error) {
	if c == nil || c.gossip == nil || (c.httpClient == nil && c.currentInternalClient() == nil) {
		return nil, nil
	}
	return pushSecretBlobToPeersWithInternal(ctx, c.gossip.members(), c.httpClient, c.currentInternalClient(), c.patToken, c.nodeID, blob, recipients)
}

// DeleteSecretOnPeers DELETEs the sandbox's cluster_secrets rows on peers that
// may hold a fan-out copy. Returns acked vs still-pending recipients. Offline /
// missing peers stay pending — never treated as success.
func (c *Cluster) DeleteSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	if c == nil || c.gossip == nil || (c.httpClient == nil && c.currentInternalClient() == nil) {
		return nil, append([]string(nil), recipients...), nil
	}
	return deleteSecretOnPeersWithInternal(ctx, c.gossip.members(), c.httpClient, c.currentInternalClient(), c.patToken, c.nodeID, sandboxID, recipients, generation)
}

// ProbeSecretOnPeers HEADs peer secret rows and returns nodes that currently
// hold seal_generation >= minGeneration (authoritative possession, not ACK memory).
func (c *Cluster) ProbeSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, minGeneration int64) (holding []string, err error) {
	if c == nil || c.gossip == nil || (c.httpClient == nil && c.currentInternalClient() == nil) {
		return nil, nil
	}
	return probeSecretOnPeersWithInternal(ctx, c.gossip.members(), c.httpClient, c.currentInternalClient(), c.patToken, c.nodeID, sandboxID, recipients, minGeneration)
}

// Agent mirrors for worker nodes that seal locally and need to fan out.
func (a *Agent) PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error) {
	if a == nil || a.gossip == nil || (a.httpClient == nil && a.internalClient == nil) {
		return nil, nil
	}
	return pushSecretBlobToPeersWithInternal(ctx, a.gossip.members(), a.httpClient, a.internalClient, a.patToken, a.nodeID, blob, recipients)
}

func (a *Agent) DeleteSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	if a == nil || a.gossip == nil || (a.httpClient == nil && a.internalClient == nil) {
		return nil, append([]string(nil), recipients...), nil
	}
	return deleteSecretOnPeersWithInternal(ctx, a.gossip.members(), a.httpClient, a.internalClient, a.patToken, a.nodeID, sandboxID, recipients, generation)
}

func (a *Agent) ProbeSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, minGeneration int64) (holding []string, err error) {
	if a == nil || a.gossip == nil || (a.httpClient == nil && a.internalClient == nil) {
		return nil, nil
	}
	return probeSecretOnPeersWithInternal(ctx, a.gossip.members(), a.httpClient, a.internalClient, a.patToken, a.nodeID, sandboxID, recipients, minGeneration)
}

// SecretPeerPusher is the narrow seam Service uses for async fan-out so tests
// can inject a fake without a full Cluster.
type SecretPeerPusher interface {
	PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error)
	DeleteSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error)
	ProbeSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, minGeneration int64) (holding []string, err error)
}

func pushSecretBlobToPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	return pushSecretBlobToPeersWithInternal(ctx, members, client, nil, pat, selfID, blob, recipients)
}

func pushSecretBlobToPeersWithInternal(ctx context.Context, members []Member, publicClient, internalClient *http.Client, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	if (publicClient == nil && internalClient == nil) || len(recipients) == 0 {
		return nil, nil
	}
	want := make(map[string]struct{}, len(recipients))
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		want[id] = struct{}{}
	}
	if len(want) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("cluster: marshal secret blob: %w", err)
	}
	// Index members by ID so create-path fan-out is O(recipients), not a full
	// membership scan per seal (critical at 2k-node / 100k-create bursts).
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID == "" {
			continue
		}
		byID[m.NodeID] = m
	}
	var acked []string
	var firstErr error
	for id := range want {
		m, ok := byID[id]
		if !ok || !m.Alive || (strings.TrimSpace(m.APIURL) == "" && strings.TrimSpace(m.InternalURL) == "") {
			continue
		}
		client, endpoint := secretPeerTransport(m, publicClient, internalClient, PublicInternalSecretPath)
		if client == nil || endpoint == "" {
			continue
		}
		if err := withSecretFanoutBackoff(ctx, func() error {
			return postSecretBlob(ctx, client, endpoint, pat, body)
		}); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("fanout secret to %s: %w", m.NodeID, err)
			}
			continue
		}
		acked = append(acked, m.NodeID)
	}
	return acked, firstErr
}

func deleteSecretOnPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	return deleteSecretOnPeersWithInternal(ctx, members, client, nil, pat, selfID, sandboxID, recipients, generation)
}

func deleteSecretOnPeersWithInternal(ctx context.Context, members []Member, publicClient, internalClient *http.Client, pat, selfID, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	if (publicClient == nil && internalClient == nil) || strings.TrimSpace(sandboxID) == "" {
		return nil, append([]string(nil), recipients...), nil
	}
	if generation <= 0 {
		generation = 1
	}
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID == "" {
			continue
		}
		byID[m.NodeID] = m
	}
	var firstErr error
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		m, ok := byID[id]
		if !ok || !m.Alive || (strings.TrimSpace(m.APIURL) == "" && strings.TrimSpace(m.InternalURL) == "") {
			pending = append(pending, id)
			continue
		}
		client, endpoint := secretPeerTransport(m, publicClient, internalClient, PublicInternalSecretPath+"/"+url.PathEscape(sandboxID))
		if client == nil || endpoint == "" {
			pending = append(pending, id)
			continue
		}
		endpoint += "?generation=" + strconv.FormatInt(generation, 10)
		if delErr := withSecretFanoutBackoff(ctx, func() error {
			return deleteSecretBlob(ctx, client, endpoint, pat)
		}); delErr != nil {
			pending = append(pending, id)
			if firstErr == nil {
				firstErr = fmt.Errorf("delete secret on %s: %w", id, delErr)
			}
			continue
		}
		acked = append(acked, id)
	}
	return acked, pending, firstErr
}

func probeSecretOnPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, sandboxID string, recipients []string, minGeneration int64) ([]string, error) {
	return probeSecretOnPeersWithInternal(ctx, members, client, nil, pat, selfID, sandboxID, recipients, minGeneration)
}

func probeSecretOnPeersWithInternal(ctx context.Context, members []Member, publicClient, internalClient *http.Client, pat, selfID, sandboxID string, recipients []string, minGeneration int64) ([]string, error) {
	if (publicClient == nil && internalClient == nil) || strings.TrimSpace(sandboxID) == "" {
		return nil, nil
	}
	if minGeneration <= 0 {
		minGeneration = 1
	}
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	var holding []string
	var firstErr error
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		m, ok := byID[id]
		if !ok || !m.Alive || (strings.TrimSpace(m.APIURL) == "" && strings.TrimSpace(m.InternalURL) == "") {
			continue
		}
		client, endpoint := secretPeerTransport(m, publicClient, internalClient, PublicInternalSecretPath+"/"+url.PathEscape(sandboxID))
		if client == nil || endpoint == "" {
			continue
		}
		endpoint += "?min_generation=" + strconv.FormatInt(minGeneration, 10)
		okHold, err := headSecretBlob(ctx, client, endpoint, pat)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("probe secret on %s: %w", id, err)
			}
			continue
		}
		if okHold {
			holding = append(holding, id)
		}
	}
	return holding, firstErr
}

// secretPeerTransport selects one transport before I/O. An advertised
// InternalURL is never retried over the public channel after an mTLS failure.
func secretPeerTransport(m Member, publicClient, internalClient *http.Client, path string) (*http.Client, string) {
	if internalClient != nil && strings.TrimSpace(m.InternalURL) != "" {
		return internalClient, strings.TrimRight(m.InternalURL, "/") + path
	}
	if publicClient != nil && strings.TrimSpace(m.APIURL) != "" {
		return publicClient, strings.TrimRight(m.APIURL, "/") + path
	}
	return nil, ""
}

func headSecretBlob(ctx context.Context, client *http.Client, endpoint, pat string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return false, err
	}
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, fmt.Errorf("peer %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
}

func withSecretFanoutBackoff(ctx context.Context, fn func() error) error {
	var last error
	backoff := 50 * time.Millisecond
	for attempt := 0; attempt < secretFanoutMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = fn()
		if last == nil {
			return nil
		}
		if attempt == secretFanoutMaxAttempts-1 {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
	return last
}

func postSecretBlob(ctx context.Context, client *http.Client, endpoint, pat string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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

func deleteSecretBlob(ctx context.Context, client *http.Client, endpoint, pat string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 404 is success — peer never held the row (partial fan-out / race).
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("peer %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
