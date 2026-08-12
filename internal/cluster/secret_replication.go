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
	return pushSecretBlobToPeersLookup(ctx, c.gossip.lookupMember, c.httpClient, c.currentInternalClient(), c.patToken, c.nodeID, blob, recipients)
}

// DeleteSecretOnPeers DELETEs the sandbox's cluster_secrets rows on peers that
// may hold a fan-out copy. Returns acked vs still-pending recipients. Offline /
// missing peers stay pending — never treated as success.
func (c *Cluster) DeleteSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	if c == nil || c.gossip == nil || (c.httpClient == nil && c.currentInternalClient() == nil) {
		return nil, append([]string(nil), recipients...), nil
	}
	return deleteSecretOnPeersLookup(ctx, c.gossip.lookupMember, c.httpClient, c.currentInternalClient(), c.patToken, c.nodeID, sandboxID, recipients, generation)
}

// ProbeSecretOnPeers HEADs peer secret rows and returns nodes that currently
// hold seal_generation >= minGeneration (authoritative possession, not ACK memory).
func (c *Cluster) ProbeSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, minGeneration int64) (holding []string, err error) {
	if c == nil || c.gossip == nil || (c.httpClient == nil && c.currentInternalClient() == nil) {
		return nil, nil
	}
	return probeSecretOnPeersLookup(ctx, c.gossip.lookupMember, c.httpClient, c.currentInternalClient(), c.patToken, c.nodeID, sandboxID, recipients, minGeneration)
}

// Agent mirrors for worker nodes that seal locally and need to fan out.
func (a *Agent) PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error) {
	if a == nil || a.gossip == nil || (a.httpClient == nil && a.internalClient == nil) {
		return nil, nil
	}
	return pushSecretBlobToPeersLookup(ctx, a.gossip.lookupMember, a.httpClient, a.internalClient, a.patToken, a.nodeID, blob, recipients)
}

func (a *Agent) DeleteSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	if a == nil || a.gossip == nil || (a.httpClient == nil && a.internalClient == nil) {
		return nil, append([]string(nil), recipients...), nil
	}
	return deleteSecretOnPeersLookup(ctx, a.gossip.lookupMember, a.httpClient, a.internalClient, a.patToken, a.nodeID, sandboxID, recipients, generation)
}

func (a *Agent) ProbeSecretOnPeers(ctx context.Context, sandboxID string, recipients []string, minGeneration int64) (holding []string, err error) {
	if a == nil || a.gossip == nil || (a.httpClient == nil && a.internalClient == nil) {
		return nil, nil
	}
	return probeSecretOnPeersLookup(ctx, a.gossip.lookupMember, a.httpClient, a.internalClient, a.patToken, a.nodeID, sandboxID, recipients, minGeneration)
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

func pushSecretBlobToPeersLookup(ctx context.Context, lookup func(string) (Member, bool), publicClient, internalClient *http.Client, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	if (publicClient == nil && internalClient == nil) || len(recipients) == 0 || lookup == nil {
		return nil, nil
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("cluster: marshal secret blob: %w", err)
	}
	var acked []string
	var firstErr error
	expected := 0
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		expected++
		m, ok := lookup(id)
		if !ok || !m.Alive {
			// Mirror delete-path pending semantics: dead/missing peers are
			// incomplete, never silent success. Callers must keep put-outbox.
			if firstErr == nil {
				if !ok {
					firstErr = fmt.Errorf("fanout secret to %s: recipient unknown", id)
				} else {
					firstErr = fmt.Errorf("fanout secret to %s: recipient not alive", id)
				}
			}
			continue
		}
		client, endpoint, dialErr := PeerDialPath(m, publicClient, internalClient, PublicInternalSecretPath)
		if dialErr != nil || client == nil || endpoint == "" {
			if firstErr == nil {
				if dialErr != nil {
					firstErr = fmt.Errorf("fanout secret to %s: %w", id, dialErr)
				} else {
					firstErr = fmt.Errorf("fanout secret to %s: no dial path", id)
				}
			}
			continue
		}
		if err := withSecretFanoutBackoff(ctx, func() error {
			return postSecretBlob(ctx, client, endpoint, pat, selfID, body)
		}); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("fanout secret to %s: %w", m.NodeID, err)
			}
			continue
		}
		acked = append(acked, m.NodeID)
	}
	if len(acked) < expected && firstErr == nil {
		firstErr = fmt.Errorf("cluster: secret fan-out incomplete: acked %d/%d", len(acked), expected)
	}
	return acked, firstErr
}

func pushSecretBlobToPeersWithInternal(ctx context.Context, members []Member, publicClient, internalClient *http.Client, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID == "" {
			continue
		}
		byID[m.NodeID] = m
	}
	return pushSecretBlobToPeersLookup(ctx, func(id string) (Member, bool) {
		m, ok := byID[id]
		return m, ok
	}, publicClient, internalClient, pat, selfID, blob, recipients)
}

func deleteSecretOnPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	return deleteSecretOnPeersWithInternal(ctx, members, client, nil, pat, selfID, sandboxID, recipients, generation)
}

func deleteSecretOnPeersLookup(ctx context.Context, lookup func(string) (Member, bool), publicClient, internalClient *http.Client, pat, selfID, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	if (publicClient == nil && internalClient == nil) || strings.TrimSpace(sandboxID) == "" || lookup == nil {
		return nil, append([]string(nil), recipients...), nil
	}
	if generation <= 0 {
		generation = 1
	}
	path := PublicInternalSecretPath + "/" + url.PathEscape(sandboxID)
	var firstErr error
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		m, ok := lookup(id)
		if !ok || !m.Alive {
			pending = append(pending, id)
			continue
		}
		client, endpoint, dialErr := PeerDialPath(m, publicClient, internalClient, path)
		if dialErr != nil || client == nil || endpoint == "" {
			pending = append(pending, id)
			if firstErr == nil && dialErr != nil {
				firstErr = fmt.Errorf("delete secret on %s: %w", id, dialErr)
			}
			continue
		}
		endpoint += "?generation=" + strconv.FormatInt(generation, 10)
		if delErr := withSecretFanoutBackoff(ctx, func() error {
			return deleteSecretBlob(ctx, client, endpoint, pat, selfID)
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

func deleteSecretOnPeersWithInternal(ctx context.Context, members []Member, publicClient, internalClient *http.Client, pat, selfID, sandboxID string, recipients []string, generation int64) (acked, pending []string, err error) {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID == "" {
			continue
		}
		byID[m.NodeID] = m
	}
	return deleteSecretOnPeersLookup(ctx, func(id string) (Member, bool) {
		m, ok := byID[id]
		return m, ok
	}, publicClient, internalClient, pat, selfID, sandboxID, recipients, generation)
}

func probeSecretOnPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, sandboxID string, recipients []string, minGeneration int64) ([]string, error) {
	return probeSecretOnPeersWithInternal(ctx, members, client, nil, pat, selfID, sandboxID, recipients, minGeneration)
}

func probeSecretOnPeersLookup(ctx context.Context, lookup func(string) (Member, bool), publicClient, internalClient *http.Client, pat, selfID, sandboxID string, recipients []string, minGeneration int64) ([]string, error) {
	if (publicClient == nil && internalClient == nil) || strings.TrimSpace(sandboxID) == "" || lookup == nil {
		return nil, nil
	}
	if minGeneration <= 0 {
		minGeneration = 1
	}
	path := PublicInternalSecretPath + "/" + url.PathEscape(sandboxID)
	var holding []string
	var firstErr error
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		m, ok := lookup(id)
		if !ok || !m.Alive {
			continue
		}
		client, endpoint, dialErr := PeerDialPath(m, publicClient, internalClient, path)
		if dialErr != nil || client == nil || endpoint == "" {
			if firstErr == nil && dialErr != nil {
				firstErr = fmt.Errorf("probe secret on %s: %w", id, dialErr)
			}
			continue
		}
		endpoint += "?min_generation=" + strconv.FormatInt(minGeneration, 10)
		okHold, err := headSecretBlob(ctx, client, endpoint, pat, selfID)
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

func probeSecretOnPeersWithInternal(ctx context.Context, members []Member, publicClient, internalClient *http.Client, pat, selfID, sandboxID string, recipients []string, minGeneration int64) ([]string, error) {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	return probeSecretOnPeersLookup(ctx, func(id string) (Member, bool) {
		m, ok := byID[id]
		return m, ok
	}, publicClient, internalClient, pat, selfID, sandboxID, recipients, minGeneration)
}

func headSecretBlob(ctx context.Context, client *http.Client, endpoint, pat, selfID string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return false, err
	}
	SetPeerNodeIDHeader(req, selfID)
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

func postSecretBlob(ctx context.Context, client *http.Client, endpoint, pat, selfID string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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

func deleteSecretBlob(ctx context.Context, client *http.Client, endpoint, pat, selfID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	SetPeerNodeIDHeader(req, selfID)
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
