package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// secretFanoutMaxAttempts bounds peer pushes and deletes. HA create may wait
// for the first backup under its own deadline; remaining fan-out is async.
const secretFanoutMaxAttempts = 4

type peerMemberDialer func(Member) (*http.Client, string, error)

// PushSecretBlobToPeers POSTs the sealed blob to each non-self recipient that
// is alive and advertises a reachable internal mTLS URL. Best-effort with
// bounded backoff; returns the
// node IDs that ACK'd (callers intersect with live membership for
// failover_ready). Missing cluster transport is reported for any remote target;
// self-only single-node calls remain a no-op.
func (c *Cluster) PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error) {
	if c == nil {
		if hasRemoteSecretRecipient(recipients, "") {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	if c.gossip == nil {
		if hasRemoteSecretRecipient(recipients, c.nodeID) {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	return pushSecretBlobToPeersLookupDial(ctx, c.gossip.lookupMember, c.currentInternalClient(), c.PeerDialMember, c.patToken, c.nodeID, blob, recipients)
}

// DeleteSecretOnPeers DELETEs the sandbox's cluster_secrets rows on peers that
// may hold a fan-out copy. It returns only authenticated acknowledgements;
// callers derive pending recipients from requested minus acknowledged so an
// incomplete transport response can never erase a durable delete obligation.
func (c *Cluster) DeleteSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, generation int64) (acked []string, err error) {
	if c == nil {
		if hasRemoteSecretRecipient(recipients, "") {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	if c.gossip == nil {
		if hasRemoteSecretRecipient(recipients, c.nodeID) {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	return deleteSecretOnPeersLookupDial(ctx, c.gossip.lookupMember, c.currentInternalClient(), c.PeerDialMember, c.patToken, c.nodeID, sandboxID, incarnationID, recipients, generation)
}

// ProbeSecretOnPeers HEADs peer secret rows and returns nodes that currently
// hold seal_generation >= minGeneration (authoritative possession, not ACK memory).
func (c *Cluster) ProbeSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, minGeneration int64) (holding []string, err error) {
	if c == nil {
		if hasRemoteSecretRecipient(recipients, "") {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	if c.gossip == nil {
		if hasRemoteSecretRecipient(recipients, c.nodeID) {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	return probeSecretOnPeersLookupDial(ctx, c.gossip.lookupMember, c.currentInternalClient(), c.PeerDialMember, c.patToken, c.nodeID, sandboxID, incarnationID, recipients, minGeneration)
}

// Agent mirrors for worker nodes that seal locally and need to fan out.
func (a *Agent) PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error) {
	if a == nil {
		if hasRemoteSecretRecipient(recipients, "") {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	if a.gossip == nil {
		if hasRemoteSecretRecipient(recipients, a.nodeID) {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	return pushSecretBlobToPeersLookupDial(ctx, a.gossip.lookupMember, a.internalClient, a.PeerDialMember, a.patToken, a.nodeID, blob, recipients)
}

func (a *Agent) DeleteSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, generation int64) (acked []string, err error) {
	if a == nil {
		if hasRemoteSecretRecipient(recipients, "") {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	if a.gossip == nil {
		if hasRemoteSecretRecipient(recipients, a.nodeID) {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	return deleteSecretOnPeersLookupDial(ctx, a.gossip.lookupMember, a.internalClient, a.PeerDialMember, a.patToken, a.nodeID, sandboxID, incarnationID, recipients, generation)
}

func (a *Agent) ProbeSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, minGeneration int64) (holding []string, err error) {
	if a == nil {
		if hasRemoteSecretRecipient(recipients, "") {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	if a.gossip == nil {
		if hasRemoteSecretRecipient(recipients, a.nodeID) {
			return nil, ErrPeerInternalURLRequired
		}
		return nil, nil
	}
	return probeSecretOnPeersLookupDial(ctx, a.gossip.lookupMember, a.internalClient, a.PeerDialMember, a.patToken, a.nodeID, sandboxID, incarnationID, recipients, minGeneration)
}

// SecretPeerPusher is the narrow seam Service uses for async fan-out so tests
// can inject a fake without a full Cluster.
type SecretPeerPusher interface {
	PushSecretBlobToPeers(ctx context.Context, blob secrets.SecretBlob, recipients []string) (ackedNodes []string, err error)
	DeleteSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, generation int64) (acked []string, err error)
	ProbeSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, minGeneration int64) (holding []string, err error)
}

func hasRemoteSecretRecipient(recipients []string, selfID string) bool {
	selfID = strings.TrimSpace(selfID)
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id != "" && id != selfID {
			return true
		}
	}
	return false
}

func pushSecretBlobToPeers(ctx context.Context, members []Member, internalClient *http.Client, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	return pushSecretBlobToPeersLookup(ctx, func(id string) (Member, bool) {
		m, ok := byID[id]
		return m, ok
	}, internalClient, pat, selfID, blob, recipients)
}

func pushSecretBlobToPeersLookup(ctx context.Context, lookup func(string) (Member, bool), internalClient *http.Client, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	return pushSecretBlobToPeersLookupDial(ctx, lookup, internalClient, nil, pat, selfID, blob, recipients)
}

func pushSecretBlobToPeersLookupDial(ctx context.Context, lookup func(string) (Member, bool), internalClient *http.Client, dial peerMemberDialer, pat, selfID string, blob secrets.SecretBlob, recipients []string) ([]string, error) {
	if len(recipients) == 0 || lookup == nil {
		return nil, nil
	}
	if internalClient == nil && dial == nil {
		return nil, ErrPeerInternalURLRequired
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
		var client *http.Client
		var base string
		var dialErr error
		if dial != nil {
			client, base, dialErr = dial(m)
		} else {
			client, base, dialErr = PeerDial(m, internalClient)
		}
		endpoint := strings.TrimRight(base, "/") + PublicInternalSecretPath
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

func deleteSecretOnPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, sandboxID, incarnationID string, recipients []string, generation int64) (acked []string, err error) {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	return deleteSecretOnPeersLookup(ctx, func(id string) (Member, bool) {
		m, ok := byID[id]
		return m, ok
	}, client, pat, selfID, sandboxID, incarnationID, recipients, generation)
}

func deleteSecretOnPeersLookup(ctx context.Context, lookup func(string) (Member, bool), internalClient *http.Client, pat, selfID, sandboxID, incarnationID string, recipients []string, generation int64) (acked []string, err error) {
	return deleteSecretOnPeersLookupDial(ctx, lookup, internalClient, nil, pat, selfID, sandboxID, incarnationID, recipients, generation)
}

func deleteSecretOnPeersLookupDial(ctx context.Context, lookup func(string) (Member, bool), internalClient *http.Client, dial peerMemberDialer, pat, selfID, sandboxID, incarnationID string, recipients []string, generation int64) (acked []string, err error) {
	if strings.TrimSpace(sandboxID) == "" || lookup == nil {
		return nil, nil
	}
	if internalClient == nil && dial == nil {
		return nil, ErrPeerInternalURLRequired
	}
	if generation <= 0 {
		return nil, errors.New("cluster: secret delete generation must be positive")
	}
	incarnationID = strings.TrimSpace(incarnationID)
	if incarnationID == "" {
		return nil, errors.New("cluster: secret delete incarnation_id is required")
	}
	path := PublicInternalSecretPath + "/" + url.PathEscape(sandboxID)
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
			if firstErr == nil {
				if !ok {
					firstErr = fmt.Errorf("delete secret on %s: recipient unknown", id)
				} else {
					firstErr = fmt.Errorf("delete secret on %s: recipient not alive", id)
				}
			}
			continue
		}
		var client *http.Client
		var base string
		var dialErr error
		if dial != nil {
			client, base, dialErr = dial(m)
		} else {
			client, base, dialErr = PeerDial(m, internalClient)
		}
		endpoint := strings.TrimRight(base, "/") + path
		if dialErr != nil || client == nil || endpoint == "" {
			if firstErr == nil {
				if dialErr != nil {
					firstErr = fmt.Errorf("delete secret on %s: %w", id, dialErr)
				} else {
					firstErr = fmt.Errorf("delete secret on %s: no dial path", id)
				}
			}
			continue
		}
		query := url.Values{}
		query.Set("generation", strconv.FormatInt(generation, 10))
		query.Set("incarnation_id", incarnationID)
		endpoint += "?" + query.Encode()
		if delErr := withSecretFanoutBackoff(ctx, func() error {
			return deleteSecretBlob(ctx, client, endpoint, pat, selfID)
		}); delErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete secret on %s: %w", id, delErr)
			}
			continue
		}
		acked = append(acked, id)
	}
	if len(acked) < expected && firstErr == nil {
		firstErr = fmt.Errorf("cluster: secret delete incomplete: acked %d/%d", len(acked), expected)
	}
	return acked, firstErr
}

func probeSecretOnPeers(ctx context.Context, members []Member, client *http.Client, pat, selfID, sandboxID, incarnationID string, recipients []string, minGeneration int64) ([]string, error) {
	byID := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	return probeSecretOnPeersLookup(ctx, func(id string) (Member, bool) {
		m, ok := byID[id]
		return m, ok
	}, client, pat, selfID, sandboxID, incarnationID, recipients, minGeneration)
}

func probeSecretOnPeersLookup(ctx context.Context, lookup func(string) (Member, bool), internalClient *http.Client, pat, selfID, sandboxID, incarnationID string, recipients []string, minGeneration int64) ([]string, error) {
	return probeSecretOnPeersLookupDial(ctx, lookup, internalClient, nil, pat, selfID, sandboxID, incarnationID, recipients, minGeneration)
}

func probeSecretOnPeersLookupDial(ctx context.Context, lookup func(string) (Member, bool), internalClient *http.Client, dial peerMemberDialer, pat, selfID, sandboxID, incarnationID string, recipients []string, minGeneration int64) ([]string, error) {
	if strings.TrimSpace(sandboxID) == "" || lookup == nil {
		return nil, nil
	}
	if internalClient == nil && dial == nil {
		return nil, ErrPeerInternalURLRequired
	}
	if minGeneration <= 0 {
		return nil, errors.New("cluster: secret probe generation must be positive")
	}
	incarnationID = strings.TrimSpace(incarnationID)
	if incarnationID == "" {
		return nil, errors.New("cluster: secret probe incarnation id is required")
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
		var client *http.Client
		var base string
		var dialErr error
		if dial != nil {
			client, base, dialErr = dial(m)
		} else {
			client, base, dialErr = PeerDial(m, internalClient)
		}
		endpoint := strings.TrimRight(base, "/") + path
		if dialErr != nil || client == nil || endpoint == "" {
			if firstErr == nil && dialErr != nil {
				firstErr = fmt.Errorf("probe secret on %s: %w", id, dialErr)
			}
			continue
		}
		query := url.Values{}
		query.Set("incarnation_id", incarnationID)
		query.Set("min_generation", strconv.FormatInt(minGeneration, 10))
		endpoint += "?" + query.Encode()
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
