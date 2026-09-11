package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"golang.org/x/sync/singleflight"
)

// Cluster-wide catalogue lists for per-worker artifacts (Firecracker
// templates, JS bundles). The artifact lives on the worker that built or
// received it and nowhere else, so an ingress node has none of them: a
// complete list has to ask the workers that can hold one. Every such list
// shares one shape, and this file is that shape:
//
//   - ingress forwards to the Raft leader so there is one aggregator;
//   - the leader answers from a short cache, and concurrent callers share one
//     sweep through singleflight;
//   - the sweep asks only workers that advertise the artifact's runtime, with
//     bounded parallelism and a per-peer deadline, and counts every peer that
//     did not answer so a partial result is never silently short.
//
// Cost is O(eligible workers) per uncached sweep, not O(fleet) and not
// O(artifacts). If a catalogue ever becomes hot, the next step is recording
// its metadata on the leader at write time — not replicating bytes.

const (
	clusterListConcurrency  = 64
	clusterListMaxBytes     = 16 << 20
	clusterListPeerTimeout  = 5 * time.Second
	clusterListSweepTimeout = 10 * time.Second
	clusterListCacheTTL     = 2 * time.Second
)

// clusterListAggregate is one merged sweep.
type clusterListAggregate[T any] struct {
	rows        []T
	failedPeers int
}

// clusterListCache holds the last sweep for clusterListCacheTTL and coalesces
// concurrent misses.
type clusterListCache[T any] struct {
	mu      sync.RWMutex
	expires time.Time
	value   clusterListAggregate[T]
	group   singleflight.Group
}

func (c *clusterListCache[T]) get(now time.Time) (clusterListAggregate[T], bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.expires.IsZero() || !now.Before(c.expires) {
		return clusterListAggregate[T]{}, false
	}
	return c.value, true
}

func (c *clusterListCache[T]) put(now time.Time, value clusterListAggregate[T]) {
	c.mu.Lock()
	c.value = value
	c.expires = now.Add(clusterListCacheTTL)
	c.mu.Unlock()
}

// cached returns the cached sweep or runs one, sharing it with every caller
// that arrives while it is in flight. The sweep runs on its own context so
// the first ingress caller leaving does not abort work others are waiting on.
func (c *clusterListCache[T]) cached(r *http.Request, sweep func(*http.Request) (clusterListAggregate[T], error)) (clusterListAggregate[T], error) {
	if v, ok := c.get(time.Now()); ok {
		return v, nil
	}
	value, err, _ := c.group.Do("all", func() (any, error) {
		if v, ok := c.get(time.Now()); ok {
			return v, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), clusterListSweepTimeout)
		defer cancel()
		request := r.Clone(ctx)
		request.Header = r.Header.Clone()
		aggregate, err := sweep(request)
		if err != nil {
			return clusterListAggregate[T]{}, err
		}
		c.put(time.Now(), aggregate)
		return aggregate, nil
	})
	if err != nil {
		return clusterListAggregate[T]{}, err
	}
	return value.(clusterListAggregate[T]), nil
}

// clusterRuntimeMemberEligible identifies workers whose local catalogue for
// runtimeName belongs in the cluster view: sandbox-owning roles that
// advertise the runtime, excluding self (self is listed locally). Drain state
// intentionally does not apply: draining prevents new placement, not
// administration of artifacts the worker already holds.
func clusterRuntimeMemberEligible(c cluster.Client, member cluster.Member, runtimeName string) bool {
	return c != nil && member.NodeID != "" && member.NodeID != c.SelfNodeID() &&
		clusterMemberCanOwnSandbox(member.Role) &&
		clusterMemberSupportsRuntime(member, runtimeName)
}

// clusterRuntimePeers returns the eligible workers that can be asked now.
func clusterRuntimePeers(c cluster.Client, runtimeName string) []cluster.Member {
	if c == nil {
		return nil
	}
	out := make([]cluster.Member, 0)
	for _, m := range c.Members() {
		if !clusterRuntimeMemberEligible(c, m, runtimeName) || !m.Alive || strings.TrimSpace(m.InternalURL) == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

// clusterRuntimeUnavailablePeerCount counts eligible workers that cannot be
// asked (dead or without an internal endpoint). They are reported as missing
// coverage rather than pretended absent.
func clusterRuntimeUnavailablePeerCount(c cluster.Client, runtimeName string) int {
	if c == nil {
		return 0
	}
	count := 0
	for _, m := range c.Members() {
		if !clusterRuntimeMemberEligible(c, m, runtimeName) {
			continue
		}
		if !m.Alive || strings.TrimSpace(m.InternalURL) == "" {
			count++
		}
	}
	return count
}

type clusterListPeerResult[T any] struct {
	peerID string
	rows   []T
	err    error
}

// clusterListFromPeers re-issues the caller's GET to each peer with
// forwardedHeader set (so the peer answers locally and never re-fans-out) and
// the caller's Authorization (so each peer applies its own owner scoping).
func clusterListFromPeers[T any](parent *http.Request, c cluster.Client, peers []cluster.Member, forwardedHeader string) <-chan clusterListPeerResult[T] {
	results := make(chan clusterListPeerResult[T], len(peers))
	if len(peers) == 0 {
		close(results)
		return results
	}
	workers := min(clusterListConcurrency, len(peers))
	jobs := make(chan cluster.Member)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for peer := range jobs {
				rows, err := clusterListFromPeer[T](parent, c, peer, forwardedHeader)
				results <- clusterListPeerResult[T]{peerID: peer.NodeID, rows: rows, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, peer := range peers {
			select {
			case jobs <- peer:
			case <-parent.Context().Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func clusterListFromPeer[T any](parent *http.Request, c cluster.Client, peer cluster.Member, forwardedHeader string) ([]T, error) {
	client, base, err := dialClusterPeer(c, peer)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent.Context(), clusterListPeerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+parent.URL.RequestURI(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(forwardedHeader, "1")
	cluster.SetPeerNodeIDHeader(req, c.SelfNodeID())
	if auth := parent.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rows []T
	dec := json.NewDecoder(io.LimitReader(resp.Body, clusterListMaxBytes+1))
	if err := dec.Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// clusterListSweep merges the local rows with every eligible peer's rows,
// deduplicated by key (local wins), and reports how many eligible peers did
// not contribute. The sweep context may expire before every peer is
// dispatched; each undispatched peer still counts as missing.
func clusterListSweep[T any](r *http.Request, c cluster.Client, runtimeName, forwardedHeader string,
	local []T, localErr error, key func(T) string, logger interface {
		Warn(string, ...any)
	}, what string,
) (clusterListAggregate[T], error) {
	peers := clusterRuntimePeers(c, runtimeName)
	unavailable := clusterRuntimeUnavailablePeerCount(c, runtimeName)
	if localErr != nil && logger != nil {
		logger.Warn("cluster "+what+": local list failed", "err", localErr)
	}
	merged := make([]T, 0, len(local))
	seen := map[string]struct{}{}
	for _, row := range local {
		k := key(row)
		if k == "" {
			continue
		}
		seen[k] = struct{}{}
		merged = append(merged, row)
	}
	successful := 0
	for result := range clusterListFromPeers[T](r, c, peers, forwardedHeader) {
		if result.err != nil {
			if logger != nil {
				logger.Warn("cluster "+what+": peer list failed", "peer", result.peerID, "err", result.err)
			}
			continue
		}
		successful++
		for _, row := range result.rows {
			k := key(row)
			if k == "" {
				continue
			}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			merged = append(merged, row)
		}
	}
	if localErr != nil && len(merged) == 0 {
		return clusterListAggregate[T]{}, localErr
	}
	failed := unavailable + len(peers) - successful
	if localErr != nil {
		failed++
	}
	return clusterListAggregate[T]{rows: merged, failedPeers: failed}, nil
}

// forwardListToLeader sends an ingress list to the Raft leader, marking it
// with routedHeader so the leader aggregates instead of forwarding again.
// Returns false when self is the leader (aggregate here).
func (h *handlers) forwardListToLeader(w http.ResponseWriter, r *http.Request, c cluster.Client, routedHeader string) bool {
	return h.forwardTemplateToLeader(w, r, c, routedHeader)
}

// writeClusterListCoverage marks a partial list so a client can tell "these
// are all of them" from "some workers did not answer".
func writeClusterListCoverage(w http.ResponseWriter, failedPeers int, missingHeader string) {
	if failedPeers > 0 {
		w.Header().Set("X-Aerol-Partial", "true")
		w.Header().Set(missingHeader, fmt.Sprint(failedPeers))
	}
}
