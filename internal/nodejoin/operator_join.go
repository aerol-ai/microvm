package nodejoin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// A Kubernetes pod's join token comes from the operator
// (plans/kubernetes-v2-architecture.md §15.2, R2, D6):
//
//	setup ─► POST <operator>/v1/join-token, Bearer <the pod's projected ServiceAccount token>
//	operator ─► TokenReview: this pod, this UID, this machine; not joined yet
//	         ◄─ a single-use join token (10 minutes), the CA hash, the join URL
//	setup ─► the join a VM does, with them
//
// No token is made for a pod before it runs and proves who it is, so none
// waits in a Secret. The answer is kept in the node's etc folder until the
// join is done: a setup run again after a failure reuses it, so the servers
// see the same token and key and answer it as a replay.

// OperatorJoin is `sandboxd join --from-operator <url>`.
type OperatorJoin struct {
	// URL is the operator's join-token endpoint.
	URL string
	// CA is the PEM the operator's certificate chains to; the operator puts
	// it in the pod spec.
	CA []byte
	// TokenFile is the pod's projected ServiceAccount token for the
	// operator's audience; read on every request, as the kubelet renews it.
	TokenFile string
	// Wait bounds how long to keep asking while the operator says to ask
	// again (no leader yet, busy); DefaultWaitTimeout when zero.
	Wait time.Duration
	// Backoff is the first pause between requests; 2 s when zero.
	Backoff time.Duration
	// Client reaches the operator; nil makes one that trusts CA alone.
	Client *http.Client
}

// operatorGrant is the operator's answer.
type operatorGrant struct {
	Token      string    `json:"token"`
	CACertHash string    `json:"ca_cert_hash"`
	JoinURL    string    `json:"join_url"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// grantMargin is how much life a kept token needs to be used again: the
// join takes seconds, its dial-back checks a few more.
const grantMargin = time.Minute

// grantFile keeps the operator's answer beside cluster.env, which the join
// writes: setup's one writable folder that outlives its own restarts.
func grantFile(p Paths) string { return filepath.Join(filepath.Dir(p.ClusterEnv), "join-grant.json") }

// runFromOperator gets this pod's join token from the operator, then joins
// as any machine does, and forgets the token once the join is done.
func (j *Joiner) runFromOperator(ctx context.Context, o JoinOptions) (JoinResult, error) {
	oj := *o.FromOperator
	switch {
	case !o.FilesOnly:
		return JoinResult{}, errors.New("--from-operator is a Kubernetes pod's setup: add --files-only")
	case o.URL != "" || o.Token != "" || o.CACertHash != "" || o.ByCertificate:
		return JoinResult{}, errors.New("--from-operator takes no join URL, --token, --ca-cert-hash or --by-certificate: the operator gives them")
	case oj.URL == "" || !strings.HasPrefix(oj.URL, "https://"):
		return JoinResult{}, fmt.Errorf("--from-operator wants the operator's https URL, got %q", oj.URL)
	case oj.TokenFile == "":
		return JoinResult{}, errors.New("--identity-token is required: the pod's projected ServiceAccount token")
	}
	g, err := j.operatorGrant(ctx, oj, o.NodeID)
	if err != nil {
		return JoinResult{}, err
	}
	o.FromOperator = nil
	o.URL, o.Token, o.CACertHash = g.JoinURL, g.Token, g.CACertHash
	res, err := j.Run(ctx, o)
	if err == nil {
		// Single use and spent: nothing to keep.
		_ = os.Remove(grantFile(j.Paths))
	}
	return res, err
}

func (j *Joiner) operatorGrant(ctx context.Context, oj OperatorJoin, nodeID string) (operatorGrant, error) {
	file := grantFile(j.Paths)
	if g, ok := readGrant(file, time.Now()); ok {
		j.printf("[join] using the join token the operator gave this pod (good until %s)\n", g.ExpiresAt.UTC().Format(time.RFC3339))
		return g, nil
	}
	hc := oj.Client
	if hc == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(oj.CA) {
			return operatorGrant{}, errors.New("--operator-ca holds no PEM certificate")
		}
		hc = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}}
	}
	wait, pause := oj.Wait, oj.Backoff
	if wait <= 0 {
		wait = DefaultWaitTimeout
	}
	if pause <= 0 {
		pause = 2 * time.Second
	}
	deadline := time.Now().Add(wait)
	j.printf("[join] asking the operator for this pod's join token (%s)\n", oj.URL)
	for {
		raw, err := os.ReadFile(oj.TokenFile)
		if err != nil {
			return operatorGrant{}, fmt.Errorf("the pod's ServiceAccount token: %w", err)
		}
		g, after, err := askOperator(ctx, hc, oj.URL, strings.TrimSpace(string(raw)), nodeID)
		if err == nil {
			// Kept for a setup run again before the join is done. The
			// folder is the node's own; a failure to keep it only costs a
			// fresh request next time.
			if b, err := json.Marshal(g); err == nil {
				if err := cluster.WriteFileAtomic(file, b, 0o600); err != nil {
					j.printf("[join] could not keep the join token for a rerun: %v\n", err)
				}
			}
			return g, nil
		}
		if after < 0 {
			return operatorGrant{}, err
		}
		if after == 0 {
			after = pause
			pause = min(2*pause, 15*time.Second)
		}
		if time.Now().Add(after).After(deadline) {
			return operatorGrant{}, fmt.Errorf("no join token from the operator in %s: %w", wait, err)
		}
		j.printf("[join] %v; asking again in %s\n", err, after)
		select {
		case <-ctx.Done():
			return operatorGrant{}, ctx.Err()
		case <-time.After(after):
		}
	}
}

// askOperator makes one request. after is -1 when asking again cannot
// help (the operator refused this pod), else the pause the operator asked
// for, or 0 to use the caller's.
func askOperator(ctx context.Context, hc *http.Client, url, token, nodeID string) (operatorGrant, time.Duration, error) {
	if token == "" {
		return operatorGrant{}, -1, errors.New("the pod's ServiceAccount token is empty")
	}
	body, _ := json.Marshal(map[string]string{"node": nodeID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return operatorGrant{}, -1, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		// The operator may be starting or moving: ask again.
		return operatorGrant{}, 0, fmt.Errorf("the operator did not answer: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		var g operatorGrant
		if err := json.Unmarshal(raw, &g); err != nil {
			return operatorGrant{}, -1, fmt.Errorf("the operator's answer is not JSON: %w", err)
		}
		if g.Token == "" || g.JoinURL == "" {
			return operatorGrant{}, -1, errors.New("the operator's answer has no token or join URL")
		}
		return g, 0, nil
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	if e.Error == "" {
		e.Error = strings.TrimSpace(string(raw))
	}
	err = fmt.Errorf("the operator refused (%d): %s", resp.StatusCode, e.Error)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		after := time.Duration(0)
		if s, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && s > 0 {
			after = time.Duration(s) * time.Second
		}
		return operatorGrant{}, after, err
	default:
		return operatorGrant{}, -1, err
	}
}

// readGrant is a kept answer with enough life left to use again.
func readGrant(file string, now time.Time) (operatorGrant, bool) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return operatorGrant{}, false
	}
	var g operatorGrant
	if json.Unmarshal(raw, &g) != nil || g.Token == "" || g.JoinURL == "" || now.Add(grantMargin).After(g.ExpiresAt) {
		return operatorGrant{}, false
	}
	return g, true
}
