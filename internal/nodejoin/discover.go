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
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// The new machine's half of discovery (D4, §4): it trusts nothing until
// the server proves it knows the token. cluster-info comes over TLS that is
// not checked yet; its MACs are, with a key only the token derives, and so
// is the CA pin when the operator gave one. From then on every call checks
// the join port's cert against that CA.

// joinTimeout bounds one call to the join port: a join includes the
// dial-back (3 s a port) and a Raft write.
const joinTimeout = 90 * time.Second

// discovery is a checked cluster-info answer.
type discovery struct {
	joinURL string
	info    cluster.ClusterInfo
	ca      *x509.Certificate
	pool    *x509.CertPool
	// serverTime is the answer's Date header, for the clock check.
	serverTime time.Time
}

// ErrDiscovery is a cluster-info answer this machine must not trust.
var ErrDiscovery = errors.New("the join server could not prove it belongs to the cluster this token is for")

// normalizeJoinURL accepts https://host:port, host:port or a bare host
// (the join port by default).
func normalizeJoinURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("missing the join URL (https://<server>:7003)")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("join URL %q is not a URL", raw)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("join URL %q must be https: the join port only speaks TLS", raw)
	}
	if u.Port() == "" {
		u.Host += fmt.Sprintf(":%d", cluster.DefaultJoinPort)
	}
	return "https://" + u.Host, nil
}

// portProbeTimeout bounds the connect to the join port (eng T14: about
// 3 s), so a firewall that drops 7003 fails the check quickly instead of
// after the whole call's budget.
const portProbeTimeout = 3 * time.Second

func joinTransport(cfg *tls.Config) *http.Transport {
	return &http.Transport{
		DialContext:         (&net.Dialer{Timeout: portProbeTimeout}).DialContext,
		TLSHandshakeTimeout: 2 * portProbeTimeout,
		TLSClientConfig:     cfg,
	}
}

// insecureClient talks to the join port before the CA is known. Safe only
// because nothing it reads is trusted until its MACs check out.
func insecureClient() *http.Client {
	return &http.Client{Timeout: joinTimeout, Transport: joinTransport(
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // trust comes from the discovery MAC, not the chain
	)}
}

// pinnedClient checks the join port's cert against the discovered CA.
func pinnedClient(pool *x509.CertPool) *http.Client {
	return &http.Client{Timeout: joinTimeout, Transport: joinTransport(
		&tls.Config{RootCAs: pool, ServerName: clusterServerName, MinVersion: tls.VersionTLS12},
	)}
}

// discover reads and checks cluster-info for token. pin is --ca-cert-hash.
func discover(ctx context.Context, client *http.Client, joinURL, token, pin string) (*discovery, error) {
	id, _, err := cluster.ParseJoinToken(token)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL+cluster.JoinClusterInfoPath+"?token_id="+url.QueryEscape(id), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &unreachableError{url: joinURL, err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, joinRefusal(resp.StatusCode, raw)
	}
	var info cluster.ClusterInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("%w: unreadable answer: %v", ErrDiscovery, err)
	}
	if !cluster.VerifyClusterInfo(token, info) {
		return nil, fmt.Errorf("%w (its MAC does not match the token: a wrong token, or not this cluster)", ErrDiscovery)
	}
	ca, err := firstCert([]byte(info.CACert))
	if err != nil {
		return nil, fmt.Errorf("%w: its CA: %v", ErrDiscovery, err)
	}
	if got := cluster.CACertHash(ca); pin != "" && !strings.EqualFold(strings.TrimSpace(pin), got) {
		return nil, fmt.Errorf("%w: its CA is %s, not the --ca-cert-hash %s", ErrDiscovery, got, pin)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	d := &discovery{joinURL: joinURL, info: info, ca: ca, pool: pool}
	if date, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		d.serverTime = date
	}
	return d, nil
}

// unreachableError is a join port that answered nothing at all.
type unreachableError struct {
	url string
	err error
}

func (e *unreachableError) Error() string {
	return fmt.Sprintf("can't reach the join server %s: %v", e.url, e.err)
}

func (e *unreachableError) Unwrap() error { return e.err }

// JoinRefusal is a refusal from the join port: its status, reason code
// (cluster.JoinReason) and message.
type JoinRefusal struct {
	Status   int
	Reason   string
	Message  string
	DialBack []cluster.DialBackResult
}

func (e *JoinRefusal) Error() string {
	return fmt.Sprintf("the join server refused (%d %s): %s", e.Status, e.Reason, e.Message)
}

// Fix is the one line that says what to do about a refusal.
func (e *JoinRefusal) Fix() string {
	switch e.Reason {
	case "token_invalid", "token_expired":
		return "the token is wrong, revoked or expired: make a new one with `aerolvm join-command`"
	case "token_used":
		return "this single-use token joined another node: make a new one with `aerolvm join-command`"
	case "role_mismatch":
		return "the token is for another role: make one for this role with `aerolvm join-command --role <role>`"
	case "node_id_in_use":
		return "another node has this ID: pick another --node-id, or delete the old node first (`aerolvm delete node <id>`)"
	case "key_revoked", "key_in_use":
		return "this machine's node key belongs to a deleted or other node: run `sudo sandboxd reset --yes`, then join again"
	case "version":
		return "this sandboxd build may not join: install the version the cluster runs (the installer picks it), then join again"
	case "dial_back":
		return portFix
	case "rate_limited":
		return "too many join calls from this address: wait a minute and try again"
	case "no_ca_signer", "not_leader":
		return "the server can't sign right now (no CA key, or no leader): try another join URL, or run `sandboxd adopt` on the servers"
	case "cluster_version":
		return "a server still runs an older build: finish upgrading every server first"
	}
	return ""
}

func joinRefusal(status int, raw []byte) *JoinRefusal {
	var body struct {
		Error    string                   `json:"error"`
		Reason   string                   `json:"reason"`
		DialBack []cluster.DialBackResult `json:"dial_back"`
	}
	r := &JoinRefusal{Status: status, Message: strings.TrimSpace(string(raw))}
	if json.Unmarshal(raw, &body) == nil && (body.Error != "" || body.Reason != "") {
		r.Message, r.Reason, r.DialBack = body.Error, body.Reason, body.DialBack
	}
	return r
}

// postJoin posts one JSON body to the join port and decodes the answer.
func postJoin(ctx context.Context, client *http.Client, joinURL, path string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return &unreachableError{url: joinURL, err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return joinRefusal(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the join server sent an unreadable answer: %w", err)
	}
	return nil
}

// portFix is the printed fix for any port the join server can't reach.
const portFix = "open TCP 7001-7002 and UDP 7001 between nodes, TCP 7000 between servers, and TCP 7003 to servers"
