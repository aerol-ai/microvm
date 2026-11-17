// Package aerolapi is the operator's client for AerolVM's admin API. The
// operator talks to AerolVM only through it (plans/kubernetes-v2-architecture.md
// P2): the same routes `aerolvm` uses, with the admin token the operator
// made for the cluster. Nothing here reaches inside a node.
package aerolapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Client calls one cluster's admin API. Any server answers; writes are
// forwarded to the leader by the server that takes them.
type Client struct {
	// BaseURL is the servers' API Service, such as
	// http://prod-api.aerolvm-system.svc:21212.
	BaseURL string
	// Token is the credential every call carries: the cluster's admin
	// token (SB_PAT_TOKEN), or the operator's own admin API token where
	// the servers take the admin token only from their own pod.
	Token string
	// Fallback, when set, is sent once if the server answers Token with
	// 401. While enterprise mode is turned on or off, servers made before
	// the change take one credential and servers made after it the other.
	// A 401 is answered before the call does anything, so sending it again
	// is safe.
	Fallback string
	HTTP     *http.Client
	// fallbackRefused: a server refused Fallback as an admin token from off
	// its own pod; it is not sent again.
	fallbackRefused atomic.Bool
	// CallTimeout bounds every call but an evacuate pass (zero: only the
	// HTTP client's own bound).
	CallTimeout time.Duration
}

const (
	// DefaultCallTimeout bounds the quick calls, which answer in
	// milliseconds. A server that stopped answering then holds a reconcile
	// 30 seconds, not the minutes an evacuate pass may take (review R3).
	DefaultCallTimeout = 30 * time.Second
	// EvacuateTimeout bounds one decommission pass: up to 8 moves at once,
	// each waiting for its target's image pull (up to 90 s) and its
	// source's release. It is the HTTP client's own bound.
	EvacuateTimeout = 6 * time.Minute
)

// New returns a Client whose every call is bounded.
func New(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token,
		HTTP: &http.Client{Timeout: EvacuateTimeout}, CallTimeout: DefaultCallTimeout}
}

// Error is a refused call: the status and the server's error text.
type Error struct {
	Status int
	Code   string
	Reason string
}

func (e *Error) Error() string {
	if e.Code != "" && e.Code != e.Reason {
		return fmt.Sprintf("aerolvm: %d %s: %s", e.Status, e.Code, e.Reason)
	}
	return fmt.Sprintf("aerolvm: %d: %s", e.Status, e.Reason)
}

// IsStatus reports whether err is a refusal with status code.
func IsStatus(err error, code int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == code
}

// IsCode reports whether err is a refusal with the error code code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// do makes a quick call, bounded by CallTimeout.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if c.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.CallTimeout)
		defer cancel()
	}
	return c.call(ctx, method, path, body, out)
}

// call makes a call bounded only by ctx and the HTTP client: with Token,
// then once with Fallback if Token is refused as unauthenticated.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	err := c.send(ctx, method, path, raw, body != nil, out, c.Token)
	if c.Fallback != "" && c.Fallback != c.Token && !c.fallbackRefused.Load() && IsStatus(err, http.StatusUnauthorized) {
		ferr := c.send(ctx, method, path, raw, body != nil, out, c.Fallback)
		if isHostScopeRefusal(ferr) {
			// The server takes the admin token only from its own pod: the
			// rest of this client's calls do not send it again.
			c.fallbackRefused.Store(true)
		}
		return ferr
	}
	return err
}

// isHostScopeRefusal reports a 401 for an admin token sent from off the
// server's own pod (SB_PAT_SCOPE=host).
func isHostScopeRefusal(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized && strings.Contains(e.Reason, "works only on this host")
}

func (c *Client) send(ctx context.Context, method, path string, body []byte, hasBody bool, out any, token string) error {
	var rd io.Reader
	if hasBody {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{Status: resp.StatusCode, Reason: strings.TrimSpace(string(raw))}
		var parsed struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Error != "" {
			e.Code, e.Reason = parsed.Error, parsed.Error
			if parsed.Reason != "" {
				e.Reason = parsed.Reason
			}
		}
		return e
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Ready reports whether the server behind BaseURL answers /ready.
func (c *Client) Ready(ctx context.Context) bool {
	return c.do(ctx, http.MethodGet, "/ready", nil, nil) == nil
}

// Leader is the current leader's node ID, "" when none.
func (c *Client) Leader(ctx context.Context) (string, error) {
	var out struct {
		Leader string `json:"leader"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/cluster/leader", nil, &out)
	return out.Leader, err
}

// Adopt records the answering server's own key as admitted, which the
// first server needs once it leads (`sandboxd init`'s second run).
func (c *Client) Adopt(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/cluster/adopt", map[string]any{}, nil)
}

// JoinToken is a minted join token and what a joiner needs with it.
type JoinToken struct {
	Token      string   `json:"token"`
	ID         string   `json:"id"`
	Role       string   `json:"role"`
	CACertHash string   `json:"ca_cert_hash"`
	JoinURLs   []string `json:"join_urls"`
}

// MintJoinToken makes a single-use join token for one pod (C23).
func (c *Client) MintJoinToken(ctx context.Context, role, ttl, createdBy string) (JoinToken, error) {
	var out JoinToken
	err := c.do(ctx, http.MethodPost, "/v1/cluster/join-tokens",
		map[string]any{"role": role, "ttl": ttl, "reusable": false, "created_by": createdBy}, &out)
	return out, err
}

// Node is the part of GET /v1/cluster/nodes/{id} the operator reads.
type Node struct {
	NodeID           string            `json:"node_id"`
	Role             string            `json:"role"`
	Alive            bool              `json:"alive"`
	Version          string            `json:"version"`
	Voter            bool              `json:"voter"`
	Leader           bool              `json:"leader"`
	Restarting       bool              `json:"restarting"`
	Drained          bool              `json:"drained"`
	Zone             string            `json:"zone"`
	Labels           map[string]string `json:"labels"`
	CapacityStale    bool              `json:"capacity_stale"`
	Capacity         Capacity          `json:"capacity"`
	SandboxesOwned   int               `json:"sandboxes_owned"`
	SandboxesRunning int               `json:"sandboxes_running"`
}

// Capacity is a node's room.
type Capacity struct {
	HostCPUCores     int     `json:"host_cpu_cores"`
	CPUBudget        float64 `json:"cpu_budget"`
	ReservedCPU      float64 `json:"reserved_cpu"`
	MemoryBudgetMB   int     `json:"memory_budget_mb"`
	ReservedMemoryMB int     `json:"reserved_memory_mb"`
}

// FreeCPU is the CPU still free for new sandboxes.
func (c Capacity) FreeCPU() float64 { return max(c.CPUBudget-c.ReservedCPU, 0) }

// FreeMemoryMB is the memory still free for new sandboxes.
func (c Capacity) FreeMemoryMB() int { return max(c.MemoryBudgetMB-c.ReservedMemoryMB, 0) }

// GetNode reads one node; a node the cluster does not know is a 404.
func (c *Client) GetNode(ctx context.Context, id string) (Node, error) {
	var out Node
	err := c.do(ctx, http.MethodGet, "/v1/cluster/nodes/"+url.PathEscape(id), nil, &out)
	return out, err
}

// Members lists every node gossip knows, with capacity.
func (c *Client) Members(ctx context.Context) ([]Node, error) {
	var out struct {
		Members []Node `json:"members"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/cluster/members", nil, &out)
	return out.Members, err
}

// Cordon stops new sandboxes landing on id; Uncordon undoes it.
func (c *Client) Cordon(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/cluster/nodes/"+url.PathEscape(id)+"/cordon", nil, nil)
}

// Uncordon lets new sandboxes land on id again.
func (c *Client) Uncordon(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/cluster/nodes/"+url.PathEscape(id)+"/uncordon", nil, nil)
}

// EvacuateRequest and EvacuateResult mirror the evacuate route (C9).
type EvacuateRequest struct {
	DeadlineUnix  int64 `json:"deadline_unix,omitempty"`
	StopRemaining bool  `json:"stop_remaining,omitempty"`
	Max           int   `json:"max,omitempty"`
}

// EvacuateResult is one decommission pass.
type EvacuateResult struct {
	Moved            []string          `json:"moved"`
	Failed           map[string]string `json:"failed"`
	RemainingMovable int               `json:"remaining_movable"`
	Remaining        int               `json:"remaining"`
	Stopped          int               `json:"stopped"`
	Done             bool              `json:"done"`
}

// Evacuate runs one decommission pass over a cordoned node (C9).
func (c *Client) Evacuate(ctx context.Context, id string, req EvacuateRequest) (EvacuateResult, error) {
	var out EvacuateResult
	// Not do: a pass may take minutes (EvacuateTimeout). The node
	// controller runs it in the background, so no reconcile waits on it.
	err := c.call(ctx, http.MethodPost, "/v1/cluster/nodes/"+url.PathEscape(id)+"/evacuate", req, &out)
	return out, err
}

// Gone tells the leader id's machine is gone (C19).
func (c *Client) Gone(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/cluster/nodes/"+url.PathEscape(id)+"/gone", nil, nil)
}

// DeleteNode removes id from the cluster; force for one that still owns
// sandboxes.
func (c *Client) DeleteNode(ctx context.Context, id string, force bool) error {
	path := "/v1/cluster/nodes/" + url.PathEscape(id)
	if force {
		path += "?force=true"
	}
	err := c.do(ctx, http.MethodDelete, path, nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// Rollout reads AerolVM's own upgrade record; nil when there never was one.
func (c *Client) Rollout(ctx context.Context) (*upgradewire.Rollout, error) {
	var out upgradewire.Rollout
	err := c.do(ctx, http.MethodGet, upgradewire.ClusterUpgradePath, nil, &out)
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// operatorDriver marks a call the Kubernetes-managed leader accepts (C13).
const operatorDriver = "?driver=operator"

// ApplyImages starts an upgrade to version that swaps images (C13).
func (c *Client) ApplyImages(ctx context.Context, version string, req upgradewire.ApplyRequest) (*upgradewire.Rollout, error) {
	req.Version, req.Source, req.Files = version, upgradewire.SourceImages, nil
	var out upgradewire.Rollout
	if err := c.do(ctx, http.MethodPost, upgradewire.ClusterUpgradePath+operatorDriver, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Rollback sends the current rollout back to the previous version.
func (c *Client) Rollback(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, upgradewire.ClusterUpgradeRollbackPath+operatorDriver, nil, nil)
}

// APIToken is an API token as the server lists it: never its secret.
type APIToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Team      string    `json:"team"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreatedAPIToken is a new token with its secret, which the server shows
// this once.
type CreatedAPIToken struct {
	APIToken
	Token string `json:"token"`
}

// CreateToken makes an API token (POST /v1/tokens). expiresIn is a Go
// duration or a number of days ("30d").
func (c *Client) CreateToken(ctx context.Context, name, role, team, expiresIn string) (CreatedAPIToken, error) {
	var out CreatedAPIToken
	err := c.do(ctx, http.MethodPost, "/v1/tokens",
		map[string]string{"name": name, "role": role, "team": team, "expires_in": expiresIn}, &out)
	if err == nil && (out.Token == "" || out.ID == "") {
		err = errors.New("aerolvm: a created token came back without its id or secret")
	}
	return out, err
}

// ListTokens is every API token (GET /v1/tokens), never a secret.
func (c *Client) ListTokens(ctx context.Context) ([]APIToken, error) {
	var out struct {
		Tokens []APIToken `json:"tokens"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/tokens", nil, &out)
	return out.Tokens, err
}

// RevokeToken deletes an API token; one already gone is not an error.
func (c *Client) RevokeToken(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/v1/tokens/"+url.PathEscape(id), nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// WhoAmI checks the client's credential (GET /v1/whoami): nil when the
// server takes it.
func (c *Client) WhoAmI(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/whoami", nil, nil)
}
