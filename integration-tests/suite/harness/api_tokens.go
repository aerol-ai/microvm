package harness

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
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Named credentials for the identity use cases (plans/identity-and-access.md
// T12). The cross-tenant cases used to need SB_ITEST_IDENTITY_FILE, a static
// "<token> <owner>" map installed on the node; T3 deleted it (D4), and the
// suite now mints real team avm_ tokens with the operator credential at
// setup, revokes them on cleanup, and drives the API with them over plain
// HTTP so a refusal's status and body are what the case asserts on.

// HeaderTeam selects which of a credential's teams a request acts for.
const HeaderTeam = "X-AerolVM-Team"

// APIClient is one credential against one API address. Unlike Client it
// treats every status as an answer: the identity cases assert on 401, 403
// and 404 as often as on 200.
type APIClient struct {
	Base   string
	Bearer string
	// Team, when set, is sent as X-AerolVM-Team.
	Team string
	// Headers are sent on every request (a facade's own credential header,
	// a forged client-address header).
	Headers map[string]string
	// HTTP defaults to a client on SharedTransport; a replacement should
	// keep that transport or a node a case took down stays in its pool.
	HTTP *http.Client
}

// NewAPIClient is an APIClient for base with bearer.
func NewAPIClient(base, bearer string) *APIClient {
	return &APIClient{Base: strings.TrimRight(base, "/"), Bearer: bearer, HTTP: HTTPClient(2 * time.Minute)}
}

// As returns a copy of c that presents bearer instead.
func (c *APIClient) As(bearer string) *APIClient {
	cp := *c
	cp.Bearer = bearer
	return &cp
}

// At returns a copy of c that talks to base instead (a node's forwarded
// loopback address, say).
func (c *APIClient) At(base string) *APIClient {
	cp := *c
	cp.Base = strings.TrimRight(base, "/")
	return &cp
}

// WithTeam returns a copy of c that sends X-AerolVM-Team: team.
func (c *APIClient) WithTeam(team string) *APIClient {
	cp := *c
	cp.Team = team
	return &cp
}

// APIResponse is one answer: status, headers and the (capped) body.
type APIResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body into v.
func (r *APIResponse) JSON(v any) error {
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("decode %d body: %w: %s", r.Status, err, snippet(r.Body))
	}
	return nil
}

// Err decodes the body as the API's error shape. A body that is not one
// yields the zero value with Error holding the raw text.
func (r *APIResponse) Err() models.ErrorResponse {
	var e models.ErrorResponse
	if json.Unmarshal(r.Body, &e) != nil {
		e.Error = strings.TrimSpace(string(r.Body))
	}
	return e
}

// String is a one-line description for failure messages.
func (r *APIResponse) String() string {
	if r == nil {
		return "<no response>"
	}
	return fmt.Sprintf("%d %s", r.Status, snippet(r.Body))
}

// maxAPIBody caps what Do reads. Every body the identity cases read is small;
// a list of sandboxes is the largest.
const maxAPIBody = 4 << 20

// Do sends one request. body, when non-nil, is sent as JSON.
func (c *APIClient) Do(ctx context.Context, method, path string, body any) (*APIResponse, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rdr)
	if err != nil {
		return nil, err
	}
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	if c.Team != "" {
		req.Header.Set(HeaderTeam, c.Team)
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = apiHTTPClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return nil, err
	}
	return &APIResponse{Status: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

// expect sends a request and requires one status, decoding the body into
// out when out is non-nil.
func (c *APIClient) expect(ctx context.Context, method, path string, body any, want int, out any) (*APIResponse, error) {
	resp, err := c.Do(ctx, method, path, body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	if resp.Status != want {
		return resp, fmt.Errorf("%s %s = %s, want %d", method, path, resp, want)
	}
	if out != nil {
		return resp, resp.JSON(out)
	}
	return resp, nil
}

// CreateToken mints an API token (POST /v1/tokens, 201).
func (c *APIClient) CreateToken(ctx context.Context, req models.CreateAPITokenRequest) (models.CreatedAPIToken, error) {
	var out models.CreatedAPIToken
	_, err := c.expect(ctx, http.MethodPost, "/v1/tokens", req, http.StatusCreated, &out)
	return out, err
}

// RevokeToken revokes a token. A token already gone counts as revoked: the
// cleanup that calls this runs after cases that revoke on purpose.
func (c *APIClient) RevokeToken(ctx context.Context, id string) error {
	resp, err := c.Do(ctx, http.MethodDelete, "/v1/tokens/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if resp.Status != http.StatusNoContent && resp.Status != http.StatusNotFound {
		return fmt.Errorf("DELETE /v1/tokens/%s = %s", id, resp)
	}
	return nil
}

// ListTokens lists every token (GET /v1/tokens).
func (c *APIClient) ListTokens(ctx context.Context) (models.APITokenList, error) {
	var out models.APITokenList
	_, err := c.expect(ctx, http.MethodGet, "/v1/tokens", nil, http.StatusOK, &out)
	return out, err
}

// WhoAmI asks who the credential is. A non-200 is returned as the response
// with a nil error, so callers can assert on the refusal.
func (c *APIClient) WhoAmI(ctx context.Context) (models.WhoAmI, *APIResponse, error) {
	var who models.WhoAmI
	resp, err := c.Do(ctx, http.MethodGet, "/v1/whoami", nil)
	if err != nil {
		return who, nil, err
	}
	if resp.Status == http.StatusOK {
		err = resp.JSON(&who)
	}
	return who, resp, err
}

// propagating reports whether a refusal is a token that has not reached
// this node yet rather than a verdict: a token minted on one node reaches a
// worker without Raft state within one mirror sync (~5 s), and until then
// that worker answers 401 unknown_or_revoked, or 503 while its mirror is
// catching up. A JWT on a node that has not loaded the identity file yet
// answers 503 too.
func propagating(resp *APIResponse) bool {
	switch resp.Status {
	case http.StatusServiceUnavailable:
		return true
	case http.StatusUnauthorized:
		return resp.Err().Reason == "unknown_or_revoked"
	}
	return false
}

// TokenMirrorNodes are the nodes that learn a new avm_ token from the token
// mirror's next poll (~5 s) instead of from Raft state of their own:
// workers, which own every sandbox on a role-separated cluster, and ingress
// nodes. A request the API domain forwards to one of them (a create placed
// on a worker, a read or exec on the sandbox's owner) is authenticated
// again there, so a token the API domain already accepts can still get 401
// unknown_or_revoked on the node that answers. Servers and mixed nodes hold
// Raft state and see a token once its create commits.
func TokenMirrorNodes(targets *IntegrationTargets) []IntegrationNode {
	if targets == nil {
		return nil
	}
	var out []IntegrationNode
	for _, n := range targets.Nodes {
		switch strings.ToLower(strings.TrimSpace(n.Role)) {
		case "worker", "ingress":
			out = append(out, n)
		}
	}
	return out
}

// tokenPropagationPoll is how often AwaitAccepted retries. A var so the
// offline tests can shrink it.
var tokenPropagationPoll = time.Second

// AwaitAccepted retries whoami until the credential is accepted, riding out
// propagation (see propagating), and fails on any other refusal at once.
func AwaitAccepted(ctx context.Context, c *APIClient, timeout time.Duration) (models.WhoAmI, error) {
	deadline := time.Now().Add(timeout)
	var last *APIResponse
	for {
		who, resp, err := c.WhoAmI(ctx)
		switch {
		case err != nil && resp == nil && !isRetriableTransportErr(err):
			return who, err
		case resp != nil && resp.Status == http.StatusOK:
			return who, err
		case resp != nil && !propagating(resp) && !transientGatewayStatuses[resp.Status]:
			return who, fmt.Errorf("credential refused at %s: %s", c.Base, resp)
		}
		if resp != nil {
			last = resp
		}
		if time.Now().After(deadline) {
			return who, fmt.Errorf("credential still not accepted at %s after %s: last %s", c.Base, timeout, last)
		}
		select {
		case <-ctx.Done():
			return who, ctx.Err()
		case <-time.After(tokenPropagationPoll):
		}
	}
}

// AwaitRefused polls whoami until the credential is refused with a 401 (a
// revoke or a deny entry reaching the node) and returns how long it took.
func AwaitRefused(ctx context.Context, c *APIClient, timeout time.Duration) (time.Duration, *APIResponse, error) {
	start := time.Now()
	for {
		_, resp, err := c.WhoAmI(ctx)
		if err == nil && resp != nil && resp.Status == http.StatusUnauthorized {
			return time.Since(start), resp, nil
		}
		if time.Since(start) > timeout {
			if err == nil {
				err = errors.New("still accepted")
			}
			return time.Since(start), resp, fmt.Errorf("credential not refused at %s within %s: %w (last %s)", c.Base, timeout, err, resp)
		}
		select {
		case <-ctx.Done():
			return time.Since(start), resp, ctx.Err()
		case <-time.After(tokenPropagationPoll):
		}
	}
}

// TokenName is a token name unique to this run and test: the name must be
// unique within its team, and a kept cluster accumulates runs.
func TokenName(prefix string) string {
	return fmt.Sprintf("itest-%s-%d", prefix, time.Now().UnixNano())
}
