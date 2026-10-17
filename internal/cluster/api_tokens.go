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

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/identity"
)

// API tokens over the cluster (plans/identity-and-access.md §5.4).
//
//	create/revoke on any node ─► server tier ─► leader: fv gate ─► opPutAPIToken / opDeleteAPIToken
//	worker or ingress node ────► TokenMirror polls GET tokens?since=N (304 | delta | resnapshot)
//	                             └► page walk: GET tokens/page?after=…
//	server node ───────────────► reads its own FSM (always current)
//
// Writes use a dedicated internal endpoint, like egress profiles, for two
// reasons: the caller needs the stored record back, and only a leader that
// has checked every Raft server's build may apply a token op, so an older
// leader can never commit an op its followers would apply and it wouldn't
// (or the reverse).
const (
	PublicInternalAPITokenWritePath   = "/v1/cluster/internal/tokens/write"
	PublicInternalAPITokenChangesPath = "/v1/cluster/internal/tokens"
	PublicInternalAPITokenPagePath    = "/v1/cluster/internal/tokens/page"
)

// Outcome codes of a token write, carried in a 200 body so the sentinel
// survives any number of forwarding hops.
const (
	apiTokenCodeNameTaken      = "name_taken"
	apiTokenCodeIDTaken        = "id_taken"
	apiTokenCodeClusterVersion = "cluster_version"
)

// APITokenWriteRequest creates a token (Delete false, Token set) or revokes
// one (Delete true, ID set). A create carries the secret's hash only.
type APITokenWriteRequest struct {
	Delete bool                 `json:"delete,omitempty"`
	Token  identity.TokenRecord `json:"token"`
	ID     string               `json:"id,omitempty"`
}

// APITokenWriteResponse is the outcome. Code is set, and Token empty, when
// the FSM or the upgrade gate refused the write.
type APITokenWriteResponse struct {
	Token   identity.TokenRecord `json:"token"`
	Code    string               `json:"code,omitempty"`
	Message string               `json:"message,omitempty"`
}

// APITokenWriteOutcome turns a write error into the body a peer gets, and
// err back into the same error, so sentinels survive forwarding.
func APITokenWriteOutcome(err error) APITokenWriteResponse {
	switch {
	case errors.Is(err, ErrAPITokenNameTaken):
		return APITokenWriteResponse{Code: apiTokenCodeNameTaken, Message: err.Error()}
	case errors.Is(err, ErrAPITokenIDTaken):
		return APITokenWriteResponse{Code: apiTokenCodeIDTaken, Message: err.Error()}
	case errors.Is(err, ErrClusterVersion):
		return APITokenWriteResponse{Code: apiTokenCodeClusterVersion, Message: err.Error()}
	}
	return APITokenWriteResponse{}
}

func (r APITokenWriteResponse) err() error {
	var sentinel error
	switch r.Code {
	case "":
		return nil
	case apiTokenCodeNameTaken:
		sentinel = ErrAPITokenNameTaken
	case apiTokenCodeIDTaken:
		sentinel = ErrAPITokenIDTaken
	case apiTokenCodeClusterVersion:
		sentinel = ErrClusterVersion
	default:
		return fmt.Errorf("cluster: API token write: %s: %s", r.Code, r.Message)
	}
	return fmt.Errorf("%w (%s)", sentinel, r.Message)
}

// WriteAPIToken creates or revokes a token. The leader checks the upgrade
// gate and applies; a follower forwards one hop to the leader. The proposer
// stamps the time into the entry, so every replica applies the same one.
func (c *Cluster) WriteAPIToken(ctx context.Context, req APITokenWriteRequest) (APITokenWriteResponse, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return APITokenWriteResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	if c.raft.raft.State() != raft.Leader {
		var out APITokenWriteResponse
		if err := c.forwardToLeaderJSON(ctx, "API token write", PublicInternalAPITokenWritePath, req, &out); err != nil {
			return APITokenWriteResponse{}, err
		}
		return out, out.err()
	}
	if err := c.raftServersSupport(apiTokenFSMOpsVersion, "API tokens"); err != nil {
		return APITokenWriteResponse{}, err
	}
	cmd := command{Op: opPutAPIToken, StampUnixNano: time.Now().UnixNano()}
	if req.Delete {
		cmd.Op, cmd.APITokenID = opDeleteAPIToken, req.ID
	} else {
		token := req.Token
		cmd.APIToken = &token
	}
	payload, err := encodeCommand(cmd)
	if err != nil {
		return APITokenWriteResponse{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return APITokenWriteResponse{}, err
	}
	if applied, ok := result.(apiTokenApplyResult); ok {
		return APITokenWriteResponse{Token: applied.Token}, nil
	}
	return APITokenWriteResponse{}, nil
}

// LookupToken answers the request path on a server node from its own
// FSM. A server is always current (§5.4: revocation is immediate there), so
// fresh is always true. It satisfies identity.TokenLookup.
func (c *Cluster) LookupToken(id string) (identity.TokenRecord, bool, bool) {
	if c == nil || c.fsm == nil {
		return identity.TokenRecord{}, false, false
	}
	rec, ok := c.fsm.apiTokens().lookup(id)
	return rec, ok, true
}

// ListAPITokens returns every stored token, sorted by team and name.
func (c *Cluster) ListAPITokens(context.Context) ([]identity.TokenRecord, error) {
	if c == nil || c.fsm == nil {
		return nil, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.apiTokens().all(), nil
}

// APITokenChanges serves a mirror's poll. changed is false when the cursor
// is current: the handler answers 304 with no body.
func (c *Cluster) APITokenChanges(since uint64) (identity.TokenChanges, bool) {
	if c == nil || c.fsm == nil {
		return identity.TokenChanges{Changes: []identity.TokenChange{}, Resnapshot: true}, true
	}
	return c.fsm.apiTokens().changesSince(since)
}

// APITokenPage serves one page of a mirror's page walk.
func (c *Cluster) APITokenPage(after string, limit int) identity.TokenPage {
	if c == nil || c.fsm == nil {
		return identity.TokenPage{Tokens: []identity.TokenRecord{}}
	}
	return c.fsm.apiTokens().page(after, limit)
}

// SweepExpiredAPITokens deletes tokens that expired before cutoff. Only the
// leader sweeps (every delete goes through Raft anyway); on any other node
// it does nothing. A delete is idempotent, so a sweep cut short by a leader
// change is finished by the next leader's sweep.
func (c *Cluster) SweepExpiredAPITokens(ctx context.Context, cutoff time.Time) (int, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil || c.raft.raft.State() != raft.Leader {
		return 0, nil
	}
	swept := 0
	for _, id := range c.fsm.apiTokens().expiredBefore(cutoff) {
		if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Delete: true, ID: id}); err != nil {
			return swept, err
		}
		swept++
	}
	return swept, nil
}

// raftServersSupport is the rolling-upgrade gate: every server in the Raft
// configuration, failed ones included, must report an FSM op set of at
// least min. A failed server counts at its last-known gossip meta because
// it replays the log when it returns; one with no gossip entry at all
// counts as an old build. A half-upgraded cluster answers ErrClusterVersion
// instead of committing an op some replica would skip.
func (c *Cluster) raftServersSupport(min int, feature string) error {
	future := c.raft.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return fmt.Errorf("cluster: read raft configuration: %w", err)
	}
	for _, srv := range future.Configuration().Servers {
		id := string(srv.ID)
		v := 0
		if id == c.nodeID {
			v = fsmOpsVersion
		} else if c.gossip != nil {
			if m, ok := c.gossip.lookupMember(id); ok {
				v = m.FSMOpsVersion
			}
		}
		if v < min {
			return fmt.Errorf("%w: server %s reports FSM ops version %d, %s need %d", ErrClusterVersion, id, v, feature, min)
		}
	}
	return nil
}

// forwardToLeaderJSON posts in to the leader's internal endpoint path and
// decodes its 200 body into out: one hop, with this node's PAT over mTLS
// (a node: principal on the leader). A 503 means the leader moved. what
// names the write in errors ("egress profile write").
func (c *Cluster) forwardToLeaderJSON(ctx context.Context, what, path string, in, out any) error {
	leader := c.Leader()
	if leader == "" {
		return ErrNotLeader
	}
	if c.currentInternalClient() == nil || c.gossip == nil {
		return ErrPeerInternalURLRequired
	}
	peerInternal := c.gossip.peerInternalURL(leader)
	if peerInternal == "" {
		return ErrPeerInternalURLRequired
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, strings.TrimRight(peerInternal, "/")+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cluster: build %s: %w", what, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	SetPeerNodeIDHeader(httpReq, c.nodeID)
	if c.patToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := c.ClientForPeer(leader).Do(httpReq)
	if err != nil {
		return fmt.Errorf("cluster: %s: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode == http.StatusServiceUnavailable {
			return ErrNotLeader
		}
		return fmt.Errorf("cluster: %s: status %d: %s", what, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if err := decodeControlPlaneJSON(resp.Body, out); err != nil {
		return fmt.Errorf("cluster: decode %s: %w", what, err)
	}
	return nil
}

// WriteAPIToken sends a token write to the server tier; any server takes it
// and forwards it to the leader.
func (a *Agent) WriteAPIToken(ctx context.Context, req APITokenWriteRequest) (APITokenWriteResponse, error) {
	if a == nil {
		return APITokenWriteResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out APITokenWriteResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalAPITokenWritePath, PublicInternalAPITokenWritePath, req, &out); err != nil {
		return APITokenWriteResponse{}, fmt.Errorf("cluster: API token write: %w", err)
	}
	return out, out.err()
}

// ListAPITokens page-walks the server tier, so a list right after a create
// on this node shows it (the local mirror may be one poll behind).
func (a *Agent) ListAPITokens(ctx context.Context) ([]identity.TokenRecord, error) {
	if a == nil {
		return nil, fmt.Errorf("cluster: agent is not configured")
	}
	var out []identity.TokenRecord
	after := ""
	for {
		body, err := a.FetchTokenPage(ctx, after, 0)
		if err != nil {
			return nil, err
		}
		var page identity.TokenPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("cluster: decode API token page: %w", err)
		}
		out = append(out, page.Tokens...)
		if page.Next == "" || page.Next <= after {
			break
		}
		after = page.Next
	}
	identity.SortTokenRecords(out)
	return out, nil
}

// FetchTokenChanges is the mirror's poll (identity.TokenFeed), on the
// existing control-plane client: any live server, retried on the next one
// if a server answers 503. A 304 is identity.ErrTokensUnchanged.
func (a *Agent) FetchTokenChanges(ctx context.Context, since uint64) ([]byte, error) {
	path := PublicInternalAPITokenChangesPath + "?since=" + strconv.FormatUint(since, 10)
	body, err := a.fetchControlPlaneRaw(ctx, path)
	if isStatus(err, http.StatusNotModified) {
		return nil, identity.ErrTokensUnchanged
	}
	return body, err
}

// FetchTokenPage is one page of the mirror's page walk (identity.TokenFeed).
func (a *Agent) FetchTokenPage(ctx context.Context, after string, limit int) ([]byte, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := PublicInternalAPITokenPagePath
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	return a.fetchControlPlaneRaw(ctx, path)
}

// fetchControlPlaneRaw GETs path from the server tier and returns the body
// undecoded, so the mirror can refuse an oversized page before decoding it
// (the transport's own ceiling, 16 MiB, still applies).
func (a *Agent) fetchControlPlaneRaw(ctx context.Context, path string) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var raw json.RawMessage
	if err := a.doControlPlaneJSON(reqCtx, http.MethodGet, path, path, nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
