package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/raft"
)

// API warm-pool entries over the cluster (plans/agent-sandbox-feature-
// parity.md W1).
//
//	PUT/DELETE on any node ─► server tier ─► leader: fv gate ─► opPutWarmPool / opDeleteWarmPool
//	worker with a warm pool ─► polls POST warm-pools/read {since} (unchanged | full list)
//	server node ─────────────► reads its own FSM
//
// Writes use a dedicated internal endpoint, like egress profiles and API
// tokens: the caller needs the stored record back, and only a leader that
// has checked every Raft server's build may apply the op, so an older
// leader can never commit an op its followers would apply and it wouldn't
// (or the reverse).
const (
	PublicInternalWarmPoolWritePath = "/v1/cluster/internal/warm-pools/write"
	PublicInternalWarmPoolReadPath  = "/v1/cluster/internal/warm-pools/read"
)

// Outcome codes of a warm-pool write, carried in a 200 body so the sentinel
// survives any number of forwarding hops.
const (
	warmPoolCodeLimit          = "limit"
	warmPoolCodeClusterVersion = "cluster_version"
)

// WarmPoolWriteRequest puts (Delete false) or deletes one entry. A delete
// needs only the image.
type WarmPoolWriteRequest struct {
	Delete bool           `json:"delete,omitempty"`
	Pool   WarmPoolRecord `json:"pool"`
}

// WarmPoolWriteResponse is the outcome. Code is set, and Pool empty, when
// the FSM or the upgrade gate refused the write.
type WarmPoolWriteResponse struct {
	Pool    WarmPoolRecord `json:"pool"`
	Changed bool           `json:"changed"`
	Code    string         `json:"code,omitempty"`
	Message string         `json:"message,omitempty"`
}

// WarmPoolReadRequest reads every entry. Since is the Version of the last
// answer the reader applied; 0 asks for the list whatever it is.
type WarmPoolReadRequest struct {
	Since uint64 `json:"since,omitempty"`
}

// WarmPoolReadResponse answers a read from a server's FSM. Unchanged means
// Since is current and Pools is left out.
type WarmPoolReadResponse struct {
	Version       uint64           `json:"version"`
	Unchanged     bool             `json:"unchanged,omitempty"`
	Pools         []WarmPoolRecord `json:"pools,omitempty"`
	Authoritative bool             `json:"authoritative"`
}

// WarmPoolWriteOutcome turns a write error into the body a peer gets, and
// err back into the same error, so sentinels survive forwarding.
func WarmPoolWriteOutcome(err error) WarmPoolWriteResponse {
	switch {
	case errors.Is(err, ErrWarmPoolLimit):
		return WarmPoolWriteResponse{Code: warmPoolCodeLimit, Message: err.Error()}
	case errors.Is(err, ErrClusterVersion):
		return WarmPoolWriteResponse{Code: warmPoolCodeClusterVersion, Message: err.Error()}
	}
	return WarmPoolWriteResponse{}
}

func (r WarmPoolWriteResponse) err() error {
	var sentinel error
	switch r.Code {
	case "":
		return nil
	case warmPoolCodeLimit:
		sentinel = ErrWarmPoolLimit
	case warmPoolCodeClusterVersion:
		sentinel = ErrClusterVersion
	default:
		return fmt.Errorf("cluster: warm pool write: %s: %s", r.Code, r.Message)
	}
	return fmt.Errorf("%w (%s)", sentinel, r.Message)
}

// WriteWarmPool puts or deletes an entry. The leader checks the upgrade
// gate and applies; a follower forwards one hop to the leader. The proposer
// stamps the time into the entry, so every replica applies the same one.
func (c *Cluster) WriteWarmPool(ctx context.Context, req WarmPoolWriteRequest) (WarmPoolWriteResponse, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return WarmPoolWriteResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	if c.raft.raft.State() != raft.Leader {
		var out WarmPoolWriteResponse
		if err := c.forwardToLeaderJSON(ctx, "warm pool write", PublicInternalWarmPoolWritePath, req, &out); err != nil {
			return WarmPoolWriteResponse{}, err
		}
		return out, out.err()
	}
	if err := c.raftServersSupport(warmPoolFSMOpsVersion, "warm pools"); err != nil {
		return WarmPoolWriteResponse{}, err
	}
	pool := req.Pool
	cmd := command{Op: opPutWarmPool, WarmPool: &pool, StampUnixNano: time.Now().UnixNano()}
	if req.Delete {
		cmd.Op = opDeleteWarmPool
	}
	payload, err := encodeCommand(cmd)
	if err != nil {
		return WarmPoolWriteResponse{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return WarmPoolWriteResponse{}, err
	}
	if applied, ok := result.(warmPoolApplyResult); ok {
		return WarmPoolWriteResponse{Pool: applied.Pool, Changed: applied.Changed}, nil
	}
	return WarmPoolWriteResponse{}, nil
}

// ReadWarmPools answers from this server's FSM.
func (c *Cluster) ReadWarmPools(_ context.Context, req WarmPoolReadRequest) (WarmPoolReadResponse, error) {
	if c == nil || c.fsm == nil {
		return WarmPoolReadResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.readWarmPools(req), nil
}

// WriteWarmPool sends an entry write to the server tier; any server takes
// it and forwards it to the leader.
func (a *Agent) WriteWarmPool(ctx context.Context, req WarmPoolWriteRequest) (WarmPoolWriteResponse, error) {
	if a == nil {
		return WarmPoolWriteResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out WarmPoolWriteResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalWarmPoolWritePath, PublicInternalWarmPoolWritePath, req, &out); err != nil {
		return WarmPoolWriteResponse{}, fmt.Errorf("cluster: warm pool write: %w", err)
	}
	return out, out.err()
}

// ReadWarmPools reads the entries from the server tier. A dedicated worker
// holds no FSM; it polls this with the last Version it applied, so a quiet
// fleet costs each poll one small "unchanged" answer.
func (a *Agent) ReadWarmPools(ctx context.Context, req WarmPoolReadRequest) (WarmPoolReadResponse, error) {
	if a == nil {
		return WarmPoolReadResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out WarmPoolReadResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalWarmPoolReadPath, PublicInternalWarmPoolReadPath, req, &out); err != nil {
		return WarmPoolReadResponse{}, fmt.Errorf("cluster: read warm pools: %w", err)
	}
	if !out.Authoritative {
		return WarmPoolReadResponse{}, fmt.Errorf("cluster: warm pool read was not authoritative")
	}
	return out, nil
}
