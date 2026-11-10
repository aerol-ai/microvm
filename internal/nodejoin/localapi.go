package nodejoin

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

	"github.com/aerol-ai/microvm/internal/cluster"
)

// localAPI is this node's own sandboxd, called with the node's PAT over
// loopback: the leader check after init, the token and adopt calls, the
// membership wait after a join, and the delete reset asks for. Loopback is
// a host origin, so it works under SB_PAT_SCOPE=host too.
type localAPI struct {
	base   string
	pat    string
	client *http.Client
}

// apiError is a refusal from the local API: its status and message.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("sandboxd answered %d: %s", e.status, e.message)
}

func (l *localAPI) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(l.base, "/")+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if l.pat != "" {
		req.Header.Set("Authorization", "Bearer "+l.pat)
	}
	client := l.client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{status: resp.StatusCode, message: errorMessage(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("sandboxd sent an unreadable answer to %s %s: %w", method, path, err)
	}
	return nil
}

// errorMessage is the "error" field of a JSON refusal, or the raw text.
func errorMessage(raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Error != "" {
		return body.Error
	}
	return strings.TrimSpace(string(raw))
}

// localMember is the part of a member record the commands read.
type localMember struct {
	NodeID string `json:"node_id"`
	Role   string `json:"role"`
	Alive  bool   `json:"alive"`
	Voter  bool   `json:"voter"`
	Leader bool   `json:"leader"`
}

func (l *localAPI) leader(ctx context.Context) (string, error) {
	var out struct {
		Leader string `json:"leader"`
	}
	err := l.do(ctx, http.MethodGet, "/v1/cluster/leader", nil, &out)
	return out.Leader, err
}

func (l *localAPI) members(ctx context.Context) ([]localMember, error) {
	var out struct {
		Members []localMember `json:"members"`
	}
	err := l.do(ctx, http.MethodGet, "/v1/cluster/members", nil, &out)
	return out.Members, err
}

func (l *localAPI) createToken(ctx context.Context, req cluster.JoinTokenCreateRequest) (cluster.JoinTokenCreated, error) {
	var out cluster.JoinTokenCreated
	err := l.do(ctx, http.MethodPost, cluster.PublicJoinTokensPath, req, &out)
	return out, err
}

func (l *localAPI) adopt(ctx context.Context, req cluster.AdoptRequest) (cluster.AdoptResponse, error) {
	var out cluster.AdoptResponse
	err := l.do(ctx, http.MethodPost, cluster.PublicAdoptPath, req, &out)
	return out, err
}

func (l *localAPI) deleteNode(ctx context.Context, nodeID string) (cluster.NodeDeleteResult, error) {
	var out cluster.NodeDeleteResult
	err := l.do(ctx, http.MethodDelete, cluster.PublicNodesPath+url.PathEscape(nodeID)+"?force=true", nil, &out)
	return out, err
}

// pollEvery is how often the waits below ask again.
var pollEvery = 2 * time.Second

// waitFor asks check until it reports done, the context ends, or timeout
// passes; the last error explains a timeout.
func waitFor(ctx context.Context, timeout time.Duration, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	for {
		done, err := check(ctx)
		if done {
			return nil
		}
		// The call cut short by the deadline says nothing new; keep the
		// last real reason.
		if err != nil && (ctx.Err() == nil || last == nil) {
			last = err
		}
		select {
		case <-ctx.Done():
			if last == nil {
				last = errors.New("still not ready")
			}
			return fmt.Errorf("waited %s: %w", timeout, last)
		case <-time.After(pollEvery):
		}
	}
}

// waitForLeader waits until this node leads (init's seed) and returns.
func (l *localAPI) waitForLeader(ctx context.Context, self string, timeout time.Duration) error {
	return waitFor(ctx, timeout, func(ctx context.Context) (bool, error) {
		leader, err := l.leader(ctx)
		if err != nil {
			return false, err
		}
		if leader != self {
			return false, fmt.Errorf("the leader is %q, not this node", leader)
		}
		return true, nil
	})
}

// waitForMember waits until self is an alive member and returns its record.
func (l *localAPI) waitForMember(ctx context.Context, self string, timeout time.Duration) (localMember, error) {
	var found localMember
	err := waitFor(ctx, timeout, func(ctx context.Context) (bool, error) {
		members, err := l.members(ctx)
		if err != nil {
			return false, err
		}
		for _, m := range members {
			if m.NodeID == self && m.Alive {
				found = m
				return true, nil
			}
		}
		return false, fmt.Errorf("%s is not an alive member yet (%d members)", self, len(members))
	})
	return found, err
}
