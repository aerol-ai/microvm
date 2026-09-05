package sshgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// Cross-node SSH forwarding (cluster mode).
//
// In cluster mode a sandbox is owned by exactly one node, but the leased SSH
// domain load-balances across every ingress node, so a client frequently lands
// on a node that does not own the target sandbox. The container and its
// per-sandbox key live only on the owner.
//
// Rather than build a bespoke SSH-over-mTLS stream, this reuses the data path
// the rest of the daemon already relies on: every per-sandbox v1 route is
// wrapped with clusterForwardWrap, which reverse-proxies the request — WebSocket
// upgrades included — to the owner over the cert-pinned mTLS internal channel.
// The edge therefore talks to its OWN node's v1 API over loopback; the cluster
// layer does the cross-node hop. The only material that crosses nodes is the
// sandbox's *public* key (for auth) and the session byte stream.

// newForwardID returns a short correlation ID stamped on the forwarded calls and
// the edge's log lines for one SSH session, so the edge and owner sides can be
// joined when debugging.
func newForwardID() string { return uuid.NewString()[:8] }

// authorizeRemoteSSH authenticates a connection for a sandbox this node does not
// own. It fetches the owner's authoritative sandbox view (public key + status)
// through the local v1 API and verifies the offered key against it. Returns
// (perms, true) only on success; every failure returns (nil, false) so the
// caller collapses to "permission denied" without leaking which step failed.
func (g *Gateway) authorizeRemoteSSH(ctx context.Context, sandboxID, mode, sessionName string, key ssh.PublicKey) (*ssh.Permissions, bool) {
	forwardID := newForwardID()
	remote, err := g.fetchRemoteSandbox(ctx, sandboxID, forwardID)
	if err != nil || remote == nil {
		g.logger.Info("ssh auth: remote owner lookup failed", "sandbox_id", sandboxID, "forward_id", forwardID, "error", err)
		return nil, false
	}
	if remote.Status != models.SandboxStatusStarted {
		g.logger.Info("ssh auth: remote sandbox not running", "sandbox_id", sandboxID, "forward_id", forwardID, "status", string(remote.Status))
		return nil, false
	}
	if authErr := authorizeKey(remote.SSHPublicKey, key); authErr != nil {
		g.logger.Info("ssh auth: remote sandbox not authorized", "sandbox_id", sandboxID, "forward_id", forwardID, "error", authErr)
		return nil, false
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"sandbox_id":   sandboxID,
			"mode":         mode,
			"session_name": sessionName,
			"remote":       "1",
		},
	}, true
}

// fetchRemoteSandbox GETs /v1/sandboxes/<id> on this node's own API. When the
// sandbox is owned by a peer, clusterForwardWrap forwards the request to the
// owner and returns its sandbox row (which includes ssh_public_key + status).
// A 404 (unknown sandbox) or any non-2xx yields a nil sandbox and no error so
// the caller treats it as a clean auth failure.
func (g *Gateway) fetchRemoteSandbox(ctx context.Context, sandboxID, forwardID string) (*models.Sandbox, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint := g.remoteBaseURL + "/v1/sandboxes/" + url.PathEscape(sandboxID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if g.remotePAT != "" {
		req.Header.Set("Authorization", "Bearer "+g.remotePAT)
	}
	if forwardID != "" {
		req.Header.Set(forwardIDHeader, forwardID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Not found / not ours / not ready — not an authorization for this key.
		return nil, nil
	}
	var sandbox models.Sandbox
	if err := json.NewDecoder(resp.Body).Decode(&sandbox); err != nil {
		return nil, fmt.Errorf("decode remote sandbox: %w", err)
	}
	return &sandbox, nil
}

// handleRemoteSession services an SSH session channel for a sandbox owned by
// another node. It mirrors handleSession's request handling but always bridges
// to the owner's toolbox session API via this node's v1 surface — there is no
// local container to docker-exec into. The interactive shell attaches to a
// named session on the owner; a one-shot exec runs the command as a fresh
// session whose exit status is reported back exactly.
//
// The attach runs concurrently with the request loop so mid-session
// window-change events can be forwarded as PTY resizes (UC-9).
func (g *Gateway) handleRemoteSession(ctx context.Context, sandboxID, sessionName string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	forwardID := newForwardID()
	ep := g.remoteSessionEndpoint(sandboxID, forwardID)
	state := &sessionState{envVars: make([]string, 0, 4)}

	resize := make(chan [2]uint32, 4)
	done := make(chan int, 1)
	started := false
	start := func() {
		if started {
			return
		}
		started = true
		// The request loop continues accepting window-change messages while the
		// attach runs. Give the goroutine an immutable launch snapshot so a late
		// SSH request cannot race session creation parameters.
		launchState := *state
		launchState.envVars = append([]string(nil), state.envVars...)
		launchName := sessionName
		g.logger.Info("ssh remote session start", "sandbox_id", sandboxID, "forward_id", forwardID, "session", launchName, "exec", launchState.execCommand != "")
		go func() { done <- g.attachToSession(ctx, channel, ep, launchName, &launchState, resize) }()
	}
	finish := func(code int) {
		_ = sendExitStatus(channel, uint32(code))
		close(resize)
		g.logger.Info("ssh remote session end", "sandbox_id", sandboxID, "forward_id", forwardID, "exit_code", code)
	}

	for {
		select {
		case code := <-done:
			finish(code)
			return
		case req, ok := <-requests:
			if !ok {
				// Client closed the channel. Drain the in-flight attach if one
				// was started so we still report its exit status.
				if started {
					finish(<-done)
				} else {
					close(resize)
				}
				return
			}
			switch req.Type {
			case "pty-req":
				if started {
					replyRequest(req, false)
					continue
				}
				term, rows, cols, ok := parsePTYRequest(req.Payload)
				if !ok {
					replyRequest(req, false)
					continue
				}
				state.wantPTY = true
				state.ptyRows = rows
				state.ptyCols = cols
				if term != "" {
					state.envVars = append(state.envVars, "TERM="+term)
				}
				replyRequest(req, true)

			case "env":
				if started {
					replyRequest(req, false)
					continue
				}
				name, value, ok := parseEnvRequest(req.Payload)
				if ok && allowEnvVar(name) {
					state.envVars = append(state.envVars, name+"="+value)
				}
				replyRequest(req, true)

			case "shell":
				if started {
					replyRequest(req, false)
					continue
				}
				replyRequest(req, true)
				start()

			case "exec":
				if started {
					replyRequest(req, false)
					continue
				}
				command, ok := parseExecRequest(req.Payload)
				if !ok || strings.TrimSpace(command) == "" {
					replyRequest(req, false)
					continue
				}
				replyRequest(req, true)
				// A one-shot exec runs as its own short-lived session so its
				// exact exit code propagates; never reuse a named shell.
				state.execCommand = command
				sessionName = "exec-" + forwardID
				start()

			case "window-change":
				rows, cols, ok := parseWindowChange(req.Payload)
				if !ok {
					continue
				}
				if started {
					select {
					case resize <- [2]uint32{cols, rows}:
					default:
					}
				} else {
					state.ptyRows = rows
					state.ptyCols = cols
				}

			default:
				if req.WantReply {
					replyRequest(req, false)
				}
			}
		}
	}
}

// remoteSessionEndpoint targets this node's own v1 sessions surface for the
// sandbox; clusterForwardWrap forwards it to the owner. The loopback hop uses
// the PAT; the owner injects the real toolbox token on its side.
func (g *Gateway) remoteSessionEndpoint(sandboxID, forwardID string) sessionEndpoint {
	httpRoot := g.remoteBaseURL + "/v1/sandboxes/" + url.PathEscape(sandboxID) + "/sessions"
	return sessionEndpoint{
		baseURL:   httpRoot,
		wsURL:     httpToWS(httpRoot),
		auth:      bearer(g.remotePAT),
		forwardID: forwardID,
	}
}

// httpToWS rewrites an http(s) URL scheme to the ws(s) equivalent.
func httpToWS(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://")
	default:
		return u
	}
}
