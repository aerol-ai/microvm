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

// authorizeRemoteSSH authenticates a connection for a sandbox this node does not
// own. It fetches the owner's authoritative sandbox view (public key + status)
// through the local v1 API and verifies the offered key against it. Returns
// (perms, true) only on success; every failure returns (nil, false) so the
// caller collapses to "permission denied" without leaking which step failed.
func (g *Gateway) authorizeRemoteSSH(ctx context.Context, sandboxID, mode, sessionName string, key ssh.PublicKey) (*ssh.Permissions, bool) {
	remote, err := g.fetchRemoteSandbox(ctx, sandboxID)
	if err != nil || remote == nil {
		g.logger.Info("ssh auth: remote owner lookup failed", "sandbox_id", sandboxID, "error", err)
		return nil, false
	}
	if remote.Status != models.SandboxStatusStarted {
		g.logger.Info("ssh auth: remote sandbox not running", "sandbox_id", sandboxID, "status", string(remote.Status))
		return nil, false
	}
	if authErr := authorizeKey(remote.SSHPublicKey, key); authErr != nil {
		g.logger.Info("ssh auth: remote sandbox not authorized", "sandbox_id", sandboxID, "error", authErr)
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
func (g *Gateway) fetchRemoteSandbox(ctx context.Context, sandboxID string) (*models.Sandbox, error) {
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
// local container to docker-exec into. Both the interactive shell and a
// one-shot exec command run inside a toolbox session on the owner.
func (g *Gateway) handleRemoteSession(ctx context.Context, sandboxID, sessionName string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	ep := g.remoteSessionEndpoint(sandboxID)
	state := &sessionState{envVars: make([]string, 0, 4)}

	for req := range requests {
		switch req.Type {
		case "pty-req":
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
			name, value, ok := parseEnvRequest(req.Payload)
			if ok && allowEnvVar(name) {
				state.envVars = append(state.envVars, name+"="+value)
			}
			replyRequest(req, true)

		case "shell":
			replyRequest(req, true)
			exitCode := g.attachToSession(ctx, channel, ep, sessionName, state)
			_ = sendExitStatus(channel, uint32(exitCode))
			return

		case "exec":
			// One-shot command: run it inside the session shell on the owner.
			// We can't docker-exec across nodes, so the command is fed as the
			// session's first stdin line. This preserves the cross-node
			// behaviour for `ssh <id> -- <cmd>`; exit status is the session's.
			command, ok := parseExecRequest(req.Payload)
			if !ok || strings.TrimSpace(command) == "" {
				replyRequest(req, false)
				continue
			}
			replyRequest(req, true)
			state.execCommand = command
			exitCode := g.attachToSession(ctx, channel, ep, sessionName, state)
			_ = sendExitStatus(channel, uint32(exitCode))
			return

		case "window-change":
			// Best-effort: the toolbox session was created with the initial
			// PTY size; mid-session resize over the forwarded attach is not
			// wired yet (matches the local session path).

		default:
			if req.WantReply {
				replyRequest(req, false)
			}
		}
	}
}

// remoteSessionEndpoint targets this node's own v1 sessions surface for the
// sandbox; clusterForwardWrap forwards it to the owner. The loopback hop uses
// the PAT; the owner injects the real toolbox token on its side.
func (g *Gateway) remoteSessionEndpoint(sandboxID string) sessionEndpoint {
	httpRoot := g.remoteBaseURL + "/v1/sandboxes/" + url.PathEscape(sandboxID) + "/sessions"
	return sessionEndpoint{
		baseURL: httpRoot,
		wsURL:   httpToWS(httpRoot),
		auth:    bearer(g.remotePAT),
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
