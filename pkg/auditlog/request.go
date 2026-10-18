package auditlog

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
)

// API action records (plans/identity-and-access.md §5.9). Create, delete,
// exec, file, port, snapshot and token calls used to leave no chain record;
// each now writes one of kind "api" that names the caller and the call.
// The types live here, beside Event, because the daemon writes them and the
// offline CLI (`aerolvm audit search`, `aerolvm access review`) reads them,
// and the CLI may not import a server package.

// Record kinds this file adds. Each one is hash-covered and unknown to a
// binary older than the release that writes it, so writers emit them only
// behind the same cluster gate as Caller.
const (
	// KindAPI is one API call, an SSH session open, or a destructive action
	// the daemon took on its own (lifecycle, reconcile).
	KindAPI = "api"
	// KindAuthDenied is a refused credential (a 401), at most one per
	// source address per minute; Dropped counts the 401s from that address
	// the limit folded into it.
	KindAuthDenied = "auth_denied"
	// KindAPIFloodMode records a change of the node's effective flood
	// control mode: a coalesce-only node that gained a second owner now
	// budgets too, and the switch is part of the evidence.
	KindAPIFloodMode = "api_flood_mode"
)

// Result values of an api record. A 403 is "denied" (who tried what they
// may not do); any other 4xx or 5xx is "error".
const (
	APIResultOK     = "ok"
	APIResultDenied = "denied"
	APIResultError  = "error"
)

// ReasonRateLimited marks the record that stands for calls the flood
// budget did not write one by one: Dropped is how many, Request.Routes
// which routes they hit, Caller who made them.
const ReasonRateLimited = "rate_limited"

// Surfaces a call can arrive through besides a direct API request.
const (
	// SurfaceMCP is a remote MCP tool's inner API call.
	SurfaceMCP = "mcp"
	// SurfaceSSH is an SSH session opened through the gateway.
	SurfaceSSH = "ssh"
)

// RefSSH is the ref of an SSH session-open record.
const RefSSH = "ssh"

// APIResultForStatus maps an HTTP status onto an api record's result.
func APIResultForStatus(status int) string {
	switch {
	case status == 401 || status == 403:
		return APIResultDenied
	case status >= 400:
		return APIResultError
	}
	return APIResultOK
}

// Request is the call behind an api record. Every field is omitempty, so a
// record carries only what applies to it. Field order is part of the hash:
// append only.
type Request struct {
	// Method and Route are the HTTP method and the route pattern the call
	// matched ("POST /v1/sandboxes/{id}/exec"), never the raw path, which
	// can carry ids and query values.
	Method string `json:"method,omitempty"`
	Route  string `json:"route,omitempty"`
	// Status is the response status; 101 for a WebSocket upgrade, recorded
	// at the upgrade.
	Status int `json:"status,omitempty"`
	// Digest is the hex SHA-256 of an exec request body, hashed as it
	// streamed. It proves which command ran without recording it.
	Digest string `json:"digest,omitempty"`
	// Count is how many identical calls one coalesced record stands for.
	// Absent means one.
	Count int64 `json:"count,omitempty"`
	// Surface is how the call arrived when not as a direct API request:
	// SurfaceMCP or SurfaceSSH.
	Surface string `json:"surface,omitempty"`
	// Argv is the command an exec ran, only with SB_AUDIT_EXEC_COMMAND=full.
	// Never the environment.
	Argv []string `json:"argv,omitempty"`
	// Target is the object a call acted on when it is not a sandbox: the
	// token, snapshot, egress profile, WASM module, JS bundle or template id
	// from the route's path; on a toolbox route, the sub-path inside the
	// sandbox ("process/execute").
	Target string `json:"target,omitempty"`
	// Routes lists the routes a rate_limited record's calls hit.
	Routes []string `json:"routes,omitempty"`
	// Source is the client address of an auth_denied record.
	Source string `json:"source,omitempty"`
	// Grant is the role and team a token create gave the token it minted
	// (Target is its id), so "who minted this admin token" survives the
	// token row's deletion (§5.9; T5b's access review reads it).
	Grant *Grant `json:"grant,omitempty"`
}

// Grant is what a credential-minting call handed out. Field order is part
// of the hash: append only.
type Grant struct {
	Role string `json:"role"`
	Team string `json:"team"`
}

// CallState is what one API request's record learns while the request
// runs: whether a forward path handed the call to a peer (which records it
// instead), and the sandbox or object the call turned out to act on when
// the route's path does not name it (a create learns its new sandbox id).
// The API edge attaches one per recorded request; everything below the
// edge only marks it, through the helpers below, never reads it.
type CallState struct {
	forwarded     atomic.Bool
	forwardFailed atomic.Bool

	mu            sync.Mutex
	sandboxID     string
	incarnationID string
	ownerRef      string
	target        string
	grant         *Grant
}

type callStateKey struct{}

// ContextWithCallState returns ctx carrying a fresh CallState. A nested
// request (a remote MCP tool's inner call) gets its own, so marking one
// never touches the other.
func ContextWithCallState(ctx context.Context) (context.Context, *CallState) {
	if ctx == nil {
		ctx = context.Background()
	}
	st := &CallState{}
	return context.WithValue(ctx, callStateKey{}, st), st
}

// CallStateFromContext returns the CallState ctx carries, or nil.
func CallStateFromContext(ctx context.Context) *CallState {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(callStateKey{}).(*CallState)
	return st
}

// MarkForwarded records that the request was handed to a peer, which runs
// the handler and writes the record; the edge then writes none (§5.9,
// "Forwarding"). cluster.StampForward calls it on every forward path.
func MarkForwarded(ctx context.Context) {
	if st := CallStateFromContext(ctx); st != nil {
		st.forwarded.Store(true)
	}
}

// MarkForwardFailed records that the forward itself failed (the edge
// answered 502 without reaching the peer), so the edge records the call
// after all: no peer ever saw it.
func MarkForwardFailed(ctx context.Context) {
	if st := CallStateFromContext(ctx); st != nil {
		st.forwardFailed.Store(true)
	}
}

// NoteSandbox records the sandbox a call acted on when the route's path
// does not carry it (a Daytona name resolved to its id).
func NoteSandbox(ctx context.Context, sandboxID string) {
	NoteSandboxIdentity(ctx, sandboxID, "", "")
}

// NoteSandboxIdentity is NoteSandbox with the sandbox's lifecycle and owner,
// when the caller already holds them: a create learns its new id here, so
// the create record names the sandbox (the creator is found through it) and
// stamping it needs no lookup.
func NoteSandboxIdentity(ctx context.Context, sandboxID, incarnationID, ownerRef string) {
	st := CallStateFromContext(ctx)
	if st == nil {
		return
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return
	}
	st.mu.Lock()
	st.sandboxID = sandboxID
	st.incarnationID = strings.TrimSpace(incarnationID)
	st.ownerRef = strings.TrimSpace(ownerRef)
	st.mu.Unlock()
}

// NoteTarget records the object a call created when the route's path does
// not name it (token create records the new token id, §5.9).
func NoteTarget(ctx context.Context, target string) {
	st := CallStateFromContext(ctx)
	if st == nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	st.mu.Lock()
	st.target = target
	st.mu.Unlock()
}

// NoteCreatedToken records the token a token create minted: its id as the
// record's target and the role and team it carries as the record's grant.
func NoteCreatedToken(ctx context.Context, id, role, team string) {
	st := CallStateFromContext(ctx)
	if st == nil {
		return
	}
	NoteTarget(ctx, id)
	st.mu.Lock()
	st.grant = &Grant{Role: strings.TrimSpace(role), Team: strings.TrimSpace(team)}
	st.mu.Unlock()
}

// Forwarded reports whether a forward path handed the call to a peer.
func (s *CallState) Forwarded() bool { return s != nil && s.forwarded.Load() }

// ForwardFailed reports whether that forward failed before reaching the peer.
func (s *CallState) ForwardFailed() bool { return s != nil && s.forwardFailed.Load() }

// SandboxID is the sandbox NoteSandbox recorded, or "".
func (s *CallState) SandboxID() string {
	id, _, _ := s.SandboxIdentity()
	return id
}

// SandboxIdentity is the sandbox NoteSandboxIdentity recorded and, when it
// was given, its lifecycle and owner.
func (s *CallState) SandboxIdentity() (sandboxID, incarnationID, ownerRef string) {
	if s == nil {
		return "", "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sandboxID, s.incarnationID, s.ownerRef
}

// Target is the object NoteTarget recorded, or "".
func (s *CallState) Target() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target
}

// Grant is the grant NoteCreatedToken recorded, or nil.
func (s *CallState) Grant() *Grant {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grant == nil {
		return nil
	}
	g := *s.grant
	return &g
}

type surfaceKey struct{}

// ContextWithSurface marks ctx as a call that arrived through surface
// (SurfaceMCP). Only in-process code sets it; nothing on the wire can.
func ContextWithSurface(ctx context.Context, surface string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, surfaceKey{}, surface)
}

// SurfaceFromContext returns the surface ContextWithSurface attached, or "".
func SurfaceFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(surfaceKey{}).(string)
	return s
}
