package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/runloop"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The api recorder (plans/identity-and-access.md §5.9) is the T2 audit seam
// (apihttp.AuditHook) filled in: every permission-tagged route hands it the
// request after authorization, and it writes one kind "api" chain record
// per call, after the handler decided the status.
//
//	Route ─► authenticate ─► authorize ─► recordRoute ─► handler
//	                              │              └─► Service.RecordAPICall ─► buffered writer
//	                              └─ 403: recordRoute(next=nil) records it as denied
//
// What it records (SB_AUDIT_API_RECORDS):
//   - mutations (default): every non-GET call, every toolbox call (file
//     reads included: files can hold secrets), token listing, and every
//     refused call, whatever its method;
//   - all: plain GETs as well;
//   - never: cluster.internal routes (node-to-node control traffic, not a
//     caller's action), /health, and the outer /mcp request (each tool's
//     inner call records itself).
//
// Only the node that runs the handler records: a forward path marks the
// call (cluster.StampForward → auditlog.MarkForwarded) and the edge writes
// nothing, unless the forward itself failed.

// shouldRecordCall is the SB_AUDIT_API_RECORDS rule for an allowed call.
func shouldRecordCall(r *http.Request, perm controlplane.Permission, policy service.APIAuditPolicy) bool {
	switch perm {
	case controlplane.PermClusterInternal:
		return false
	case controlplane.PermSandboxExec, controlplane.PermTokenRead:
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return policy.AllReads
	}
	return true
}

// recordRoute is the AuditHook. NewServer installs it unless
// SB_AUDIT_API_RECORDS=off, so "off" costs nothing per request.
func (s *Server) recordRoute(w http.ResponseWriter, r *http.Request, call apihttp.RouteCall, next http.Handler) {
	if call.Permission == controlplane.PermClusterInternal {
		if next != nil {
			next.ServeHTTP(w, r)
		}
		return
	}
	policy := s.service.APIAuditPolicy()
	if next == nil {
		// Refused: its 403 is already written. A refusal is recorded
		// whatever the method; it answers "who tried what they may not do".
		if policy.Enabled {
			desc := describeRoute(r)
			s.service.RecordAPICall(r.Context(), service.APICall{
				Method: r.Method, Route: desc.route, Status: http.StatusForbidden,
				SandboxID: desc.sandboxID, Target: desc.target, Denied: true,
				Surface: requestSurface(r),
			})
		}
		return
	}
	if !policy.Enabled || !shouldRecordCall(r, call.Permission, policy) {
		next.ServeHTTP(w, r)
		return
	}
	ctx, state := auditlog.ContextWithCallState(r.Context())
	desc := describeRoute(r)
	// requestSurface: a peer's MCP forward is recorded with surface mcp on
	// the owner, the node that runs it (X-Cluster-Surface from a live peer).
	rec := &pendingAPIRecord{
		svc:     s.service,
		ctx:     ctx,
		state:   state,
		method:  r.Method,
		desc:    desc,
		surface: requestSurface(r),
		durable: policy.Durable && (desc.deletesSandbox || call.Permission == controlplane.PermTokenWrite),
	}
	if desc.deletesSandbox && desc.sandboxID != "" {
		// A successful delete ends the lifecycle and forgets it; resolve
		// it now so the record still lands in the sandbox's history.
		rec.inc, rec.owner = s.service.AuditIdentityForSandbox(desc.sandboxID)
	}
	if call.Permission == controlplane.PermSandboxExec && requestHasBody(r) {
		rec.body = newDigestBody(r.Body, state, policy.ExecArgv)
		r.Body = rec.body
	}
	rw := &recordingWriter{ResponseWriter: w, early: rec.emit}
	defer func() {
		// A handler that panics still made the call: record it (as a 500
		// unless a status was already sent), then let net/http see the
		// panic as before.
		if p := recover(); p != nil {
			status := http.StatusInternalServerError
			if rw.status != 0 {
				status = rw.status
			}
			rec.emit(status)
			panic(p)
		}
	}()
	next.ServeHTTP(rw, r.WithContext(ctx))
	rec.emit(rw.statusCode())
}

// requestHasBody reports whether r carries a body worth hashing.
func requestHasBody(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// pendingAPIRecord is one call's record, written once: at the WebSocket
// upgrade or the first flush of a stream (so a long session is on record
// while it runs, status 101 or 200), or when the handler returns.
type pendingAPIRecord struct {
	svc        *service.Service
	ctx        context.Context
	state      *auditlog.CallState
	method     string
	desc       routeDesc
	inc, owner string
	surface    string
	body       *digestBody
	durable    bool
	once       sync.Once
}

func (p *pendingAPIRecord) emit(status int) {
	p.once.Do(func() {
		if p.state.Forwarded() && !p.state.ForwardFailed() {
			return // the peer that ran the handler records it
		}
		if g, ok := auditlog.SSHGatewayCallFromContext(p.ctx); ok && g.Open {
			// The first call of a bridged SSH session writes the session's
			// one ssh record, on the node that runs it: the owner, whose
			// audit is the sandbox's.
			p.svc.RecordSSHSession(p.ctx, g.SandboxID, g.Session)
		}
		call := service.APICall{
			Method:        p.method,
			Route:         p.desc.route,
			Status:        status,
			SandboxID:     p.desc.sandboxID,
			IncarnationID: p.inc,
			OwnerRef:      p.owner,
			Target:        p.desc.target,
			Surface:       p.surface,
			Durable:       p.durable,
		}
		if id, inc, owner := p.state.SandboxIdentity(); id != "" && id != call.SandboxID {
			// The handler named the sandbox (a create's new id, a Daytona
			// name resolved to its id): its identity is the one to stamp.
			call.SandboxID, call.IncarnationID, call.OwnerRef = id, inc, owner
		}
		if t := p.state.Target(); t != "" {
			call.Target = t
		}
		call.Grant = p.state.Grant()
		if p.body != nil {
			call.Digest = p.body.digest()
			call.Argv = p.body.argv()
		}
		p.svc.RecordAPICall(p.ctx, call)
	})
}

// routeDesc is what a record says about the route a call matched.
type routeDesc struct {
	// route is the pattern without its method ("/v1/sandboxes/{id}/exec").
	route string
	// sandboxID is the sandbox the path names; target the other object it
	// names (a snapshot, profile, module, bundle, template, token or node
	// id; a toolbox sub-path).
	sandboxID, target string
	// deletesSandbox marks the call that ends the sandbox's life.
	deletesSandbox bool
}

// sandboxPathSegments are the path segments a sandbox id follows in every
// surface's patterns: /v1/sandboxes/{id}, /e2b/sandboxes/{id},
// /daytona/sandbox/{idOrName}, /daytona/toolbox/{id}.
var sandboxPathSegments = map[string]bool{"sandboxes": true, "sandbox": true, "toolbox": true}

// describeRoute reads the route off the pattern the mux matched and the
// path values it bound. The raw path is never recorded: it can carry query
// values, and ids belong in their own fields.
func describeRoute(r *http.Request) routeDesc {
	pattern := routePattern(r)
	if strings.HasPrefix(pattern, runloop.DevboxesPath) {
		route, sandboxID, target, deletes := runloop.AuditRoute(r)
		return routeDesc{route: route, sandboxID: sandboxID, target: target, deletesSandbox: deletes}
	}
	desc := routeDesc{route: pattern}
	segs := strings.Split(strings.Trim(pattern, "/"), "/")
	for i, seg := range segs {
		if len(seg) < 3 || seg[0] != '{' || seg[len(seg)-1] != '}' {
			continue
		}
		name := strings.TrimSuffix(seg[1:len(seg)-1], "...")
		value := strings.TrimSpace(r.PathValue(name))
		if value == "" {
			continue
		}
		if i > 0 && sandboxPathSegments[segs[i-1]] && desc.sandboxID == "" {
			desc.sandboxID = value
			desc.deletesSandbox = r.Method == http.MethodDelete && i == len(segs)-1
			continue
		}
		if desc.target == "" {
			desc.target = value
		}
	}
	return desc
}

// recordingWriter remembers the status and tells the record when the call
// turned into a long-lived stream (a hijacked WebSocket, a flushed
// response), so the record is written then rather than when it ends.
type recordingWriter struct {
	http.ResponseWriter
	status int
	early  func(status int)
}

func (w *recordingWriter) WriteHeader(code int) {
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
		if code == http.StatusSwitchingProtocols {
			w.early(code)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not implement http.Hijacker")
	}
	conn, rw, err := hj.Hijack()
	if err == nil {
		w.status = http.StatusSwitchingProtocols
		w.early(http.StatusSwitchingProtocols)
	}
	return conn, rw, err
}

func (w *recordingWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.early(w.status)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the writer underneath.
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *recordingWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// execArgvCaptureMax bounds how much of an exec body is kept to read its
// argv (SB_AUDIT_EXEC_COMMAND=full only). Commands are small; a body past
// this is a file upload, not a command.
const execArgvCaptureMax = 64 << 10

// digestBody hashes an exec request body as the handler reads it: the
// record proves which command ran without the body ever being buffered
// (I5). Once the call is forwarded to a peer it stops hashing, since the
// peer records the call and hashes the same bytes.
type digestBody struct {
	io.ReadCloser
	h       hash.Hash
	n       int64
	state   *auditlog.CallState
	capture *bytes.Buffer
}

func newDigestBody(body io.ReadCloser, state *auditlog.CallState, captureArgv bool) *digestBody {
	d := &digestBody{ReadCloser: body, h: sha256.New(), state: state}
	if captureArgv {
		d.capture = &bytes.Buffer{}
	}
	return d
}

func (d *digestBody) Read(p []byte) (int, error) {
	n, err := d.ReadCloser.Read(p)
	if n > 0 && !d.state.Forwarded() {
		_, _ = d.h.Write(p[:n])
		d.n += int64(n)
		if d.capture != nil && d.capture.Len() < execArgvCaptureMax {
			room := execArgvCaptureMax - d.capture.Len()
			d.capture.Write(p[:min(n, room)])
		}
	}
	return n, err
}

// digest is the hex SHA-256 of what the handler read, or "" if it read
// nothing.
func (d *digestBody) digest() string {
	if d == nil || d.n == 0 {
		return ""
	}
	return hex.EncodeToString(d.h.Sum(nil))
}

// argv extracts the command from a captured JSON exec body. It reads only
// the fields every surface names its command with (argv; cmd with args;
// command) and never the environment. A body that is not a JSON object, or
// was cut at the capture cap, yields nothing.
func (d *digestBody) argv() []string {
	if d == nil || d.capture == nil || d.capture.Len() == 0 || d.capture.Len() >= execArgvCaptureMax {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(d.capture.Bytes(), &fields); err != nil {
		return nil
	}
	if argv := jsonStrings(fields["argv"]); len(argv) > 0 {
		return argv
	}
	if cmd := jsonStrings(fields["cmd"]); len(cmd) > 0 {
		return append(cmd, jsonStrings(fields["args"])...)
	}
	return jsonStrings(fields["command"])
}

// jsonStrings reads a JSON string or array of strings.
func jsonStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		return many
	}
	return nil
}
