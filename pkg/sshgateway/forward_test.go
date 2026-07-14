package sshgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// ownerAPIStub stands in for this node's own v1 API. In production
// clusterForwardWrap proxies GET /v1/sandboxes/{id} to the owner; here the stub
// returns the owner's authoritative sandbox view directly so we can exercise the
// edge-side remote auth + routing without a real cluster.
var errNotFoundStub = errors.New("not found")

func ownerAPIStub(t *testing.T, sandbox *models.Sandbox, wantToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantToken != "" && r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if sandbox == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sandbox)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newRemoteGateway(t *testing.T, baseURL, pat string, local *fakeLookup) *Gateway {
	t.Helper()
	return &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		svc:           local,
		remoteBaseURL: baseURL,
		remotePAT:     pat,
	}
}

func TestPublicKeyCallback_RemoteOwned(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	wrongSigner, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	owner := &models.Sandbox{
		ID:           "sb-remote",
		Status:       models.SandboxStatusStarted,
		ContainerIP:  "10.0.0.9",
		SSHPublicKey: authorized,
	}

	t.Run("authorizes against owner key when not held locally", func(t *testing.T) {
		srv := ownerAPIStub(t, owner, "pat-1")
		// Local store does not have the sandbox (remote-owned).
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		perms, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-remote"}, signer.PublicKey())
		if err != nil {
			t.Fatalf("expected remote auth success, got %v", err)
		}
		if perms.Extensions["remote"] != "1" {
			t.Fatalf("expected remote=1 marker, got %+v", perms.Extensions)
		}
		if perms.Extensions["sandbox_id"] != "sb-remote" || perms.Extensions["mode"] != "session" {
			t.Fatalf("unexpected perms: %+v", perms.Extensions)
		}
	})

	t.Run("forged key denied", func(t *testing.T) {
		srv := ownerAPIStub(t, owner, "pat-1")
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-remote"}, wrongSigner.PublicKey()); err == nil {
			t.Fatal("expected permission denied for forged key")
		}
	})

	t.Run("unknown sandbox denied", func(t *testing.T) {
		srv := ownerAPIStub(t, nil, "pat-1") // 404
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "ghost"}, signer.PublicKey()); err == nil {
			t.Fatal("expected permission denied for unknown sandbox")
		}
	})

	t.Run("stopped remote sandbox denied", func(t *testing.T) {
		stopped := *owner
		stopped.Status = models.SandboxStatusStopped
		srv := ownerAPIStub(t, &stopped, "pat-1")
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-remote"}, signer.PublicKey()); err == nil {
			t.Fatal("expected permission denied for stopped sandbox")
		}
	})
}

// TestPublicKeyCallback_SingleNodeNeverRemote asserts the byte-for-byte
// single-node guarantee: with no RemoteAPIBaseURL configured, a local lookup
// miss is a flat denial and the remote path is never attempted.
func TestPublicKeyCallback_SingleNodeNeverRemote(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	// remoteBaseURL empty → single-node.
	g := newRemoteGateway(t, "", "", &fakeLookup{err: errNotFoundStub})
	if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-x"}, signer.PublicKey()); err == nil {
		t.Fatal("expected permission denied; single-node must not attempt remote auth")
	}
}

// TestPublicKeyCallback_LocalWins asserts a locally-owned sandbox takes the
// local path (no remote marker) even when remote routing is configured.
func TestPublicKeyCallback_LocalWins(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	local := &fakeLookup{sandbox: &models.Sandbox{
		ID:           "sb-local",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-1",
		SSHPublicKey: authorized,
	}}
	g := newRemoteGateway(t, "http://127.0.0.1:1/should-not-be-called", "pat", local)
	perms, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-local"}, signer.PublicKey())
	if err != nil {
		t.Fatalf("local auth: %v", err)
	}
	if perms.Extensions["remote"] == "1" {
		t.Fatal("local sandbox must not be marked remote")
	}
}

// ownerSessionStub stands in for the owner's v1 sessions surface that this
// node's clusterForwardWrap reverse-proxies to. It serves the list/create REST
// calls and upgrades the attach path to a WebSocket that streams a stdout frame
// then an exit frame. Every request's forward-id correlation header and PAT are
// captured so the cross-node call shape can be asserted.
type capturedCall struct {
	method    string
	path      string
	auth      string
	forwardID string
	body      []byte
}

func ownerSessionStub(t *testing.T, sandboxID, sessionID string, exitCode int, onAttach func(conn *websocket.Conn)) (string, int, *[]capturedCall) {
	t.Helper()
	calls := &[]capturedCall{}
	base := "/v1/sandboxes/" + sandboxID + "/sessions"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := capturedCall{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), forwardID: r.Header.Get(forwardIDHeader)}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			*calls = append(*calls, rec)
			_, _ = w.Write([]byte(`{"sessions":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == base:
			rec.body, _ = io.ReadAll(r.Body)
			*calls = append(*calls, rec)
			_, _ = w.Write([]byte(`{"id":"` + sessionID + `","name":"s","status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == base+"/"+sessionID+"/attach":
			*calls = append(*calls, rec)
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			if onAttach != nil {
				onAttach(conn)
			}
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStdout}, []byte("remote-ok")...))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":`+strconv.Itoa(exitCode)+`}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	return "http://" + net.JoinHostPort(host, portStr), port, calls
}

// TestHandleRemoteSession_Shell drives the cross-node interactive-shell path:
// the edge node bridges a shell to the owner's session API, forwards a
// mid-session resize, and reports the owner's exit code back over the channel.
func TestHandleRemoteSession_Shell(t *testing.T) {
	gotResize := make(chan struct{}, 1)
	baseURL, _, calls := ownerSessionStub(t, "sb-remote", "sess-r", 9, func(conn *websocket.Conn) {
		// Wait for the forwarded resize control message before exiting so the
		// attachToSession resize goroutine is exercised.
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage && bytes.Contains(data, []byte(`"resize"`)) {
				select {
				case gotResize <- struct{}{}:
				default:
				}
				return
			}
		}
	})

	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat-z",
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()

	requests <- &ssh.Request{Type: "pty-req", Payload: bytes.Join([][]byte{
		encodeString("xterm"), encodeUint32(80), encodeUint32(24), encodeUint32(0), encodeUint32(0), encodeString(""),
	}, nil)}
	requests <- &ssh.Request{Type: "shell"}
	requests <- &ssh.Request{Type: "window-change", Payload: bytes.Join([][]byte{
		encodeUint32(132), encodeUint32(43), encodeUint32(0), encodeUint32(0),
	}, nil)}

	select {
	case <-gotResize:
	case <-time.After(5 * time.Second):
		t.Fatal("owner never received the forwarded resize")
	}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleRemoteSession did not return")
	}

	if got := channel.exitStatus(); got != 9 {
		t.Fatalf("exit status = %d, want 9", got)
	}
	// Every forwarded call must carry the PAT and a correlation id.
	if len(*calls) == 0 {
		t.Fatal("owner saw no calls")
	}
	for _, c := range *calls {
		if c.auth != "Bearer pat-z" {
			t.Fatalf("call %s %s auth = %q, want Bearer pat-z", c.method, c.path, c.auth)
		}
		if c.forwardID == "" {
			t.Fatalf("call %s %s missing forward-id header", c.method, c.path)
		}
	}
}

// TestHandleRemoteSession_Exec drives the cross-node one-shot exec path: the
// command runs as a fresh owner session (POST carries Command) and its exit
// status propagates exactly.
func TestHandleRemoteSession_Exec(t *testing.T) {
	baseURL, _, calls := ownerSessionStub(t, "sb-remote", "sess-x", 3, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
		remotePAT:     "pat-z",
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("echo hi")}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleRemoteSession did not return")
	}

	if got := channel.exitStatus(); got != 3 {
		t.Fatalf("exit status = %d, want 3", got)
	}
	// A one-shot exec skips the list step and POSTs the command directly.
	var posted *capturedCall
	for i := range *calls {
		if (*calls)[i].method == http.MethodPost {
			posted = &(*calls)[i]
		}
		if (*calls)[i].method == http.MethodGet && strings.HasSuffix((*calls)[i].path, "/sessions") {
			t.Fatalf("exec path should not list sessions, saw GET %s", (*calls)[i].path)
		}
	}
	if posted == nil {
		t.Fatal("no create POST observed for exec")
	}
	var cr models.CreateSessionRequest
	if err := json.Unmarshal(posted.body, &cr); err != nil {
		t.Fatalf("decode create body: %v", err)
	}
	if cr.Command != "echo hi" {
		t.Fatalf("create command = %q, want echo hi", cr.Command)
	}
}

// TestHandleRemoteSession_ClientClosesBeforeStart covers the request-channel
// close arriving before any shell/exec was started: the resize channel must be
// closed and the function must return without blocking on the attach.
func TestHandleRemoteSession_ClientClosesBeforeStart(t *testing.T) {
	baseURL, _, _ := ownerSessionStub(t, "sb-remote", "sess-r", 0, nil)
	g := &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		remoteBaseURL: baseURL,
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleRemoteSession(context.Background(), "sb-remote", "default", channel, requests)
	}()
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleRemoteSession did not return on early close")
	}
}

// TestRemoteSessionEndpoint asserts the loopback endpoint targets this node's
// own v1 sessions surface, carries the PAT, and converts http→ws.
func TestRemoteSessionEndpoint(t *testing.T) {
	g := &Gateway{remoteBaseURL: "http://127.0.0.1:8080", remotePAT: "pat"}
	ep := g.remoteSessionEndpoint("sb-1", "fwd-123")
	if ep.baseURL != "http://127.0.0.1:8080/v1/sandboxes/sb-1/sessions" {
		t.Fatalf("baseURL = %q", ep.baseURL)
	}
	if ep.wsURL != "ws://127.0.0.1:8080/v1/sandboxes/sb-1/sessions" {
		t.Fatalf("wsURL = %q", ep.wsURL)
	}
	if ep.auth != "Bearer pat" || ep.forwardID != "fwd-123" {
		t.Fatalf("auth/forwardID = %q/%q", ep.auth, ep.forwardID)
	}
}

func TestHTTPToWS(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8080/v1/x": "ws://127.0.0.1:8080/v1/x",
		"https://node.internal/v1/y": "wss://node.internal/v1/y",
		"ftp://weird":                "ftp://weird",
	}
	for in, want := range cases {
		if got := httpToWS(in); got != want {
			t.Errorf("httpToWS(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHandleSession_ContainerdExecViaToolbox is the UC-43 regression: on the
// containerd engine a one-shot ssh `exec` request must run through the
// in-container toolbox session (POST /sessions carrying Command) rather than
// the docker-exec path, which cannot reach a containerd task (echo would come
// back exit 1). The command's exit status must propagate over the SSH channel.
func TestHandleSession_ContainerdExecViaToolbox(t *testing.T) {
	var posted *models.CreateSessionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			body, _ := io.ReadAll(r.Body)
			var cr models.CreateSessionRequest
			_ = json.Unmarshal(body, &cr)
			posted = &cr
			_, _ = w.Write([]byte(`{"id":"sess-local","name":"exec","status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/sess-local/attach":
			up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStdout}, []byte("ssh-ok")...))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	g := &Gateway{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerEngine: models.ContainerEngineContainerd,
		toolboxPort:     port,
		svc: &fakeLookup{sandbox: &models.Sandbox{
			ID:           "sb-ctd",
			Status:       models.SandboxStatusStarted,
			ContainerID:  "ctr-1",
			ContainerIP:  host,
			ToolboxToken: "tok",
		}},
	}
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-ctd", "session", "default", false, channel, requests)
	}()
	requests <- &ssh.Request{Type: "exec", Payload: encodeString("echo ssh-ok")}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleSession did not return")
	}

	if posted == nil {
		t.Fatal("containerd exec must POST a toolbox session; the docker-exec path was taken instead")
	}
	if posted.Command != "echo ssh-ok" {
		t.Fatalf("toolbox session command = %q, want echo ssh-ok", posted.Command)
	}
	if got := channel.exitStatus(); got != 0 {
		t.Fatalf("exit status = %d, want 0", got)
	}
}
