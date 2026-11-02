package sshgateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/aerol-ai/microvm/pkg/models"
)

// recordingLookup is a SandboxLookup that also records sessions, the way
// *service.Service does.
type recordingLookup struct {
	fakeLookup
	mu       sync.Mutex
	sessions []string // sandbox|session per record
}

func (r *recordingLookup) RecordSSHSession(_ context.Context, sandboxID, session string) {
	r.mu.Lock()
	r.sessions = append(r.sessions, sandboxID+"|"+session)
	r.mu.Unlock()
}

func (r *recordingLookup) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sessions...)
}

// TestSessionOpenWritesOneRecord is UC-287's gateway half (CEO review D3):
// opening an SSH session over a real connection writes exactly one audit
// record naming the sandbox, before the command runs.
func TestSessionOpenWritesOneRecord(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "host_key"))
	if err != nil {
		t.Fatal(err)
	}
	lookup := &recordingLookup{fakeLookup: fakeLookup{sandbox: &models.Sandbox{
		ID: "sb-1", Status: models.SandboxStatusStarted, ContainerID: "ctr-1",
		SSHPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}}}
	dockerCli := &fakeDockerExec{createID: "exec-1", startSession: newTestExecSession(t, "ok"), inspectCode: 0}
	g := &Gateway{logger: logger, svc: lookup, dockerCli: dockerCli, signer: signer}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		g.handleConn(context.Background(), conn)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{
		User: "sb-1+exec", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	if got := lookup.recorded(); len(got) != 0 {
		t.Fatalf("records before any session opened: %v", got)
	}
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	exitCh := captureExitStatus(requests)
	if ok, err := channel.SendRequest("exec", true, encodeString("true")); err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	_ = channel.CloseWrite()
	_, _ = io.ReadAll(channel)
	waitForExitStatus(t, exitCh)
	_ = channel.Close()
	_ = client.Close()
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
	if got := lookup.recorded(); len(got) != 1 || got[0] != "sb-1|" {
		t.Fatalf("session records = %v, want one for sb-1 with no toolbox session (exec mode)", got)
	}
}

func TestRecordSessionModes(t *testing.T) {
	lookup := &recordingLookup{}
	g := &Gateway{svc: lookup}
	g.recordSession(context.Background(), "sb-1", "session", "default")
	g.recordSession(context.Background(), "sb-1", "exec", "ignored")
	g.recordSession(context.Background(), "", "session", "default")
	if got := lookup.recorded(); strings.Join(got, ",") != "sb-1|default,sb-1|" {
		t.Fatalf("records = %v", got)
	}
	// A lookup that cannot record (tests, other embedders) records nothing.
	(&Gateway{svc: &fakeLookup{}}).recordSession(context.Background(), "sb-1", "session", "default")
}

// gatedRecorder is a recordingLookup that also answers the owner-record
// gate, the way *service.Service does in cluster mode.
type gatedRecorder struct {
	recordingLookup
	ownerRecords bool
}

func (g *gatedRecorder) SSHSessionsRecordedByOwner() bool { return g.ownerRecords }

// bridgedCall is one request the gateway made to its own node's API.
type bridgedCall struct {
	route  string // "METHOD /path"
	header http.Header
}

// bridgeAPIStub stands in for this node's own v1 API, which in production
// forwards to the owner: it answers the auth lookup with the owner's view of
// the sandbox, serves the sessions surface (list, create, attach with an
// exit frame), and keeps every request's headers.
func bridgeAPIStub(t *testing.T, sandbox *models.Sandbox) (string, func() []bridgedCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []bridgedCall
	base := "/v1/sandboxes/" + sandbox.ID
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, bridgedCall{route: r.Method + " " + r.URL.Path, header: r.Header.Clone()})
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			_ = json.NewEncoder(w).Encode(sandbox)
		case r.Method == http.MethodGet && r.URL.Path == base+"/sessions":
			_, _ = w.Write([]byte(`{"sessions":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == base+"/sessions":
			_, _ = w.Write([]byte(`{"id":"sess-1","name":"s","status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == base+"/sessions/sess-1/attach":
			conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []bridgedCall {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(calls)
	}
}

// runSSHSession opens one SSH connection to g as user, runs one session
// channel with request ("shell", or "exec" of `true`), and waits for the
// gateway to finish with the connection.
func runSSHSession(t *testing.T, g *Gateway, signer ssh.Signer, user, request string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		g.handleConn(context.Background(), conn)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	exitCh := captureExitStatus(requests)
	var payload []byte
	if request == "exec" {
		payload = encodeString("true")
	}
	if ok, err := channel.SendRequest(request, true, payload); err != nil || !ok {
		t.Fatalf("%s: ok=%v err=%v", request, ok, err)
	}
	waitForExitStatus(t, exitCh)
	_ = channel.Close()
	_ = client.Close()
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
}

// TestRemoteSessionRecordedByOwner is UC-287's gateway half on a cluster.
// A session bridged to the sandbox's owner used to be recorded on this
// node, which the sandbox's audit read never asks, and its calls carried
// only the operator token, so the owner recorded them as the operator's.
// Now every bridged call is attested as this gateway acting for the
// sandbox's key, and the session's first call carries the open marker that
// asks the owner to write the one ssh record; nothing is recorded here.
// Until every member runs a build that honours the marker (or with a lookup
// that cannot say), the gateway records here as before and sends no marker,
// so a session never gets two records or none. The auth lookup, made before
// the key is known to match, is never attested.
func TestRemoteSessionRecordedByOwner(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "host_key"))
	if err != nil {
		t.Fatal(err)
	}
	owner := &models.Sandbox{ID: "sb-remote", Status: models.SandboxStatusStarted, SSHPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}
	remote := func() recordingLookup { return recordingLookup{fakeLookup: fakeLookup{err: errNotFoundStub}} }
	const sessions = "/v1/sandboxes/sb-remote/sessions"
	cases := []struct {
		name, user, request string
		lookup              interface {
			SandboxLookup
			recorded() []string
		}
		wantLocal   []string
		wantOpen    string // the route of the one call that opens the session; "" for none
		wantSession string
	}{
		{name: "a login that runs a command: the owner records it", user: "sb-remote", request: "exec",
			lookup: &gatedRecorder{recordingLookup: remote(), ownerRecords: true}, wantOpen: "POST " + sessions, wantSession: "default"},
		{name: "a shell: the session list opens it", user: "sb-remote+prod", request: "shell",
			lookup: &gatedRecorder{recordingLookup: remote(), ownerRecords: true}, wantOpen: "GET " + sessions, wantSession: "prod"},
		{name: "a one-shot exec login names no session", user: "sb-remote+exec", request: "exec",
			lookup: &gatedRecorder{recordingLookup: remote(), ownerRecords: true}, wantOpen: "POST " + sessions, wantSession: ""},
		{name: "rolling upgrade: the gateway records here, as before", user: "sb-remote", request: "exec",
			lookup: &gatedRecorder{recordingLookup: remote()}, wantLocal: []string{"sb-remote|default"}},
		{name: "a lookup that cannot answer the gate records here", user: "sb-remote", request: "exec",
			lookup: func() *recordingLookup { l := remote(); return &l }(), wantLocal: []string{"sb-remote|default"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, calls := bridgeAPIStub(t, owner)
			g := &Gateway{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), svc: tc.lookup, signer: signer, remoteBaseURL: baseURL, remotePAT: "pat-z"}
			runSSHSession(t, g, signer, tc.user, tc.request)

			if got := tc.lookup.recorded(); !slices.Equal(got, tc.wantLocal) {
				t.Fatalf("records on the gateway's node = %v, want %v", got, tc.wantLocal)
			}
			var opened []string
			bridged := 0
			for _, c := range calls() {
				if c.route == "GET /v1/sandboxes/sb-remote" {
					if c.header.Get(headerBridgedCall) != "" || c.header.Get(headerBridgedCallMAC) != "" {
						t.Fatalf("the auth lookup was attested for the key before it matched: %v", c.header)
					}
					continue
				}
				bridged++
				if c.header.Get("Authorization") != "Bearer pat-z" {
					t.Fatalf("%s lost the loopback credential: %v", c.route, c.header)
				}
				call, ok := TakeBridgedCall(c.header, "sb-remote")
				if !ok {
					t.Fatalf("%s is not attested as this gateway acting for sb-remote's key: %v", c.route, c.header)
				}
				if call.Open {
					opened = append(opened, c.route)
					if call.Session != tc.wantSession {
						t.Fatalf("open marker names session %q, want %q", call.Session, tc.wantSession)
					}
				}
			}
			if bridged < 2 {
				t.Fatalf("bridged calls = %d, want the session's create or list and its attach", bridged)
			}
			if (tc.wantOpen == "" && len(opened) != 0) || (tc.wantOpen != "" && !slices.Equal(opened, []string{tc.wantOpen})) {
				t.Fatalf("calls carrying the open marker = %v, want exactly %q", opened, tc.wantOpen)
			}
		})
	}
}
