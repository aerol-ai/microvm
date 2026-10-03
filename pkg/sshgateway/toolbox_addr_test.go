package sshgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// addressingDockerExec is a fakeDockerExec that also answers ToolboxAddress,
// the way *docker.Client does under SB_DOCKER_TOOLBOX_LOOPBACK.
type addressingDockerExec struct {
	*fakeDockerExec
	addr  string
	err   error
	asked []string
}

func (a *addressingDockerExec) ToolboxAddress(_ context.Context, sb *models.Sandbox) (string, error) {
	a.asked = append(a.asked, sb.ID)
	return a.addr, a.err
}

// unroutableIP is TEST-NET-1: a session test only passes if the gateway
// dialed the address the Docker client reported, not the container IP.
const unroutableIP = "192.0.2.10"

func TestSessionToolboxAddr(t *testing.T) {
	sb := &models.Sandbox{ID: "sb-1", ContainerIP: unroutableIP}
	for _, tc := range []struct {
		name   string
		engine string
		cli    DockerExec
		want   string
		err    bool
	}{
		{name: "fake_without_addresser", cli: &fakeDockerExec{}, want: unroutableIP + ":2280"},
		{name: "docker_addresser", cli: &addressingDockerExec{fakeDockerExec: &fakeDockerExec{}, addr: "127.0.0.1:49153"}, want: "127.0.0.1:49153"},
		{name: "containerd_ignores_docker_addresser", engine: models.ContainerEngineContainerd,
			cli: &addressingDockerExec{fakeDockerExec: &fakeDockerExec{}, addr: "127.0.0.1:49153"}, want: unroutableIP + ":2280"},
		{name: "addresser_error", cli: &addressingDockerExec{fakeDockerExec: &fakeDockerExec{}, err: errors.New("not published")}, err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Gateway{dockerCli: tc.cli, toolboxPort: 2280, containerEngine: tc.engine}
			got, err := g.sessionToolboxAddr(context.Background(), sb)
			if tc.err {
				if err == nil {
					t.Fatal("sessionToolboxAddr() expected error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("sessionToolboxAddr() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestLocalSessionEndpointAtMatchesLegacyShape(t *testing.T) {
	legacy := localSessionEndpoint("10.0.0.5", 2280, "tok")
	at := localSessionEndpointAt("10.0.0.5:2280", "tok")
	if legacy != at {
		t.Fatalf("localSessionEndpoint = %+v, localSessionEndpointAt = %+v", legacy, at)
	}
	if at.baseURL != "http://10.0.0.5:2280/sessions" || at.wsURL != "ws://10.0.0.5:2280/sessions" || at.auth != "Bearer tok" {
		t.Fatalf("endpoint = %+v", at)
	}
}

func runSessionShell(t *testing.T, g *Gateway) *fakeChannel {
	t.Helper()
	channel := &fakeChannel{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	requests := make(chan *ssh.Request, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handleSession(context.Background(), "sb-1", "session", "default", false, channel, requests)
	}()
	requests <- &ssh.Request{Type: "shell"}
	close(requests)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleSession did not return")
	}
	return channel
}

func TestHandleSession_ShellUsesDockerToolboxAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			_, _ = w.Write([]byte(`{"sessions":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/sessions":
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte(`{"id":"sess-local","name":"default","status":"running"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/sess-local/attach":
			up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamFramePrefixStdout}, []byte("loopback-ok")...))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"exit","code":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cli := &addressingDockerExec{fakeDockerExec: &fakeDockerExec{}, addr: srv.Listener.Addr().String()}
	g := &Gateway{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		toolboxPort: 2280,
		dockerCli:   cli,
		svc: &fakeLookup{sandbox: &models.Sandbox{
			ID: "sb-1", Status: models.SandboxStatusStarted, ContainerID: "ctr-1",
			ContainerIP: unroutableIP, ToolboxToken: "tok",
		}},
	}
	channel := runSessionShell(t, g)
	if got := channel.exitStatus(); got != 0 {
		t.Fatalf("exit status = %d, stderr = %q", got, channel.stderr.(*bytes.Buffer).String())
	}
	if !strings.Contains(channel.stdout.(*bytes.Buffer).String(), "loopback-ok") {
		t.Fatalf("stdout = %q, want session output via the reported address", channel.stdout.(*bytes.Buffer).String())
	}
	if len(cli.asked) != 1 || cli.asked[0] != "sb-1" {
		t.Fatalf("docker client asked for %v, want [sb-1]", cli.asked)
	}
}

func TestHandleSession_ShellToolboxAddressError(t *testing.T) {
	g := &Gateway{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		toolboxPort: 2280,
		dockerCli:   &addressingDockerExec{fakeDockerExec: &fakeDockerExec{}, err: errors.New("toolbox port is not published")},
		svc: &fakeLookup{sandbox: &models.Sandbox{
			ID: "sb-1", Status: models.SandboxStatusStarted, ContainerID: "ctr-1", ContainerIP: unroutableIP,
		}},
	}
	channel := runSessionShell(t, g)
	if got := channel.exitStatus(); got != 1 {
		t.Fatalf("exit status = %d, want 1", got)
	}
	if !strings.Contains(channel.stderr.(*bytes.Buffer).String(), "toolbox unavailable: toolbox port is not published") {
		t.Fatalf("stderr = %q", channel.stderr.(*bytes.Buffer).String())
	}
}
