package sshgateway

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
