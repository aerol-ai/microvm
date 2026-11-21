//go:build linux

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// stallReaper parks the reaper on a close that returns only when the test
// releases it (or ends), as a close on a stalled mount would park it.
func stallReaper(t *testing.T) func() {
	t.Helper()
	started, block := make(chan struct{}), make(chan struct{})
	reap(closerFunc(func() error { close(started); <-block; return nil }))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper is busy with something else")
	}
	var once sync.Once
	release := func() {
		once.Do(func() { close(block) })
		// A full queue would hold the idle check's own closer.
		for deadline := time.Now().Add(10 * time.Second); len(reaper.queue) == cap(reaper.queue) && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		waitReaperIdle(t)
	}
	t.Cleanup(release)
	return release
}

// waitReaperIdle returns once the reaper has closed everything queued.
func waitReaperIdle(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	reap(closerFunc(func() error { close(done); return nil }))
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the reaper did not get through its queue")
	}
}

// No request goroutine releases a worker's descriptor: with the reaper
// parked (a stalled mount), a refused reply's descriptor is still held
// when the call returns, wherever the worker put it, and it is released
// once the reaper moves on.
func TestWorkerDescriptorsAreReleasedByTheReaper(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(*pipeProbe, int) fdReply
		call  func(*Client) error
	}{
		{"with a reply", func(p *pipeProbe, fd int) fdReply {
			return fdReply{env: Envelope{Type: MsgPong}, fds: []int{fd}, closeAfter: []*os.File{p.r}}
		}, func(c *Client) error { return c.Ping("sb") }},
		{"queued after a good reply", func(p *pipeProbe, fd int) fdReply {
			body, _ := encodePayload(execStartedPayload{ID: "run-1"})
			return fdReply{env: Envelope{Type: MsgExecStarted, Payload: body}, after: func(uc *net.UnixConn) {
				_, _, _ = uc.WriteMsgUnix([]byte{0}, unix.UnixRights(fd), nil)
				_ = p.r.Close()
			}}
		}, func(c *Client) error {
			// A run's connection stays open past the reply, so the
			// worker's extra segment is queued before the close looks.
			st, err := c.StartExec(context.Background(), "sb", ExecStartPayload{})
			if err != nil {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			_ = st.Close()
			return errors.New("closed")
		}},
		{"as guest_listener's listener", func(p *pipeProbe, fd int) fdReply {
			body, _ := encodePayload(guestListenerResult{Host: "127.0.0.1", Port: 1})
			return fdReply{env: Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, fds: []int{fd}, closeAfter: []*os.File{p.r}}
		}, func(c *Client) error {
			return c.ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{1}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := stallReaper(t)
			probe := newPipeProbe(t)
			fd := probe.fd(t)
			sock, _ := fdWorker(t, func(Envelope) fdReply { return tc.reply(probe, fd) })
			done := make(chan error, 1)
			go func() { done <- tc.call(NewClient(sock)) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("the call succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the call did not return with the reaper parked")
			}
			if workerQuarantined(sock) == nil {
				t.Fatal("the worker was not quarantined")
			}
			if probe.released() {
				t.Fatal("the descriptor was released on the request's goroutine")
			}
			release()
			if !probe.eventuallyReleased() {
				t.Fatal("the reaper never released it")
			}
		})
	}
}

// guest_listener's reply may carry one socket and nothing more: two
// sockets, or a socket and a file, are refused and quarantine the worker.
func TestGuestListenerTakesOneSocket(t *testing.T) {
	ln, served := guestServer(t, "tcp", "127.0.0.1:0")
	lf, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	lfd, _ := rawFD(lf)
	probe := newPipeProbe(t)
	for name, fds := range map[string][]int{"two sockets": {lfd, lfd}, "a socket and a file": {lfd, probe.fd(t)}} {
		sock, _ := fdWorker(t, func(Envelope) fdReply {
			body, _ := encodePayload(guestListenerResult{Host: "127.0.0.1", Port: portOf(ln)})
			return fdReply{env: Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, fds: fds}
		})
		err := NewClient(sock).ProxyHTTPDialed("sb", 8080, "127.0.0.1", []int{portOf(ln)}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if !errors.Is(err, errWorkerSentFDs) || workerQuarantined(sock) == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if served.Load() != 0 {
		t.Fatalf("the guest served %d requests", served.Load())
	}
}

// A streaming run closed early has output left in the queue: the close
// reads it off, finds no descriptor, and closes there (no quarantine, no
// reaper), even with the reaper parked.
func TestStreamClosedEarlyClosesInline(t *testing.T) {
	stallReaper(t)
	var workerSaw atomic.Value
	sock, _ := fdWorker(t, func(Envelope) fdReply {
		body, _ := encodePayload(execStartedPayload{ID: "run-1"})
		return fdReply{env: Envelope{Type: MsgExecStarted, Payload: body}, after: func(uc *net.UnixConn) {
			chunk, _ := encodeFrame(Envelope{Type: MsgExecChunk, Stream: StreamStdout, Payload: make([]byte, 4096)})
			for range 32 {
				if _, err := uc.Write(chunk); err != nil {
					workerSaw.Store(err)
					return
				}
			}
			// Then wait for sandboxd's close to reach the worker.
			_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := uc.Read(make([]byte, 1))
			workerSaw.Store(fmt.Errorf("read after the run: %w", err))
		}}
	})
	st, err := NewClient(sock).StartExec(context.Background(), "sb", ExecStartPayload{})
	if err != nil {
		t.Fatal(err)
	}
	if ev, err := st.Recv(); err != nil || len(ev.Data) != 4096 {
		t.Fatalf("first chunk: %v %v", ev, err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); workerSaw.Load() == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
	}
	if got, _ := workerSaw.Load().(error); got == nil || !errors.Is(got, io.EOF) {
		t.Fatalf("the worker saw %v, want EOF from sandboxd's close", got)
	}
	if err := workerQuarantined(sock); err != nil {
		t.Fatalf("a run's own output quarantined its worker: %v", err)
	}
}

// Out-of-band data is read inline: descriptors on an out-of-band segment
// are seen like any other's (Linux 5.15+ has out-of-band data on Unix
// sockets; a read would otherwise skip the segment and free it, and its
// descriptors, on its own).
func TestOutOfBandDescriptorsAreSeen(t *testing.T) {
	probe := newPipeProbe(t)
	fd := probe.fd(t)
	oob := make(chan error, 1)
	sock, _ := fdWorker(t, func(Envelope) fdReply {
		body, _ := encodePayload(execStartedPayload{ID: "run-1"})
		return fdReply{env: Envelope{Type: MsgExecStarted, Payload: body}, after: func(uc *net.UnixConn) {
			var err error
			rc, _ := uc.SyscallConn()
			_ = rc.Write(func(s uintptr) bool {
				err = unix.Sendmsg(int(s), []byte{'#'}, unix.UnixRights(fd), nil, unix.MSG_OOB)
				return true
			})
			oob <- err
		}}
	})
	st, err := NewClient(sock).StartExec(context.Background(), "sb", ExecStartPayload{})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := <-oob; err != nil {
		_ = st.Close()
		t.Skipf("no out-of-band data on Unix sockets here: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = st.Close()
	if workerQuarantined(sock) == nil {
		t.Fatal("descriptors on an out-of-band segment went unseen")
	}
	_ = probe.r.Close()
	if !probe.eventuallyReleased() {
		t.Fatal("never released")
	}
}

// The reaper never blocks its caller: with it parked and its queue full,
// what comes after is kept open and counted.
func TestReaperQueueFull(t *testing.T) {
	release := stallReaper(t)
	held := workerReaperHeld.Value()
	var closed atomic.Int64
	done := make(chan struct{})
	go func() {
		for range reaperQueue + 5 {
			reap(closerFunc(func() error { closed.Add(1); return nil }))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reap blocked")
	}
	if got := workerReaperHeld.Value() - held; got != 5 {
		t.Fatalf("held %d, want 5", got)
	}
	release()
	if closed.Load() != reaperQueue {
		t.Fatalf("closed %d of the %d queued", closed.Load(), reaperQueue)
	}
	reaper.mu.Lock()
	reaper.held = nil
	reaper.mu.Unlock()
}

const quarantineChildEnv = "AEROL_WASM_QUARANTINE_CHILD"

// TestQuarantineChild is a hostile worker: it answers every request with
// a pong that carries one of its descriptors.
func TestQuarantineChild(t *testing.T) {
	sock := os.Getenv(quarantineChildEnv)
	if sock == "" {
		t.Skip("child half of TestQuarantineStopsTheWorker")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(3)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		go func(c *net.UnixConn) {
			defer c.Close()
			if _, files, err := readFrameFiles(c); err == nil {
				closeFiles(files)
				_ = writeFrameFiles(c, Envelope{Type: MsgPong, FDPaths: []string{"x"}}, []*os.File{os.Stdin})
				_, _ = io.Copy(io.Discard, c)
			}
		}(c.(*net.UnixConn))
	}
}

// Review round 4, F4: a worker that broke the protocol is killed through
// its supervisor and not restarted; its slot answers ErrWorkerQuarantined
// until it is stopped, and sandboxd opens no connection to it. Stop ends
// the quarantine.
func TestQuarantineStopsTheWorker(t *testing.T) {
	sock := shortTempDir(t) + "/q.sock"
	sup := NewSupervisor(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestQuarantineChild$")
		cmd.Env = append(os.Environ(), quarantineChildEnv+"="+socketPath)
		return cmd, nil
	})
	t.Cleanup(func() { _ = sup.Stop("sb-q") })
	ensure := func() {
		t.Helper()
		if err := sup.Ensure(context.Background(), "sb-q", sock); err != nil {
			t.Fatal(err)
		}
	}
	ensure()
	c := NewClient(sock)
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err = c.Ping("sb-q"); err != nil && !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "no such file") {
			break
		}
	}
	if !errors.Is(err, errWorkerSentFDs) {
		t.Fatalf("ping = %v", err)
	}
	sup.mu.Lock()
	st := sup.slots["sb-q"]
	sup.mu.Unlock()
	select {
	case <-st.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker was not killed")
	}
	time.Sleep(100 * time.Millisecond)
	if n := sup.SpawnCount("sb-q"); n != 1 {
		t.Fatalf("spawned %d times: a quarantined worker was restarted", n)
	}
	if err := sup.Ensure(context.Background(), "sb-q", sock); !errors.Is(err, ErrWorkerQuarantined) {
		t.Fatalf("Ensure on a quarantined slot = %v", err)
	}
	if err := c.Ping("sb-q"); !errors.Is(err, ErrWorkerQuarantined) {
		t.Fatalf("a dial to a quarantined worker = %v", err)
	}
	if err := sup.Stop("sb-q"); err != nil {
		t.Fatal(err)
	}
	if err := workerQuarantined(sock); err != nil {
		t.Fatalf("Stop did not end the quarantine: %v", err)
	}
	ensure()
	if n := sup.SpawnCount("sb-q"); n != 1 {
		t.Fatalf("after Stop: spawn count %d", n)
	}
	// An adopted worker in a quarantined slot is not taken over either.
	sup.quarantine(sock)
	if sup.Adopt("sb-q", sock, fakeProc{}) {
		t.Fatal("a quarantined slot adopted a worker")
	}
}

// fakeProc is a process that never ends.
type fakeProc struct{}

func (fakeProc) Pid() int                    { return 1 }
func (fakeProc) Signal(syscall.Signal) error { return nil }
func (fakeProc) Done() <-chan struct{}       { return make(chan struct{}) }
func (fakeProc) Close() error                { return nil }

// A connection whose read deadline has passed (a cancelled request)
// still closes where it is closed when nothing is left in its queue: the
// reaper is for connections that may hold a worker's descriptors.
func TestExpiredConnectionClosesInline(t *testing.T) {
	stallReaper(t)
	sawClose := make(chan error, 1)
	sock, _ := fdWorker(t, func(Envelope) fdReply {
		return fdReply{env: Envelope{Type: MsgPong}, after: func(uc *net.UnixConn) {
			_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := uc.Read(make([]byte, 1))
			sawClose <- err
		}}
	})
	conn, err := dialWorker(NewClient(sock).dial, sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, Envelope{Type: MsgHealthPing}); err != nil {
		t.Fatal(err)
	}
	if reply, err := readFrame(conn); err != nil || reply.Type != MsgPong {
		t.Fatalf("reply %v %v", reply.Type, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sawClose:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("the worker saw %v, want EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the close went to the reaper")
	}
	if err := workerQuarantined(sock); err != nil {
		t.Fatal(err)
	}
}
