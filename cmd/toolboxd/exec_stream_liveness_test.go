package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newExecStreamTestServer serves handleExecStream. A non-zero liveness scales
// the keepalive down so the RR1 proofs run in about a second; the tests keep
// production's ratio of ping interval to deadline roughly intact.
func newExecStreamTestServer(t *testing.T, liveness ...execStreamLiveness) string {
	t.Helper()
	s := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if len(liveness) > 0 {
		s.execLiveness = liveness[0]
	}
	httpSrv := httptest.NewServer(http.HandlerFunc(s.handleExecStream))
	t.Cleanup(httpSrv.Close)
	return httpSrv.URL
}

func dialExecStream(t *testing.T, baseURL string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(baseURL, "http"), nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readShellPID reads stdout frames until the first line, which the test
// commands make the shell's PID (= its process group, via Setpgid/Setsid).
func readShellPID(t *testing.T, conn *websocket.Conn) int {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var out strings.Builder
	for !strings.Contains(out.String(), "\n") {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read pid: %v (so far %q)", err, out.String())
		}
		if msgType == websocket.BinaryMessage && len(payload) > 1 {
			out.Write(payload[1:])
		}
	}
	pid, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(out.String(), "\n", 2)[0]))
	if err != nil || pid <= 0 {
		t.Fatalf("parse pid from %q: %v", out.String(), err)
	}
	return pid
}

// waitGroupGone polls until no process in group pgid can be signalled.
func waitGroupGone(t *testing.T, pgid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	t.Fatalf("process group %d still alive after %v", pgid, within)
}

func readExit(t *testing.T, conn *websocket.Conn, within time.Duration) execStreamControlOut {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read until exit: %v", err)
		}
		if msgType != websocket.TextMessage {
			continue
		}
		var ctrl execStreamControlOut
		if err := json.Unmarshal(payload, &ctrl); err == nil && ctrl.Type == "exit" {
			return ctrl
		}
	}
}

// TestExecStreamDropKillsProcessGroup is the CEO review CF3 proof: when the
// client vanishes mid-command, toolboxd kills the whole process group, and
// the background child the shell started goes with it.
func TestExecStreamDropKillsProcessGroup(t *testing.T) {
	for _, tty := range []bool{false, true} {
		t.Run(map[bool]string{false: "pipes", true: "pty"}[tty], func(t *testing.T) {
			conn := dialExecStream(t, newExecStreamTestServer(t))
			if err := conn.WriteJSON(map[string]any{"command": "echo $$; sleep 300 & sleep 300", "tty": tty}); err != nil {
				t.Fatalf("start: %v", err)
			}
			pgid := readShellPID(t, conn)
			if err := syscall.Kill(-pgid, 0); err != nil {
				t.Fatalf("precondition: group %d not running: %v", pgid, err)
			}
			// Drop without a close handshake, like a killed client.
			_ = conn.UnderlyingConn().Close()
			waitGroupGone(t, pgid, 2*time.Second)
		})
	}
}

// TestExecStreamNormalExitStillReportsExit pins that kill-on-drop leaves the
// normal path alone: a finished command reports its code, and the close that
// follows doesn't count as a drop.
func TestExecStreamNormalExitStillReportsExit(t *testing.T) {
	conn := dialExecStream(t, newExecStreamTestServer(t))
	if err := conn.WriteJSON(map[string]any{"command": "exit 3"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := readExit(t, conn, 5*time.Second); got.Code != 3 || got.Signal != "" {
		t.Fatalf("exit = %+v, want code 3", got)
	}
}

// idleClosingProxy forwards TCP and closes a connection once no bytes have
// moved in either direction for idle — the behaviour of load balancers and
// CDN proxies that drop quiet WebSockets.
func idleClosingProxy(t *testing.T, target string, idle time.Duration) (addr string, closedIdle *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	closedIdle = &atomic.Int32{}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			var last atomic.Int64
			last.Store(time.Now().UnixNano())
			var once sync.Once
			closeBoth := func(idleClose bool) {
				once.Do(func() {
					if idleClose {
						closedIdle.Add(1)
					}
					_ = client.Close()
					_ = upstream.Close()
				})
			}
			pipe := func(dst, src net.Conn) {
				buf := make([]byte, 32*1024)
				for {
					_ = src.SetReadDeadline(time.Now().Add(idle / 4))
					n, err := src.Read(buf)
					if n > 0 {
						last.Store(time.Now().UnixNano())
						if _, werr := dst.Write(buf[:n]); werr != nil {
							closeBoth(false)
							return
						}
					}
					if err != nil {
						var nerr net.Error
						if errors.As(err, &nerr) && nerr.Timeout() {
							if time.Since(time.Unix(0, last.Load())) > idle {
								closeBoth(true)
								return
							}
							continue
						}
						closeBoth(false)
						return
					}
				}
			}
			go pipe(upstream, client)
			go pipe(client, upstream)
		}
	}()
	return ln.Addr().String(), closedIdle
}

// TestExecStreamKeepaliveSurvivesIdleProxy is the RR1 proof, scaled down: a
// command that prints nothing for longer than the proxy's idle timeout still
// completes, because the pings keep bytes moving.
func TestExecStreamKeepaliveSurvivesIdleProxy(t *testing.T) {
	base := newExecStreamTestServer(t, execStreamLiveness{pingInterval: 50 * time.Millisecond, pongWait: 600 * time.Millisecond})
	proxyAddr, closedIdle := idleClosingProxy(t, strings.TrimPrefix(base, "http://"), 250*time.Millisecond)
	conn := dialExecStream(t, "http://"+proxyAddr)
	if err := conn.WriteJSON(map[string]any{"command": "sleep 1.2"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	// readExit keeps the client reading, so gorilla's default ping handler
	// answers every ping, as the SDK read loops do.
	if got := readExit(t, conn, 10*time.Second); got.Code != 0 || got.Signal != "" {
		t.Fatalf("exit = %+v, want a clean exit", got)
	}
	if n := closedIdle.Load(); n != 0 {
		t.Fatalf("the idle proxy closed %d connections; pings did not keep the stream alive", n)
	}
}

// TestExecStreamMissingPongsKillCommand is the other half of RR1: a client
// that stops answering pings (a dead peer whose socket hasn't errored yet)
// trips the read deadline, which kills the command like any other drop.
func TestExecStreamMissingPongsKillCommand(t *testing.T) {
	conn := dialExecStream(t, newExecStreamTestServer(t, execStreamLiveness{pingInterval: 50 * time.Millisecond, pongWait: 300 * time.Millisecond}))
	conn.SetPingHandler(func(string) error { return nil }) // never pong
	if err := conn.WriteJSON(map[string]any{"command": "echo $$; sleep 30"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	pgid := readShellPID(t, conn)
	// Keep reading so pings arrive (and go unanswered) until the server gives up.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	waitGroupGone(t, pgid, 3*time.Second)
}

func TestExecStreamLivenessDefaults(t *testing.T) {
	if got := (&server{}).execStreamLiveness(); got != defaultExecStreamLiveness {
		t.Fatalf("zero config = %+v, want defaults", got)
	}
	if got := (&server{execLiveness: execStreamLiveness{pingInterval: time.Second}}).execStreamLiveness(); got != defaultExecStreamLiveness {
		t.Fatalf("partial config = %+v, want defaults", got)
	}
	got := (&server{execLiveness: execStreamLiveness{pingInterval: time.Second, pongWait: 3 * time.Second}}).execStreamLiveness()
	if got.pingInterval != time.Second || got.pongWait != 3*time.Second || got.pingWriteWait != defaultExecStreamLiveness.pingWriteWait {
		t.Fatalf("override = %+v", got)
	}
	if defaultExecStreamLiveness.pingInterval != 30*time.Second || defaultExecStreamLiveness.pongWait != 90*time.Second {
		t.Fatalf("production keepalive drifted from the reviewed 30s/90s: %+v", defaultExecStreamLiveness)
	}
}

func TestExecStreamKillerGuards(t *testing.T) {
	// No process: nothing to kill, and no panic.
	newExecStreamKiller(nil).streamDropped()
	k := &execStreamKiller{pgid: -1}
	k.streamDropped()
	// After exit the group must be left alone even with a real PID.
	k = &execStreamKiller{pgid: 1}
	k.markExited()
	k.streamDropped()
}
