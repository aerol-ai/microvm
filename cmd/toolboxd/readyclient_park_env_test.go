//go:build linux

package main

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// hostAdopt plays sandboxd on the host end of a parked handshake: it reads
// the parked hello, writes frameLine (one raw line, so a test can send what
// EncodeAdopt would refuse), and returns the ack, or the read error when the
// guest sends none.
func hostAdopt(host net.Conn, frameLine string) (readyproto.ReadySignal, error) {
	br := bufio.NewReader(host)
	if _, err := readyproto.DecodeParked(br); err != nil {
		return readyproto.ReadySignal{}, err
	}
	if _, err := io.WriteString(host, frameLine); err != nil {
		return readyproto.ReadySignal{}, err
	}
	return readyproto.Decode(br)
}

func adoptLine(t *testing.T, env map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := readyproto.EncodeAdopt(&buf, readyproto.AdoptFrame{SandboxID: "sb-env", Token: "sandbox-tok", Nonce: "adopt-n", Env: env}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The held-back image command starts after the env is in the store and the
// ack is out, so it sees the env; the ack proves the env to the host.
func TestParkedHandshakeHeldCommandSeesEnv(t *testing.T) {
	withSandboxEnv(t, nil)
	var mu sync.Mutex
	var startedEnv []string
	var startedArgs []string
	oldStart := startUserCommandFn
	startUserCommandFn = func(_ *slog.Logger, args []string) {
		mu.Lock()
		defer mu.Unlock()
		startedArgs = append([]string(nil), args...)
		startedEnv = childEnviron() // what the real startUserCommand gives the child
	}
	t.Cleanup(func() { startUserCommandFn = oldStart })

	srv := &server{logger: slog.Default(), parkedMode: true, deferredCmd: []string{"/entrypoint.sh", "serve"}}
	guest, host := net.Pipe()
	t.Cleanup(func() { _ = guest.Close(); _ = host.Close() })
	env := map[string]string{"BANK_SECRET": envCanary, "PATH": "/opt/app/bin:/usr/bin"}
	type result struct {
		ack readyproto.ReadySignal
		err error
	}
	hostDone := make(chan result, 1)
	go func() {
		ack, err := hostAdopt(host, adoptLine(t, env))
		hostDone <- result{ack, err}
	}()
	if err := parkedReadyOnConn(slog.Default(), srv, guest, "boot-tok", "park-n"); err != nil {
		t.Fatalf("guest: %v", err)
	}
	res := <-hostDone
	if res.err != nil {
		t.Fatalf("host: %v", res.err)
	}
	if !readyproto.EnvDigestMatches("adopt-n", env, res.ack.EnvDigest) {
		t.Fatalf("ack %+v does not prove the env", res.ack)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(startedArgs, []string{"/entrypoint.sh", "serve"}) {
		t.Fatalf("held command = %v", startedArgs)
	}
	for _, want := range []string{"BANK_SECRET=" + envCanary, "PATH=/opt/app/bin:/usr/bin"} {
		if !slices.Contains(startedEnv, want) {
			t.Fatalf("held command's env lacks %q", strings.SplitN(want, "=", 2)[0])
		}
	}
}

// A frame whose env can't be applied gets no ack and starts nothing: the
// host's wait for the ack fails, and it goes cold.
func TestParkedHandshakeBadEnvSendsNoAckAndStartsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"empty key", `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":{"":"` + envCanary + `"}}` + "\n"},
		{"NUL in value", `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":{"K":"` + envCanary + `\u0000"}}` + "\n"},
		{"env not an object", `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":"` + envCanary + `"}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSandboxEnv(t, nil)
			started := false
			oldStart := startUserCommandFn
			startUserCommandFn = func(*slog.Logger, []string) { started = true }
			t.Cleanup(func() { startUserCommandFn = oldStart })

			srv := &server{logger: slog.Default(), parkedMode: true, deferredCmd: []string{"/entrypoint.sh"}}
			guest, host := net.Pipe()
			t.Cleanup(func() { _ = host.Close() })
			hostDone := make(chan error, 1)
			go func() {
				_, err := hostAdopt(host, tc.line)
				hostDone <- err
			}()
			err := parkedReadyOnConn(slog.Default(), srv, guest, "boot-tok", "park-n")
			if err == nil {
				t.Fatal("the guest accepted a bad env")
			}
			if strings.Contains(err.Error(), envCanary) {
				t.Fatalf("error quotes the env: %v", err)
			}
			_ = guest.Close() // what runParkedReadyHandshake's defer does
			if err := <-hostDone; err == nil {
				t.Fatal("the host got an ack for a refused env")
			}
			if started {
				t.Fatal("the held command started")
			}
			if srv.servingRequests() || sandboxEnv.Len() != 0 {
				t.Fatalf("serving=%v store keys=%d after a refused adopt", srv.servingRequests(), sandboxEnv.Len())
			}
		})
	}
}

// Over a real socket, as main runs it: whether the adopt succeeds or is
// refused, no log line carries a key or a value.
func TestRunParkedReadyHandshakeLogsNoEnv(t *testing.T) {
	oldStart := startUserCommandFn
	t.Cleanup(func() { startUserCommandFn = oldStart })
	for _, tc := range []struct {
		name string
		line string
		ok   bool
	}{
		{"applied", adoptLine(t, map[string]string{"BANK_SECRET": envCanary}), true},
		{"refused", `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":{"TOKEN=` + envCanary + `":"x"}}` + "\n", false},
		{"malformed", `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":{"K":"` + envCanary + "\x01" + `"}}` + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSandboxEnv(t, nil)
			startUserCommandFn = func(*slog.Logger, []string) {}
			dir, err := os.MkdirTemp("", "pe")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			sock := filepath.Join(dir, "p.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			hostDone := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					hostDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, err = hostAdopt(conn, tc.line)
				hostDone <- err
			}()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			srv := &server{logger: logger, parkedMode: true, deferredCmd: []string{"/entrypoint.sh"}}
			runParkedReadyHandshake(logger, srv, sock, "boot-tok", "park-n")
			if err := <-hostDone; (err == nil) != tc.ok {
				t.Fatalf("host ack err = %v, want ok=%v", err, tc.ok)
			}
			if !tc.ok && !strings.Contains(logs.String(), "park ready handshake failed") {
				t.Fatalf("a refused adopt was not logged: %q", logs.String())
			}
			if strings.Contains(logs.String(), envCanary) || strings.Contains(logs.String(), "TOKEN") {
				t.Fatalf("a log line carries the env: %q", logs.String())
			}
		})
	}
}
