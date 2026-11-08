package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sandboxenv"
	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func adoptFrameWith(env map[string]string) readyproto.AdoptFrame {
	return readyproto.AdoptFrame{Event: readyproto.EventAdopt, SandboxID: "sb-adopt", Token: "sandbox-tok", Nonce: "adopt-n", Env: env}
}

// A warm-pool adopt loads the env into the store the user's children read,
// takes the identity, and acks with the digest the host checks.
func TestApplyAdoptFrameLoadsEnvAndAcksWithItsDigest(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"no env", nil, nil},
		{"env", map[string]string{"BANK_SECRET": envCanary, "REGION": "eu"}, []string{"BANK_SECRET=" + envCanary, "REGION=eu"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSandboxEnv(t, nil)
			srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), parkedMode: true, authToken: "boot-tok"}
			ack, err := srv.applyAdoptFrame(adoptFrameWith(tc.env))
			if err != nil {
				t.Fatalf("applyAdoptFrame: %v", err)
			}
			if got := sandboxEnv.Environ(nil); !slices.Equal(got, tc.want) {
				t.Fatalf("store = %v, want %v", got, tc.want)
			}
			if id, tok := srv.identity(); id != "sb-adopt" || tok != "sandbox-tok" || !srv.servingRequests() {
				t.Fatalf("identity = %q/%q serving=%v", id, tok, srv.servingRequests())
			}
			if ack.Event != readyproto.EventReady || ack.SandboxID != "sb-adopt" || ack.Token != "sandbox-tok" || ack.Nonce != "adopt-n" {
				t.Fatalf("ack = %+v", ack)
			}
			if !readyproto.EnvDigestMatches("adopt-n", tc.env, ack.EnvDigest) {
				t.Fatal("ack digest does not prove the env")
			}
		})
	}
}

// An env the agent can't apply leaves it parked: no identity (so exec and
// sessions stay closed), no ack for the host, the store untouched, and an
// error that names no key or value.
func TestApplyAdoptFrameRefusesBadEnvBeforeTheIdentity(t *testing.T) {
	for _, env := range []map[string]string{
		{"": envCanary},
		{"K": envCanary + "\x00"},
		{"TOKEN=" + envCanary: "v"},
	} {
		withSandboxEnv(t, nil)
		srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), parkedMode: true, authToken: "boot-tok"}
		ack, err := srv.applyAdoptFrame(adoptFrameWith(env))
		if !errors.Is(err, sandboxenv.ErrInvalid) {
			t.Fatalf("applyAdoptFrame = %v, want ErrInvalid", err)
		}
		if strings.Contains(err.Error(), envCanary) {
			t.Fatalf("error quotes the env: %v", err)
		}
		if ack != (readyproto.ReadySignal{}) {
			t.Fatalf("an ack was built: %+v", ack)
		}
		if srv.servingRequests() {
			t.Fatal("the agent took the identity for an env it refused")
		}
		if id, _ := srv.identity(); id != "" {
			t.Fatalf("sandbox id %q set", id)
		}
		if sandboxEnv.Len() != 0 {
			t.Fatal("a refused env reached the store")
		}
	}
}

// Replace, not merge: a later adopt's env is exactly its own, so a key the
// sandbox no longer has is gone (a stopped sandbox's restart re-adopts with
// the env the sealed row holds now).
func TestReAdoptDropsRemovedKeys(t *testing.T) {
	withSandboxEnv(t, nil)
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), parkedMode: true}
	if _, err := srv.applyAdoptFrame(adoptFrameWith(map[string]string{"KEEP": "1", "DROP": envCanary})); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.applyAdoptFrame(adoptFrameWith(map[string]string{"KEEP": "2"})); err != nil {
		t.Fatal(err)
	}
	if got := sandboxEnv.Environ(nil); !slices.Equal(got, []string{"KEEP=2"}) {
		t.Fatalf("store after re-adopt = %v, want [KEEP=2]", got)
	}
	if !slices.Contains(childEnviron(), "KEEP=2") || slices.ContainsFunc(childEnviron(), func(kv string) bool { return strings.HasPrefix(kv, "DROP=") }) {
		t.Fatal("children do not see exactly the re-adopted env")
	}
}

// The env an adopt delivers reaches the held-back image command (started
// from childEnviron, as the handshake does once the ack is out), exec and
// sessions. None of it reaches a log line.
func TestAdoptedEnvReachesCommandExecAndSessions(t *testing.T) {
	withSandboxEnv(t, nil)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := &server{logger: logger, parkedMode: true, allowedPorts: map[int]struct{}{}}
	if _, err := srv.applyAdoptFrame(adoptFrameWith(map[string]string{"BANK_SECRET": envCanary, "SHARED": "sandbox"})); err != nil {
		t.Fatal(err)
	}

	t.Run("held command", func(t *testing.T) {
		old := mainProgram
		t.Cleanup(func() { mainProgram = old; userCommandPID.Store(0) })
		mainProgram = &mainProgramState{state: mainProgramNone}
		out := filepath.Join(t.TempDir(), "env.out")
		startUserCommand(logger, []string{"/bin/sh", "-c", `printf '%s' "$BANK_SECRET" > "$0.tmp" && mv "$0.tmp" "$0"`, out})
		if pid := int(userCommandPID.Load()); pid > 0 {
			t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			b, err := os.ReadFile(out)
			if err == nil {
				if string(b) != envCanary {
					t.Fatalf("held command saw BANK_SECRET=%q", b)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("held command never wrote its env")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("exec", func(t *testing.T) {
		body, _ := json.Marshal(models.ExecRequest{Command: `printf '%s|%s' "$BANK_SECRET" "$SHARED"`, Env: map[string]string{"SHARED": "exec"}, TimeoutSeconds: 10})
		rr := httptest.NewRecorder()
		srv.handleExec(rr, httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader(body)))
		var res models.ExecResult
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("status %d: %s (%v)", rr.Code, rr.Body.String(), err)
		}
		if want := envCanary + "|exec"; res.Stdout != want {
			t.Fatalf("exec output = %q, want %q", res.Stdout, want)
		}
	})

	t.Run("sessions", func(t *testing.T) {
		mgr, err := sessions.New(slog.New(slog.NewTextHandler(io.Discard, nil)), sessions.Config{
			SandboxID: "sb-adopt", RecordingDir: t.TempDir(), BaseEnv: childEnviron,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(mgr.Close)
		sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
			Command: `printf '%s|%s' "$BANK_SECRET" "$SHARED"`, Env: map[string]string{"SHARED": "session"},
		})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-sess.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("session did not exit")
		}
		if got, want := string(sess.Replay()), envCanary+"|session"; !strings.Contains(got, want) {
			t.Fatalf("session output = %q, want %q", got, want)
		}
	})

	if strings.Contains(logs.String(), envCanary) {
		t.Fatalf("a log line carries the env: %q", logs.String())
	}
}

// A create that sets PATH resolves the image command on that PATH warm, as
// the engine resolves an entrypoint on a cold container: a name only the
// sandbox's PATH holds runs, and a name only toolboxd's own PATH holds does
// not.
func TestHeldCommandResolvesOnTheAdoptedPath(t *testing.T) {
	old := mainProgram
	t.Cleanup(func() { mainProgram = old; userCommandPID.Store(0) })
	bin := t.TempDir()
	out := filepath.Join(t.TempDir(), "ran")
	script := "#!/bin/sh\nprintf ok > " + out + "\n"
	if err := os.WriteFile(filepath.Join(bin, "aerolvm-adopt-tool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	withSandboxEnv(t, nil)
	srv := &server{logger: logger, parkedMode: true}
	if _, err := srv.applyAdoptFrame(adoptFrameWith(map[string]string{"PATH": bin + ":/usr/bin:/bin"})); err != nil {
		t.Fatal(err)
	}
	mainProgram = &mainProgramState{state: mainProgramNone}
	startUserCommand(logger, []string{"aerolvm-adopt-tool"})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(out); err == nil && string(b) == "ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a command on the sandbox's PATH did not run: %v", mainProgram.snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A PATH without sh: toolboxd's own PATH has it, the sandbox's does not.
	if _, err := srv.applyAdoptFrame(adoptFrameWith(map[string]string{"PATH": bin})); err != nil {
		t.Fatal(err)
	}
	mainProgram = &mainProgramState{state: mainProgramNone}
	startUserCommand(logger, []string{"sh", "-c", "exit 0"})
	if snap := mainProgram.snapshot(); snap["state"] != "exited" || snap["exit_code"] != 127 {
		t.Fatalf("a name off the sandbox's PATH started: %v", snap)
	}
}
