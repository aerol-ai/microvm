package sessions

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
	"github.com/aerol-ai/microvm/pkg/models"
)

func waitDone(t *testing.T, s *Session) string {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not exit")
	}
	return string(s.Replay())
}

// TestLoginSessionsKeepTheImagePath: a login shell given a command (the
// argv an E2B command arrives with) and a login shell fed through stdin (a
// Daytona session) both run with the image's PATH first, after
// /etc/profile has reset it.
func TestLoginSessionsKeepTheImagePath(t *testing.T) {
	t.Setenv(loginshell.Env, "/aerolvm-image/bin:/usr/bin:/bin")
	mgr := newTestManager(t)
	ctx := context.Background()

	s, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "e2b", Argv: []string{"/bin/sh", "-l", "-c", `printf 'P=%s\n' "$PATH"`}})
	if err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/aerolvm-image/bin:") {
		t.Fatalf("login -c session: %q", out)
	}

	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "daytona", Argv: []string{"/bin/sh", "-l"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("printf 'P=%s\\n' \"$PATH\"; exit\n")); err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/aerolvm-image/bin:") {
		t.Fatalf("stdin login session: %q", out)
	}

	// A request's own PATH is the one kept.
	s, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "req", Argv: []string{"/bin/sh", "-lc", `printf 'P=%s\n' "$PATH"`},
		Env: map[string]string{"PATH": "/req/bin:/usr/bin:/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	if out := waitDone(t, s); !strings.Contains(out, "P=/req/bin:") {
		t.Fatalf("request PATH: %q", out)
	}
}
