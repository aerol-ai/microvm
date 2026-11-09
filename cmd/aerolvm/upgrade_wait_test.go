package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

func TestWaitNodeEndings(t *testing.T) {
	f := newFakeUpgrade(t, false, "v0.6.12")
	h := upgradeHarness(t, f)
	f.opSteps = []string{"staging", "staging", "staging", "staging", "staging", "staging", "staging", "staging"}
	f.ops = []upgradewire.NodeUpgradeResponse{{Op: "op-1", State: "pending", Version: "v0.6.13"}}
	conn := connection{apiURL: f.srv.URL, token: agenttoolstest.Token}
	c := &commonFlags{}
	// The caller gives up first: the error says the upgrade goes on.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	h.app.pollEvery = 5 * time.Millisecond
	code := h.app.waitNode(ctx, c, conn, f.ops[0], time.Millisecond, "")
	cancel()
	// Under load the deadline can pass before the first poll moves the op
	// on from pending, so either state is right; what matters is the hint.
	still := strings.Contains(h.stderr.String(), "is still staging") || strings.Contains(h.stderr.String(), "is still pending")
	if code != exitError || !still || !strings.Contains(h.stderr.String(), "it goes on without aerolvm") {
		t.Fatalf("timeout = %d %q", code, h.stderr.String())
	}
	// A refusal that is not a restart ends the wait.
	h.stderr.Reset()
	// The cancelled wait's last request can still be in the fake's handler,
	// which reads these under f.mu: change them under it too.
	f.mu.Lock()
	f.noRoutes = true
	f.mu.Unlock()
	if code := h.app.waitNode(context.Background(), c, conn, f.ops[0], time.Minute, ""); code != exitError || !strings.Contains(h.stderr.String(), "no upgrade API") {
		t.Fatalf("refusal = %d %q", code, h.stderr.String())
	}
	// Someone else's op is the latest: ours is not followed past it.
	f.mu.Lock()
	f.noRoutes = false
	f.ops = append(f.ops, upgradewire.NodeUpgradeResponse{Op: "op-2", State: "done", Version: "v0.6.14"})
	f.mu.Unlock()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if code := h.app.waitNode(ctx, c, conn, f.ops[0], time.Millisecond, "json"); code != exitError {
		t.Fatalf("someone else's op = %d", code)
	}
	if (&app{}).pollInterval() != 2*time.Second || rfcTime(time.Time{}) != "-" || yesNo(true) != "yes" {
		t.Fatal("helpers")
	}
}

func TestUpgradeNeedsALogin(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{"HOME": t.TempDir(), "XDG_CONFIG_HOME": t.TempDir()}
	for _, args := range [][]string{{"upgrade", "status"}, {"upgrade", "stop"}, {"upgrade", "rollback"}} {
		if code := h.run(args...); code != exitError {
			t.Fatalf("%v with no login = %d %q", args, code, h.stderr.String())
		}
	}
}
