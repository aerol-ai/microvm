package egress

// Regression tests from the fourth review of PR #622: each reproduces a
// finding against the reviewed head (4fdb667c) and passes with its fix.

import (
	"encoding/json"
	"errors"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"net"
	"testing"
)

func TestSyncTokenCannotCrossARestart(t *testing.T) {
	be := NewMemBackend()
	old := New(Options{Backend: be})
	if err := old.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	spec := allowSpec("sb", ipA, "pypi.org")
	if err := old.Attach(spec); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := old.SetBlocked("sb", BlockQuota, i%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	// sandboxd reads this before its SQLite snapshot, then gatewayd restarts.
	since := old.SyncToken()
	fresh := New(Options{Backend: be})
	if err := fresh.Restore([]Spec{spec}); err != nil {
		t.Fatal(err)
	}
	// This hold is newer than the snapshot, but its generation restarts at 1.
	if err := fresh.SetBlocked("sb", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	if err := fresh.SyncFrom(since, []Spec{spec}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a token from the previous gateway process must be refused, got %v", err)
	}
	if !fresh.IsBlocked("sb") {
		t.Fatal("the refused Sync must leave the hold and the restart block in place")
	}
	// A token from this process is accepted, and a write after it survives.
	tok := fresh.SyncToken()
	if err := fresh.SetBlocked("sb", BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	if err := fresh.SyncFrom(tok, []Spec{spec}); err != nil || !fresh.IsBlocked("sb") {
		t.Fatalf("this process's token: %v blocked=%v", err, fresh.IsBlocked("sb"))
	}
}

func TestSyncWithoutATokenIsRefused(t *testing.T) {
	for _, object := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-array", true: "missing-since"}[object], func(t *testing.T) {
			g := New(Options{Backend: NewMemBackend()})
			if err := g.Bootstrap(); err != nil {
				t.Fatal(err)
			}
			spec := allowSpec("sb", ipA, "pypi.org")
			if err := g.Attach(spec); err != nil {
				t.Fatal(err)
			}
			var payload any = []Spec{spec}
			if object {
				payload = map[string]any{"specs": []Spec{spec}}
			}
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := g.SetBlocked("sb", BlockHold, true); err != nil {
				t.Fatal(err)
			}
			s := NewServer(g, ServerHooks{}, nil, nil, nil)
			if _, err := s.dispatch(request{Op: opSync, Payload: b}); err != nil {
				return /* safe rejection */
			}
			if !g.IsBlocked("sb") {
				t.Fatal("unversioned Sync was accepted as current and erased a newer hold")
			}
		})
	}
}

// TestPolicyChangeClosesConnsWhoseRulesChanged (review 4 finding 2): an
// established connection to a host the new policy still allows is closed
// when the rules that decided it changed (a binary, inspection); a
// connection whose host and rules are unchanged stays. Both an Attach and
// a Sync sweep this way.
func TestPolicyChangeClosesConnsWhoseRulesChanged(t *testing.T) {
	for _, viaSync := range []bool{false, true} {
		name := map[bool]string{false: "attach", true: "sync"}[viaSync]
		t.Run(name, func(t *testing.T) {
			g, _, _ := newTestGateway(t)
			spec := allowSpec("sb", ipA, "pypi.org", "other.org")
			spec.Rules = []egresspolicy.RuleSpec{{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/curl"}}}
			if err := g.Attach(spec); err != nil {
				t.Fatal(err)
			}
			ruled, r2 := net.Pipe()
			defer r2.Close()
			plain, p2 := net.Pipe()
			defer p2.Close()
			g.Track("sb", "pypi.org", 443, ruled)
			kept := g.Track("sb", "other.org", 443, plain)
			next := spec
			next.Rules = []egresspolicy.RuleSpec{{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/wget"}}}
			var err error
			if viaSync {
				err = g.Sync([]Spec{next})
			} else {
				err = g.Attach(next)
			}
			if err != nil {
				t.Fatal(err)
			}
			if g.ConnCount("sb") != 1 {
				t.Fatalf("tracked conns = %d, want only the unchanged one", g.ConnCount("sb"))
			}
			if _, err := r2.Write([]byte("x")); err == nil {
				t.Fatal("the connection whose rule changed must be closed")
			}
			kept.Close()
		})
	}
}
