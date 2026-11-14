package gatewayd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestFromOperatorRefusesBadFiles (§5.10): an operator file that is invalid
// at start, or whose upstream credentials can't be read, stops the gateway
// rather than running it without them.
func TestFromOperatorRefusesBadFiles(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":           "version: 1\ndeny_cidrs: [not-a-cidr]\n",
		"unreadable secret": "version: 1\nupstream_proxy:\n  url: http://proxy.example:3128\n  auth_file: /no/such/auth\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "op.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := fromOperatorFile(path); err == nil {
				t.Fatal("want the gateway start refused")
			}
		})
	}
}

// TestGatewayEgressRanges (C24): the gateway reads the node's extra deny
// floor and private ranges from its own environment; its guard and kernel
// floor carry the floor with or without an operator file, its dials refuse
// both lists; and a list it cannot read stops it.
func TestGatewayEgressRanges(t *testing.T) {
	prevFloor, prevPrivate := egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges()
	t.Cleanup(func() { egresspolicy.SetRanges(prevFloor, prevPrivate) })
	t.Setenv(egresspolicy.DenyFloorEnv, "10.96.0.1")
	t.Setenv(egresspolicy.PrivateRangesEnv, "198.18.0.0/15")
	if err := egresspolicy.LoadRangesFromEnv(); err != nil {
		t.Fatal(err)
	}
	apiServer := netip.MustParsePrefix("10.96.0.1/32")
	op := filepath.Join(t.TempDir(), "op.yaml")
	if err := os.WriteFile(op, []byte("version: 1\ndeny_cidrs: [10.99.0.0/16]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", op} {
		g, _, err := fromOperatorFile(path)
		if err != nil || !slices.Contains(g.DenyFloor, apiServer) {
			t.Fatalf("operator file %q: floor %v, %v", path, g.DenyFloor, err)
		}
		pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: []string{"10.0.0.0/8", "api.example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		var de *egresspolicy.DialError
		if err := g.Check(pol, egresspolicy.DialTarget{Name: "api.example.com", NameAllowed: true, Addr: netip.MustParseAddrPort("10.96.0.1:443")}); !errors.As(err, &de) || de.Reason != egresspolicy.DialReasonDenyFloor {
			t.Fatalf("an allowed name on the floor: %v", err)
		}
		if err := g.Check(pol, egresspolicy.DialTarget{Name: "api.example.com", NameAllowed: true, Addr: netip.MustParseAddrPort("198.18.0.9:443")}); !errors.As(err, &de) || de.Reason != egresspolicy.DialReasonPrivate {
			t.Fatalf("an allowed name in an extra private range: %v", err)
		}
	}
	t.Setenv(egresspolicy.DenyFloorEnv, "10.96.0.1/12")
	if err := RunCLI(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), egresspolicy.DenyFloorEnv) {
		t.Fatalf("a gateway with an unreadable floor: %v", err)
	}
}

// TestReloadOnHUP (review finding 7): SIGHUP reloads the operator file
// without waiting for the poll.
func TestReloadOnHUP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "op.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndeny_cidrs: [10.99.0.0/16]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := make(chan *operator.Operator, 4)
	w := operator.NewWatcher(path, nil, func(op *operator.Operator) { changed <- op })
	<-changed // the load at start
	// A SIGHUP that lands before reloadOnHUP subscribes would kill the test
	// binary; this subscription keeps it from ever being unhandled.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGHUP)
	defer signal.Stop(guard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { reloadOnHUP(ctx, w); close(done) }()
	if err := os.WriteFile(path, []byte("version: 1\ndeny_cidrs: [10.98.0.0/16]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for reloaded := false; !reloaded; {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case op := <-changed:
			if g := op.Guard(); len(g.DenyFloor) != 1+len(egresspolicy.MetadataPrefixes) || g.DenyFloor[0].String() != "10.98.0.0/16" {
				t.Fatalf("reloaded floor = %v", g.DenyFloor)
			}
			reloaded = true
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatal("SIGHUP never reloaded the operator file")
		}
	}
	cancel()
	<-done
}
