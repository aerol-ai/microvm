package gatewayd

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress/operator"
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
			if g := op.Guard(); len(g.DenyFloor) != 1 || g.DenyFloor[0].String() != "10.98.0.0/16" {
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
