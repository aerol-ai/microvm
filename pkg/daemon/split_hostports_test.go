package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootclient"
)

// TestHostPortForwarderForSplit (M1 PR 5b): in privilege mode split the
// forwarder is the root helper's, once the handshake says the helper
// forwards host ports; a helper that does not (one release back), or none
// at all, gives no forwarder, so the routing engage is refused and the
// node keeps per-sandbox Caddy routes. Single mode is unchanged.
func TestHostPortForwarderForSplit(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), IngressProxyRouting: true}
	sock := filepath.Join(dir, "sock", "root.sock")
	splitHelper(t, sock)
	helper := rootclient.New(rootclient.Config{Socket: sock, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = helper.Close() })
	rec := &levelRecorder{}
	fwd := hostPortForwarderFor(context.Background(), cfg, helper, slog.New(rec))
	if _, ok := fwd.(*rootclient.HostPortForwarder); !ok {
		t.Fatalf("split forwarder = %T, want the helper's", fwd)
	}
	// The flag off and no marker: nothing is built, nothing asked.
	if fwd := hostPortForwarderFor(context.Background(), config.Config{DBPath: cfg.DBPath}, helper, slog.New(rec)); fwd != nil {
		t.Fatalf("flag off: %T", fwd)
	}
	// A helper that is not there: no forwarder, and the operator is told.
	gone := rootclient.New(rootclient.Config{Socket: filepath.Join(dir, "none.sock"), HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = gone.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), hostPortRequireTimeout)
	defer cancel()
	if fwd := hostPortForwarderFor(ctx, cfg, gone, slog.New(rec)); fwd != nil {
		t.Fatalf("no helper: %T", fwd)
	}
	warns := rec.at(slog.LevelWarn)
	if len(warns) != 1 || !strings.Contains(warns[0], "does not forward host ports") {
		t.Fatalf("warnings %q", warns)
	}
}
