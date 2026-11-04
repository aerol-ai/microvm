package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/service"
)

// TestStartEgressProcid (review finding 16): sandboxd serves the gateway's
// executable lookups on a socket group-owned by the gateway's user, mode
// 0660; a missing user or path turns it off, and a lookup for a sandbox
// without per-binary rules is refused.
func TestStartEgressProcid(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	prev := lookupGatewayUser
	t.Cleanup(func() { lookupGatewayUser = prev })
	lookupGatewayUser = func(string) (*user.User, error) { return me, nil }
	dir, err := os.MkdirTemp("", "egp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "run", "egress-procid.sock")
	svc := service.New(config.Config{}, testLogger(), openTestStore(t), nil, nil, nil, nil, nil, nil)
	cfg := config.Config{EgressProcidSocket: sock, EgressGatewayUser: "aerolvm-egress"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := startEgressProcid(ctx, cfg, svc, log); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, %v", st.Mode(), err)
	}
	if _, err := (procid.Client{Path: sock}).Match("sb", netip.MustParseAddrPort("10.0.0.2:1"), netip.MustParseAddrPort("1.1.1.1:443"), nil); err == nil {
		t.Fatal("a sandbox without per-binary rules must be refused")
	}

	if err := startEgressProcid(ctx, config.Config{}, svc, log); err != nil {
		t.Fatal("no socket configured is off, not an error")
	}
	lookupGatewayUser = func(string) (*user.User, error) { return nil, errors.New("unknown user") }
	if err := startEgressProcid(ctx, cfg, svc, log); err == nil {
		t.Fatal("a missing gateway user must be reported")
	}
}
