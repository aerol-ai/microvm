package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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

// C6: a gateway in its own container runs as a user this container's
// /etc/passwd does not name, so the setting may be numbers. A name is still
// looked up.
func TestGatewayIDs(t *testing.T) {
	prev := lookupGatewayUser
	t.Cleanup(func() { lookupGatewayUser = prev })
	lookupGatewayUser = func(name string) (*user.User, error) {
		switch name {
		case "aerolvm-egress":
			return &user.User{Uid: "998", Gid: "997"}, nil
		case "bad-uid":
			return &user.User{Uid: "x", Gid: "1"}, nil
		case "bad-gid":
			return &user.User{Uid: "1", Gid: "x"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	for _, tc := range []struct {
		name    string
		uid     uint32
		gid     int
		wantErr string
	}{
		{name: "aerolvm-egress", uid: 998, gid: 997},
		{name: "65532", uid: 65532, gid: 65532},
		{name: "65532:65533", uid: 65532, gid: 65533},
		{name: "0", uid: 0, gid: 0},
		{name: "nobody-here", wantErr: "unknown user"},
		{name: "65532:abc", wantErr: `gid "abc" is not a number`},
		{name: "abc:1", wantErr: `uid "abc" is not a number`},
		{name: "4294967296", wantErr: "unknown user"},
		{name: "bad-uid", wantErr: `uid "x"`},
		{name: "bad-gid", wantErr: `gid "x"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid, err := gatewayIDs(tc.name)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || uid != tc.uid || gid != tc.gid {
				t.Fatalf("= %d %d %v, want %d %d", uid, gid, err, tc.uid, tc.gid)
			}
		})
	}
}

// With numbers, the lookup socket is served without a user database entry.
func TestStartEgressProcidNumericUser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := lookupGatewayUser
	t.Cleanup(func() { lookupGatewayUser = prev })
	lookupGatewayUser = func(string) (*user.User, error) {
		t.Fatal("a numeric user was looked up")
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "egp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "egress-procid.sock")
	svc := service.New(config.Config{}, testLogger(), openTestStore(t), nil, nil, nil, nil, nil, nil)
	gid := os.Getgid() // a group this process may chown to
	cfg := config.Config{EgressProcidSocket: sock, EgressGatewayUser: fmt.Sprintf("%d:%d", os.Getuid(), gid)}
	if err := startEgressProcid(ctx, cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatal(err)
	}
	cfg.EgressGatewayUser = "1:x"
	if err := startEgressProcid(ctx, cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), `egress gateway user "1:x"`) {
		t.Fatalf("err = %v", err)
	}
}
