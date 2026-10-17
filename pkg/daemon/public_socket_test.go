package daemon

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// ownGroup is the test process's primary group: a group it may chown to
// without root, standing in for Caddy's.
func ownGroup(t *testing.T) (string, int) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("primary group %s has no name: %v", u.Gid, err)
	}
	gid, _ := strconv.Atoi(g.Gid)
	return g.Name, gid
}

// shortDir is a temp dir short enough for a Unix socket path (about 104
// bytes on macOS); t.TempDir() embeds the test name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func statOwner(t *testing.T, path string) (fs.FileMode, int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat_t on this platform")
	}
	return info.Mode(), int(st.Gid)
}

// setEnterpriseCredentialEnv satisfies enterprise mode's credential checks
// for a boot test (§5.12): identity on (tokens-only) and SB_PAT_SCOPE=host,
// with the public socket in a temp dir owned by the test's own group.
func setEnterpriseCredentialEnv(t *testing.T) {
	t.Helper()
	group, _ := ownGroup(t)
	old := publicAPISocketGroup
	publicAPISocketGroup = group
	t.Cleanup(func() { publicAPISocketGroup = old })
	t.Setenv("SB_IDENTITY_ENABLED", "true")
	t.Setenv("SB_PAT_SCOPE", "host")
	t.Setenv("SB_PUBLIC_API_SOCKET", filepath.Join(shortDir(t), "pub", "api.sock"))
}

// TestListenPublicAPISocketPermissions is the socket-directory test of
// plans/identity-and-access.md §5.11: the directory is <owner>:caddy 0750
// and the socket 0660 every boot, whatever was there before; a stale socket
// is replaced; anything else at the path, or a directory that is not one,
// fails the boot rather than being deleted or chmodded.
func TestListenPublicAPISocketPermissions(t *testing.T) {
	group, gid := ownGroup(t)
	t.Run("fresh directory and socket", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "pub", "api.sock")
		ln, err := listenPublicAPISocket(path, group)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		mode, g := statOwner(t, filepath.Dir(path))
		if mode.Perm() != 0o750 || !mode.IsDir() || g != gid {
			t.Fatalf("directory = %v gid %d, want drwxr-x--- gid %d", mode, g, gid)
		}
		mode, g = statOwner(t, path)
		if mode.Perm() != 0o660 || mode&fs.ModeSocket == 0 || g != gid {
			t.Fatalf("socket = %v gid %d, want srw-rw---- gid %d", mode, g, gid)
		}
	})
	t.Run("an existing directory is tightened and a stale socket replaced", func(t *testing.T) {
		dir := filepath.Join(shortDir(t), "pub")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "api.sock")
		stale, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		stale.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = stale.Close() // the file stays, as after a crash
		ln, err := listenPublicAPISocket(path, group)
		if err != nil {
			t.Fatalf("a stale socket must be replaced: %v", err)
		}
		defer ln.Close()
		if mode, _ := statOwner(t, dir); mode.Perm() != 0o750 {
			t.Fatalf("directory mode = %v, want 0750", mode.Perm())
		}
	})
	t.Run("a regular file at the path is refused and kept", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "api.sock")
		if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := listenPublicAPISocket(path, group); err == nil || !strings.Contains(err.Error(), "is not a socket") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if b, _ := os.ReadFile(path); string(b) != "keep" {
			t.Fatal("the file was touched")
		}
	})
	t.Run("a symlinked directory is refused", func(t *testing.T) {
		base := shortDir(t)
		real := filepath.Join(base, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := listenPublicAPISocket(filepath.Join(link, "api.sock"), group); err == nil || !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if mode, _ := statOwner(t, real); mode.Perm() != 0o700 {
			t.Fatalf("the symlink target was chmodded to %v", mode.Perm())
		}
	})
	t.Run("a directory path that is a file", func(t *testing.T) {
		file := filepath.Join(shortDir(t), "f")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := listenPublicAPISocket(filepath.Join(file, "api.sock"), group); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("no such group", func(t *testing.T) {
		if _, err := listenPublicAPISocket(filepath.Join(shortDir(t), "api.sock"), "aerolvm-no-such-group-x"); err == nil || !strings.Contains(err.Error(), "group") {
			t.Fatalf("err = %v, want the group named", err)
		}
	})
	t.Run("a group with a non-numeric gid", func(t *testing.T) {
		old := lookupPublicAPISocketGroup
		lookupPublicAPISocketGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "x", Name: "caddy"}, nil }
		t.Cleanup(func() { lookupPublicAPISocketGroup = old })
		if _, err := listenPublicAPISocket(filepath.Join(shortDir(t), "api.sock"), "caddy"); err == nil || !strings.Contains(err.Error(), "gid") {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestRunPublicSocketRefusesThePAT drives the real boot under
// SB_PAT_SCOPE=host: the daemon opens Caddy's socket, a PAT through it gets
// the 401 that says to sign in, and shutdown closes it.
func TestRunPublicSocketRefusesThePAT(t *testing.T) {
	_ = setBaseRunEnv(t)
	group, _ := ownGroup(t)
	old := publicAPISocketGroup
	publicAPISocketGroup = group
	t.Cleanup(func() { publicAPISocketGroup = old })
	path := filepath.Join(shortDir(t), "pub", "api.sock")
	t.Setenv("SB_PAT_SCOPE", "host")
	t.Setenv("SB_PUBLIC_API_SOCKET", path)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, testLogger(), nil) }()

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	var resp *http.Response
	deadline := time.Now().Add(20 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, "http://sandboxd/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		var err error
		if resp, err = client.Do(req); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run returned before the socket served: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the public socket never served: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "the operator token works only on this host") {
		t.Fatalf("PAT on the public socket = %d %s", resp.StatusCode, body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not shut down")
	}
}

// TestRunPublicSocketFailureStopsBoot: §11, "boot fails loudly if it cannot
// create the socket".
func TestRunPublicSocketFailureStopsBoot(t *testing.T) {
	_ = setBaseRunEnv(t)
	old := publicAPISocketGroup
	publicAPISocketGroup = "aerolvm-no-such-group-x"
	t.Cleanup(func() { publicAPISocketGroup = old })
	t.Setenv("SB_PAT_SCOPE", "host")
	t.Setenv("SB_PUBLIC_API_SOCKET", filepath.Join(shortDir(t), "api.sock"))
	err := runWithAutoCancel(t, 2*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "public API socket") {
		t.Fatalf("Run err = %v, want the public socket refusal", err)
	}
}

// TestLogPATBootSettings: boot logs the PROXY-protocol flag and the
// effective operator volume scope (§11, H2), and nothing for a default node.
func TestLogPATBootSettings(t *testing.T) {
	logs := func(cfg config.Config) string {
		var buf bytes.Buffer
		logPATBootSettings(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
		return buf.String()
	}
	if got := logs(config.Config{PATToken: "pat"}); got != "" {
		t.Fatalf("a default node logs %q", got)
	}
	cfg := config.Config{PATToken: "pat", PATScope: config.PATScopeHost, PublicAPISocket: "/run/x.sock", PATTokenPrevious: "old",
		L4FallbackProxyProtocol: true, L4TLSFallback: "127.0.0.1:8443"}
	cfg.PlatformVolumes.Enabled = true
	got := logs(cfg)
	for _, want := range []string{"SB_PAT_SCOPE=host", "/run/x.sock", "SB_PAT_TOKEN_PREVIOUS", "PROXY protocol v2", "scope=op-", "pinned=false"} {
		if !strings.Contains(got, want) {
			t.Errorf("boot log misses %q:\n%s", want, got)
		}
	}
	cfg.OperatorVolumeScope = "op-pinned"
	if got := logs(cfg); !strings.Contains(got, "scope=op-pinned") || !strings.Contains(got, "pinned=true") {
		t.Errorf("a pinned scope is logged as such:\n%s", got)
	}
	cfg.OperatorVolumeScope, cfg.PATToken = "", ""
	if got := logs(cfg); !strings.Contains(got, "operator volume scope unresolved") {
		t.Errorf("an unresolvable scope warns:\n%s", got)
	}
}
