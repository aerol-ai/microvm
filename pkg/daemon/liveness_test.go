package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain keeps every Run in this package off the real
// /run/sandboxd/live.sock (a root-run test container would otherwise share
// one path across tests); the liveness tests set their own short path.
func TestMain(m *testing.M) {
	if os.Getenv("SB_LIVENESS_SOCKET") == "" {
		_ = os.Setenv("SB_LIVENESS_SOCKET", "off")
	}
	os.Exit(m.Run())
}

// livezClient talks HTTP over the liveness socket, as the watchdog's
// `curl --unix-socket` does.
func livezClient(path string) *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}},
	}
}

func getLivez(t *testing.T, path string) (int, livenessAnswer, error) {
	t.Helper()
	resp, err := livezClient(path).Get("http://localhost" + livenessPath)
	if err != nil {
		return 0, livenessAnswer{}, err
	}
	defer resp.Body.Close()
	var got livenessAnswer
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return resp.StatusCode, got, err
	}
	return resp.StatusCode, got, nil
}

// The socket answers 200 from the moment it opens, reports the phase the
// daemon is in, and is gone (file and listener) after stop.
func TestLivenessAnswersEveryPhaseAndRemovesItsSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "run", "live.sock")
	l := startLiveness(path, testLogger())
	if l == nil {
		t.Fatal("startLiveness returned nil for a usable path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != livenessSocketMode {
		t.Fatalf("socket mode = %v, want %v (root-only: the watchdog runs as root)", mode, livenessSocketMode)
	}
	if dirInfo, err := os.Stat(filepath.Dir(path)); err != nil || dirInfo.Mode().Perm() != livenessSocketDirMode {
		t.Fatalf("socket dir mode = %v (%v), want %v", dirInfo.Mode().Perm(), err, livenessSocketDirMode)
	}
	for _, phase := range []int32{livenessPhaseBooting, livenessPhaseServing, livenessPhaseStopping} {
		l.setPhase(phase)
		status, got, err := getLivez(t, path)
		if err != nil || status != http.StatusOK {
			t.Fatalf("phase %s: status %d err %v", livenessPhaseName(phase), status, err)
		}
		if got.Status != "alive" || got.Phase != livenessPhaseName(phase) || got.UptimeSeconds < 0 {
			t.Fatalf("phase %s: answer %+v", livenessPhaseName(phase), got)
		}
	}
	l.stop()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket file still there after stop: %v", err)
	}
	if _, _, err := getLivez(t, path); err == nil {
		t.Fatal("liveness still answered after stop")
	}
}

// A run ended by SIGKILL leaves its socket file behind, and a Unix listen on
// that path fails. The next boot must replace it, or every restart after a
// kill would lose its liveness socket.
func TestLivenessReplacesASocketAKilledRunLeftBehind(t *testing.T) {
	path := filepath.Join(shortDir(t), "live.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket was not left behind: %v", err)
	}
	l := startLiveness(path, testLogger())
	if l == nil {
		t.Fatal("startLiveness did not replace the stale socket")
	}
	defer l.stop()
	if status, _, err := getLivez(t, path); err != nil || status != http.StatusOK {
		t.Fatalf("status %d err %v", status, err)
	}
}

// The path comes from configuration, so a file there that is not a socket is
// left alone and the daemon boots without the socket (the watchdog falls
// back to /health). Off is a nil server whose methods do nothing.
func TestLivenessSkipsWhatItMustNotTouch(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	path := filepath.Join(shortDir(t), "live.sock")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l := startLiveness(path, logger); l != nil {
		l.stop()
		t.Fatal("startLiveness took over a path holding a regular file")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep me" {
		t.Fatalf("regular file was changed: %q", got)
	}
	if !strings.Contains(logs.String(), "falls back to /health") {
		t.Fatalf("no warning logged: %s", logs.String())
	}

	// A path too long for a Unix socket (108 bytes on Linux, 104 on macOS):
	// the listen fails and the boot goes on without it.
	long := filepath.Join(shortDir(t), strings.Repeat("d", 120), "live.sock")
	if l := startLiveness(long, logger); l != nil {
		l.stop()
		t.Fatal("startLiveness succeeded on a path too long to bind")
	}

	// A directory that cannot be made.
	blocker := filepath.Join(shortDir(t), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if l := startLiveness(filepath.Join(blocker, "live.sock"), nil); l != nil {
		l.stop()
		t.Fatal("startLiveness succeeded under a regular file")
	}

	var off *livenessServer
	if got := startLiveness("", logger); got != nil {
		t.Fatal("an empty path must mean off")
	}
	off.setPhase(livenessPhaseServing)
	off.stop()
}

// A probe is answered without waiting on anything the API holds: with the
// handler goroutines of another server blocked, /livez still answers at once.
func TestLivenessAnswersWhileAnotherServerIsSaturated(t *testing.T) {
	path := filepath.Join(shortDir(t), "live.sock")
	l := startLiveness(path, nil)
	if l == nil {
		t.Fatal("startLiveness returned nil")
	}
	defer l.stop()

	block := make(chan struct{})
	defer close(block)
	busy := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block })}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = busy.Serve(ln) }()
	defer busy.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	for range 64 {
		go func() {
			if resp, err := client.Get("http://" + ln.Addr().String()); err == nil {
				resp.Body.Close()
			}
		}()
	}

	start := time.Now()
	status, _, err := getLivez(t, path)
	if err != nil || status != http.StatusOK {
		t.Fatalf("status %d err %v", status, err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("liveness took %v with another server saturated", took)
	}
}

// A stop that lands mid-boot is a clean exit, not a failure; any other boot
// error is still returned.
func TestBootStopped(t *testing.T) {
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	bootErr := errors.New("seed containerd netns pool: netns: seed slot 0: context canceled")
	cases := []struct {
		name string
		stop context.Context
		err  error
		want error
	}{
		{name: "no error", stop: stopped, err: nil, want: nil},
		{name: "boot failed with no stop requested", stop: context.Background(), err: bootErr, want: bootErr},
		{name: "boot interrupted by a stop", stop: stopped, err: bootErr, want: nil},
		{name: "no stop context", stop: nil, err: bootErr, want: bootErr},
		{name: "a deadline bounds a boot, it does not stop it", stop: expired, err: bootErr, want: bootErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bootStopped(tc.stop, tc.err, testLogger()); !errors.Is(got, tc.want) {
				t.Fatalf("bootStopped = %v, want %v", got, tc.want)
			}
		})
	}
}

// Regression (bank flagship, 2026-11-01): the watchdog's second restart
// stopped a daemon 70 ms into its boot, the interrupted step returned
// "context canceled", and the daemon exited 1 — a failed unit. A boot that
// fails because it was asked to stop now returns nil, so systemd records a
// clean stop.
func TestRun_StopDuringBootExitsCleanly(t *testing.T) {
	setBaseRunEnv(t)
	// A boot step that fails: without the stop it is an error (see
	// TestRun_MountManagerErrorReturnsWrappedError).
	t.Setenv("SB_MOUNTS_ROOT", "relative-mounts-root")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, testLogger(), nil); err != nil {
		t.Fatalf("Run with a stop requested during boot returned %v, want nil (a clean stop)", err)
	}
}

// The liveness socket is up while Run serves and gone when it returns.
func TestRun_ServesLivenessUntilShutdown(t *testing.T) {
	setBaseRunEnv(t)
	path := filepath.Join(shortDir(t), "live.sock")
	t.Setenv("SB_LIVENESS_SOCKET", path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, testLogger(), nil) }()

	deadline := time.Now().Add(20 * time.Second)
	for {
		status, got, err := getLivez(t, path)
		if err == nil && status == http.StatusOK && got.Phase == "serving" {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run returned before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("liveness never reported serving: status %d answer %+v err %v", status, got, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("liveness socket left behind after a graceful stop: %v", err)
	}
}
