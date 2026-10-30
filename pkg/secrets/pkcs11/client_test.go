package pkcs11

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// TestMain doubles as the helper process for the exec tests: ExecStarter runs
// os.Executable(), which is this test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperFlag {
		open := func(cfg TokenConfig) (closingBackend, error) {
			if cfg.KeyLabel == "refuse" {
				return nil, errors.New("token refused")
			}
			return &fakeBackend{info: Info{KeyLabel: cfg.KeyLabel, TokenLabel: cfg.TokenLabel, DecryptLabels: cfg.DecryptLabels, IVMode: cfg.IVMode}}, nil
		}
		if os.Getenv("PKCS11_HELPER_REAL") == "1" {
			open = openBackend
		}
		if err := runHelper(os.Args[2:], open); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeBackend wraps by prefixing, and can fail or hang on demand.
type fakeBackend struct {
	mu      sync.Mutex
	info    Info
	err     error
	hang    chan struct{} // Wrap blocks until closed, ignoring ctx, like a stuck C call
	closed  bool
	lastAAD []byte
}

func (f *fakeBackend) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	f.mu.Lock()
	hang, err := f.hang, f.err
	f.lastAAD = aad
	f.mu.Unlock()
	if hang != nil {
		<-hang
	}
	if err != nil {
		return nil, err
	}
	return append([]byte("p11:fake:"), dek...), nil
}

func (f *fakeBackend) Unwrap(_ context.Context, w, _ []byte) ([]byte, error) {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return bytes.TrimPrefix(w, []byte("p11:fake:")), nil
}

func (f *fakeBackend) Ping(context.Context) error { return f.err }
func (f *fakeBackend) Info() Info                 { return f.info }
func (f *fakeBackend) Close()                     { f.closed = true }

func (f *fakeBackend) set(fn func(*fakeBackend)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// inproc is a helper "process" serving in this process.
type inproc struct {
	ln   net.Listener
	done chan struct{}
	once sync.Once
}

func (p *inproc) Wait() error { <-p.done; return nil }
func (p *inproc) Kill() error {
	p.once.Do(func() { _ = p.ln.Close(); close(p.done) })
	return nil
}

func inprocStarter(b backend, starts *atomic.Int32, fail *atomic.Bool) starter {
	return func(socket string) (proc, error) {
		if fail != nil && fail.Load() {
			return nil, errors.New("cannot start")
		}
		starts.Add(1)
		ln, err := listen(socket)
		if err != nil {
			return nil, err
		}
		p := &inproc{ln: ln, done: make(chan struct{})}
		go func() { _ = serve(context.Background(), ln, b) }()
		return p, nil
	}
}

// shortSocket returns a socket path short enough for macOS (104 bytes).
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "p11")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "run", "h.sock")
}

func fastTimings(t *testing.T) {
	t.Helper()
	opDeadlineOverride.Store(int64(300 * time.Millisecond))
	startTimeoutOverride.Store(int64(2 * time.Second))
	t.Cleanup(func() { opDeadlineOverride.Store(0); startTimeoutOverride.Store(0) })
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHelperRoundTripAndClasses(t *testing.T) {
	fastTimings(t)
	b := &fakeBackend{info: Info{KeyLabel: "k", HardwareSlot: true}}
	var starts atomic.Int32
	sock := shortSocket(t)
	h, err := StartHelper(HelperOptions{Socket: sock, start: inprocStarter(b, &starts, nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if info := h.Info(); info.KeyLabel != "k" || !info.HardwareSlot {
		t.Fatalf("Info = %+v", info)
	}
	if fi, err := os.Stat(filepath.Dir(sock)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode = %v %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v %v", fi.Mode(), err)
	}
	ctx := context.Background()
	encCtx := map[string]string{"aerolvm.ref": "r"}
	w, err := h.Wrap(ctx, []byte("dek"), encCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.Unwrap(ctx, w, encCtx); err != nil || string(got) != "dek" {
		t.Fatalf("Unwrap = %q %v", got, err)
	}
	if !bytes.Equal(b.lastAAD, secrets.EncryptionContextAAD(encCtx)) {
		t.Fatal("encryption context did not reach the helper as AAD")
	}
	for _, class := range []error{secrets.ErrKeyRevoked, secrets.ErrKeyVersionRetired, secrets.ErrProviderDenied, secrets.ErrProviderThrottled, secrets.ErrDecryptFailed, secrets.ErrProviderUnavailable} {
		b.set(func(f *fakeBackend) { f.err = fmt.Errorf("%w: from the token", class) })
		if _, err := h.Unwrap(ctx, w, nil); !errors.Is(err, class) {
			t.Fatalf("class %v crossed the socket as %v", class, err)
		}
	}
}

// eng D5: a helper that dies is restarted with backoff; calls in the gap are
// unavailable, and the restart is counted.
func TestHelperRestartsAfterExit(t *testing.T) {
	fastTimings(t)
	b := &fakeBackend{}
	var starts atomic.Int32
	h, err := StartHelper(HelperOptions{Socket: shortSocket(t), start: inprocStarter(b, &starts, nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	before := counter(RestartExit)
	h.mu.Lock()
	p := h.proc
	h.mu.Unlock()
	_ = p.Kill()
	waitUntil(t, "restart", func() bool { return starts.Load() == 2 && h.isReady() })
	if counter(RestartExit) != before+1 {
		t.Fatalf("exit restarts = %d, want %d", counter(RestartExit), before+1)
	}
	if _, err := h.Wrap(context.Background(), []byte("d"), nil); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	h.mu.Lock()
	h.ready = false
	h.mu.Unlock()
	if _, err := h.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, secrets.ErrProviderUnavailable) || !strings.Contains(err.Error(), "restarting") {
		t.Fatalf("while restarting = %v", err)
	}
}

// eng D25: an op stuck past OpDeadline gets the helper killed and replaced;
// a caller's own shorter deadline does not.
func TestHelperDeadlineKillsStuckHelper(t *testing.T) {
	fastTimings(t)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	b := &fakeBackend{hang: hang}
	var starts atomic.Int32
	h, err := StartHelper(HelperOptions{Socket: shortSocket(t), start: inprocStarter(b, &starts, nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Wrap(short, []byte("d"), nil); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("caller deadline = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if starts.Load() != 1 {
		t.Fatal("a caller's own deadline replaced the helper")
	}

	before := counter(RestartDeadline)
	if _, err := h.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("stuck op = %v", err)
	}
	waitUntil(t, "replacement", func() bool { return starts.Load() == 2 })
	if counter(RestartDeadline) != before+1 {
		t.Fatalf("deadline restarts = %d, want %d", counter(RestartDeadline), before+1)
	}
}

// A first start that fails is reported, and the supervisor keeps trying, so
// lenient boot gets a working provider once the token is back.
func TestHelperFirstStartFailure(t *testing.T) {
	fastTimings(t)
	var starts atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	h, err := StartHelper(HelperOptions{Socket: shortSocket(t), start: inprocStarter(&fakeBackend{}, &starts, &fail)})
	if !errors.Is(err, secrets.ErrProviderUnavailable) || h == nil {
		t.Fatalf("StartHelper = %v %v", h, err)
	}
	defer h.Close()
	if _, err := h.Unwrap(context.Background(), []byte("x"), nil); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("before the token is back = %v", err)
	}
	fail.Store(false)
	waitUntil(t, "late start", h.isReady)
}

func TestHelperStartErrors(t *testing.T) {
	fastTimings(t)
	// Exits during start.
	exits := func(string) (proc, error) {
		p := &inproc{ln: nopListener{}, done: make(chan struct{})}
		_ = p.Kill()
		return p, nil
	}
	h, err := StartHelper(HelperOptions{Socket: shortSocket(t), start: exits})
	if err == nil || !strings.Contains(err.Error(), "exited during start") {
		t.Fatalf("exit during start = %v", err)
	}
	_ = h.Close()
	// Never serves.
	startTimeoutOverride.Store(int64(200 * time.Millisecond))
	silent := func(string) (proc, error) { return &inproc{ln: nopListener{}, done: make(chan struct{})}, nil }
	h, err = StartHelper(HelperOptions{Socket: shortSocket(t), start: silent})
	if err == nil || !strings.Contains(err.Error(), "did not serve") {
		t.Fatalf("silent helper = %v", err)
	}
	_ = h.Close()
	// Socket directory cannot be made.
	if _, err := StartHelper(HelperOptions{Socket: "/dev/null/x/h.sock", start: silent}); err == nil {
		t.Fatal("unusable socket directory accepted")
	}
}

func TestHelperCloseIsFinal(t *testing.T) {
	fastTimings(t)
	var starts atomic.Int32
	sock := shortSocket(t)
	h, err := StartHelper(HelperOptions{Socket: sock, start: inprocStarter(&fakeBackend{}, &starts, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal("second Close")
	}
	time.Sleep(3 * restartBackoff)
	if starts.Load() != 1 {
		t.Fatal("helper restarted after Close")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
	if _, err := h.Wrap(context.Background(), nil, nil); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("after Close = %v", err)
	}
}

// The real exec path: this test binary re-executed as the helper (TestMain).
func TestExecStarter(t *testing.T) {
	fastTimings(t)
	startTimeoutOverride.Store(int64(10 * time.Second))
	sock := shortSocket(t)
	cfg := TokenConfig{Module: "/m.so", TokenLabel: "tok", PINFile: "/pin", KeyLabel: "kek-b", DecryptLabels: []string{"kek-a", "kek-0"}, IVMode: IVCaller, Sessions: 10}
	h, err := StartHelper(HelperOptions{Socket: sock, Token: cfg})
	if err != nil {
		t.Fatal(err)
	}
	info := h.Info()
	if info.KeyLabel != "kek-b" || info.TokenLabel != "tok" || strings.Join(info.DecryptLabels, ",") != "kek-a,kek-0" || info.IVMode != IVCaller {
		t.Fatalf("flags did not reach the helper: %+v", info)
	}
	w, err := h.Wrap(context.Background(), []byte("dek"), nil)
	if err != nil || !bytes.HasPrefix(w, []byte("p11:")) {
		t.Fatalf("Wrap through the exec'd helper = %q %v", w, err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v %v", fi, err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	refused, err := StartHelper(HelperOptions{Socket: shortSocket(t), Token: TokenConfig{KeyLabel: "refuse"}})
	if err == nil || !strings.Contains(err.Error(), "exited during start") {
		t.Fatalf("helper that cannot open its token = %v", err)
	}
	_ = refused.Close()
}

func TestRunHelperArgs(t *testing.T) {
	open := func(TokenConfig) (closingBackend, error) { return &fakeBackend{}, nil }
	if err := runHelper([]string{"--bogus"}, open); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := runHelper(nil, open); err == nil || !strings.Contains(err.Error(), "--socket") {
		t.Fatalf("no socket = %v", err)
	}
	if err := runHelper([]string{"--socket", shortSocket(t)}, func(TokenConfig) (closingBackend, error) {
		return nil, errors.New("no token")
	}); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("open failure = %v", err)
	}
	if err := runHelper([]string{"--socket", "/dev/null/x.sock"}, open); err == nil {
		t.Fatal("unlistenable socket accepted")
	}
	// A parent that is not ours: the helper treats sandboxd as gone and exits.
	sock := shortSocket(t)
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- runHelper([]string{"--socket", sock, "--parent", "1", "--decrypt-key-labels", " a, ,b "}, open)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("parent gone = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper outlived its parent")
	}
}

func TestProtocolEdges(t *testing.T) {
	fastTimings(t)
	sock := shortSocket(t)
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serve(ctx, ln, &fakeBackend{info: Info{KeyLabel: "k"}}) }()
	send := func(raw string) reply {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte(raw))
		var r reply
		_ = json.NewDecoder(c).Decode(&r)
		return r
	}
	if r := send(`{"op":"ping","timeout_ms":100}`); r.Class != "" {
		t.Fatalf("ping = %+v", r)
	}
	if r := send(`{"op":"nope"}`); r.Class != "unavailable" || !strings.Contains(r.Error, "unknown op") {
		t.Fatalf("unknown op = %+v", r)
	}
	if r := send(`not json`); r.Class != "" || r.Data != nil {
		t.Fatalf("bad request got a reply: %+v", r)
	}
	if err := errFromReply(reply{Class: "martian", Error: "?"}); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("unknown class = %v", err)
	}
	if classOf(errors.New("plain")) != "unavailable" {
		t.Fatal("an unclassed error must cross as unavailable")
	}
	cancel()
	if err := <-served; err != nil {
		t.Fatalf("serve after cancel = %v", err)
	}
	ln2, _ := net.Listen("unix", sock+"2")
	_ = ln2.Close()
	if err := serve(context.Background(), ln2, &fakeBackend{}); err == nil {
		t.Fatal("serve on a closed listener returned nil")
	}
}

func counter(reason string) int64 {
	if v, ok := helperRestarts.Get(reason).(interface{ Value() int64 }); ok {
		return v.Value()
	}
	return 0
}

func (h *Helper) isReady() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ready
}

// nopListener stands in for a helper that never serves.
type nopListener struct{}

func (nopListener) Accept() (net.Conn, error) { return nil, errors.New("closed") }
func (nopListener) Close() error              { return nil }
func (nopListener) Addr() net.Addr            { return &net.UnixAddr{} }

func TestHelperCurrentKeyVersion(t *testing.T) {
	fastTimings(t)
	var starts atomic.Int32
	h, err := StartHelper(HelperOptions{Socket: shortSocket(t), start: inprocStarter(&fakeBackend{info: Info{KeyLabel: "kek-b", DecryptLabels: []string{"kek-a"}}}, &starts, nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if v, err := h.CurrentKeyVersion(context.Background()); err != nil || v != "p11:kek-b" {
		t.Fatalf("CurrentKeyVersion = %q %v", v, err)
	}
	if got := h.DecryptableKeyVersions(); strings.Join(got, ",") != "p11:kek-b,p11:kek-a" {
		t.Fatalf("DecryptableKeyVersions = %v", got)
	}
	if _, err := (&Helper{}).CurrentKeyVersion(context.Background()); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("not started = %v", err)
	}
	if (&Helper{}).DecryptableKeyVersions() != nil {
		t.Fatal("a helper that never started lists keys")
	}
}
