//go:build cgo

package pkcs11

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	p11 "github.com/miekg/pkcs11"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// fakeHSM is a token in Go with the behaviors Phase 0 recorded: private keys
// are invisible without a login, SoftHSM2 uses the caller's IV (even an
// all-zero one) while CloudHSM writes its own, and a GCM tag mismatch comes
// back from C_Decrypt as CKR_GENERAL_ERROR.
type fakeHSM struct {
	mu         sync.Mutex
	slotList   []slotInfo
	slotsErr   error
	pin        string
	loggedInV  bool
	logins     int
	next       uint
	open       map[p11.SessionHandle]bool
	keys       map[string]p11.ObjectHandle
	objs       map[p11.ObjectHandle]*fakeKey
	writesIV   bool
	noProbeKey bool
	fail       map[string][]error
	closed     bool
}

type fakeKey struct {
	aead      cipher.AEAD
	noDecrypt bool
}

func newFakeHSM(labels ...string) *fakeHSM {
	f := &fakeHSM{
		slotList: []slotInfo{{ID: 3, Label: "tok", Hardware: true, Manufacturer: "Fake", Model: "F1"}, {ID: 4, Label: "other"}},
		pin:      "1234", open: map[p11.SessionHandle]bool{}, keys: map[string]p11.ObjectHandle{},
		objs: map[p11.ObjectHandle]*fakeKey{}, fail: map[string][]error{},
	}
	for _, l := range labels {
		f.addKey(l)
	}
	return f
}

func (f *fakeHSM) newKey() p11.ObjectHandle {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	block, _ := aes.NewCipher(k)
	aead, _ := cipher.NewGCM(block)
	f.next++
	h := p11.ObjectHandle(f.next)
	f.objs[h] = &fakeKey{aead: aead}
	return h
}

func (f *fakeHSM) addKey(label string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[label] = f.newKey()
}

func (f *fakeHSM) removeKey(label string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objs, f.keys[label])
	delete(f.keys, label)
}

// rekey keeps the label but gives it a new object (and handle), so a cached
// handle goes stale.
func (f *fakeHSM) rekey(label string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.keys[label]
	f.next++
	f.keys[label] = p11.ObjectHandle(f.next)
	f.objs[f.keys[label]] = f.objs[old]
	delete(f.objs, old)
}

func (f *fakeHSM) inject(method string, errs ...error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[method] = append(f.fail[method], errs...)
}

func (f *fakeHSM) injected(method string) error {
	if q := f.fail[method]; len(q) > 0 {
		f.fail[method] = q[1:]
		return q[0]
	}
	return nil
}

func code(c uint) error { return p11.Error(c) }

func (f *fakeHSM) slots() ([]slotInfo, error) { return f.slotList, f.slotsErr }

func (f *fakeHSM) openSession(uint) (p11.SessionHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("open"); err != nil {
		return 0, err
	}
	f.next++
	sh := p11.SessionHandle(f.next)
	f.open[sh] = true
	return sh, nil
}

func (f *fakeHSM) closeSession(sh p11.SessionHandle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.open, sh)
}

func (f *fakeHSM) loggedIn(sh p11.SessionHandle) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.open[sh] {
		return false, code(p11.CKR_SESSION_HANDLE_INVALID)
	}
	return f.loggedInV, nil
}

func (f *fakeHSM) login(_ p11.SessionHandle, pin string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("login"); err != nil {
		return err
	}
	if pin != f.pin {
		return code(p11.CKR_PIN_INCORRECT)
	}
	if f.loggedInV {
		return code(p11.CKR_USER_ALREADY_LOGGED_IN)
	}
	f.loggedInV = true
	f.logins++
	return nil
}

func (f *fakeHSM) findKey(sh p11.SessionHandle, label string) (p11.ObjectHandle, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("find"); err != nil {
		return 0, false, err
	}
	if !f.open[sh] {
		return 0, false, code(p11.CKR_SESSION_HANDLE_INVALID)
	}
	h, ok := f.keys[label]
	if !ok || !f.loggedInV {
		return 0, false, nil
	}
	return h, true, nil
}

func (f *fakeHSM) encryptGCM(sh p11.SessionHandle, key p11.ObjectHandle, iv, aad, pt []byte) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("encrypt"); err != nil {
		return nil, nil, err
	}
	k, ok := f.objs[key]
	if !ok {
		return nil, nil, code(p11.CKR_OBJECT_HANDLE_INVALID)
	}
	used := append([]byte(nil), iv...)
	if f.writesIV {
		_, _ = rand.Read(used)
	}
	return k.aead.Seal(nil, used, pt, aad), used, nil
}

func (f *fakeHSM) decryptGCM(sh p11.SessionHandle, key p11.ObjectHandle, iv, aad, ct []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("decryptInit"); err != nil {
		return nil, initError{err}
	}
	k, ok := f.objs[key]
	if !ok {
		return nil, initError{code(p11.CKR_OBJECT_HANDLE_INVALID)}
	}
	if k.noDecrypt {
		return nil, initError{code(p11.CKR_KEY_FUNCTION_NOT_PERMITTED)}
	}
	if err := f.injected("decrypt"); err != nil {
		return nil, err
	}
	pt, err := k.aead.Open(nil, iv, ct, aad)
	if err != nil {
		return nil, code(p11.CKR_GENERAL_ERROR)
	}
	return pt, nil
}

func (f *fakeHSM) newProbeKey(p11.SessionHandle) (p11.ObjectHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noProbeKey {
		return 0, code(p11.CKR_FUNCTION_NOT_SUPPORTED)
	}
	return f.newKey(), nil
}

func (f *fakeHSM) destroy(_ p11.SessionHandle, obj p11.ObjectHandle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objs, obj)
}

func (f *fakeHSM) close() { f.closed = true }

func pinFile(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func openFake(t *testing.T, f *fakeHSM, cfg TokenConfig) *Token {
	t.Helper()
	if cfg.TokenLabel == "" {
		cfg.TokenLabel = "tok"
	}
	if cfg.PINFile == "" {
		cfg.PINFile = pinFile(t, 0o400, "1234\n")
	}
	if cfg.Sessions == 0 {
		cfg.Sessions = 2
	}
	tok, err := openToken(f, cfg)
	if err != nil {
		t.Fatalf("openToken: %v", err)
	}
	return tok
}

func TestTokenRoundTrip(t *testing.T) {
	f := newFakeHSM("kek-b", "kek-a")
	tok := openFake(t, f, TokenConfig{KeyLabel: "kek-b", DecryptLabels: []string{"kek-a", " ", "kek-b", "kek-0"}})
	if f.logins != 1 || len(f.open) != 2 {
		t.Fatalf("logins %d sessions %d, want 1 login for a pool of 2", f.logins, len(f.open))
	}
	info := tok.Info()
	if info.IVMode != IVCaller || !info.HardwareSlot || info.Manufacturer != "Fake" || strings.Join(info.DecryptLabels, ",") != "kek-0,kek-a" {
		t.Fatalf("Info = %+v", info)
	}
	ctx := context.Background()
	aad := []byte("ctx")
	w, err := tok.Wrap(ctx, []byte("data-key"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(w, []byte("p11:1:")) {
		t.Fatalf("wrapped = %q", w)
	}
	if got, err := tok.Unwrap(ctx, w, aad); err != nil || string(got) != "data-key" {
		t.Fatalf("Unwrap = %q %v", got, err)
	}
	if _, err := tok.Unwrap(ctx, w, []byte("other")); !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("wrong AAD = %v, want ErrDecryptFailed", err)
	}
	if err := tok.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	tok.Close()
	if !f.closed || len(f.open) != 0 {
		t.Fatal("Close left sessions or the module open")
	}
}

func TestTokenIVModes(t *testing.T) {
	// A CloudHSM-like token writes its own IV: auto picks hsm.
	cloud := newFakeHSM("k")
	cloud.writesIV = true
	tok := openFake(t, cloud, TokenConfig{KeyLabel: "k"})
	if tok.Info().IVMode != IVHSM {
		t.Fatalf("auto on an IV-writing token = %s", tok.Info().IVMode)
	}
	if _, err := tok.Wrap(context.Background(), []byte("d"), nil); err != nil {
		t.Fatal(err)
	}
	// Told hsm on a token that does not write the IV: the all-zero IV is
	// refused, never stored.
	soft := newFakeHSM("k")
	tok = openFake(t, soft, TokenConfig{KeyLabel: "k", IVMode: IVHSM})
	if _, err := tok.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, secrets.ErrProviderUnavailable) || !strings.Contains(err.Error(), "all-zero GCM IV") {
		t.Fatalf("zero IV = %v", err)
	}
	// The probe never touches the real key.
	probe := newFakeHSM("k")
	probe.inject("encrypt") // nothing queued: harmless
	_ = openFake(t, probe, TokenConfig{KeyLabel: "k"})
	if len(probe.objs) != 1 {
		t.Fatalf("probe key left behind: %d objects", len(probe.objs))
	}
	// No session keys allowed: auto refuses and names the fix.
	locked := newFakeHSM("k")
	locked.noProbeKey = true
	if _, err := openToken(locked, TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinFile(t, 0o600, "1234"), Sessions: 1}); err == nil || !strings.Contains(err.Error(), "set hsm or caller") {
		t.Fatalf("no probe key = %v", err)
	}
	if _, err := openToken(newFakeHSM("k"), TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinFile(t, 0o600, "1234"), IVMode: "random"}); err == nil {
		t.Fatal("unknown IV mode accepted")
	}
	failing := newFakeHSM("k")
	failing.inject("encrypt", code(p11.CKR_MECHANISM_INVALID))
	if _, err := openToken(failing, TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinFile(t, 0o600, "1234")}); err == nil || !strings.Contains(err.Error(), "IV probe") {
		t.Fatalf("probe encrypt failure = %v", err)
	}
}

// §2 label rules across a rotation (eng D23).
func TestTokenLabelRotation(t *testing.T) {
	ctx := context.Background()
	f := newFakeHSM("kek-a", "kek-b")
	oldRow, err := openFake(t, f, TokenConfig{KeyLabel: "kek-a"}).Wrap(ctx, []byte("old"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := openFake(t, f, TokenConfig{KeyLabel: "kek-b", DecryptLabels: []string{"kek-a"}})
	newRow, err := tok.Wrap(ctx, []byte("new"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tok.Unwrap(ctx, oldRow, nil); err != nil || string(got) != "old" {
		t.Fatalf("decrypt-only label = %q %v", got, err)
	}
	if _, err := openFake(t, f, TokenConfig{KeyLabel: "kek-b"}).Unwrap(ctx, oldRow, nil); !errors.Is(err, secrets.ErrDecryptFailed) || !strings.Contains(err.Error(), "unknown key label") {
		t.Fatalf("label in neither setting = %v", err)
	}
	f.removeKey("kek-a")
	if _, err := tok.Unwrap(ctx, oldRow, nil); !errors.Is(err, secrets.ErrKeyVersionRetired) {
		t.Fatalf("old label gone, current present = %v, want retired", err)
	}
	f.removeKey("kek-b")
	if _, err := tok.Unwrap(ctx, oldRow, nil); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("both labels gone = %v, want revoked", err)
	}
	if _, err := tok.Unwrap(ctx, newRow, nil); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("current label gone = %v, want revoked", err)
	}
	if _, err := tok.Wrap(ctx, []byte("x"), nil); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("wrap with the current label gone = %v, want revoked", err)
	}
}

// Private objects are invisible without a login (Phase 0): a logged-out
// session logs in again instead of reporting a revoke.
func TestTokenLoginLost(t *testing.T) {
	f := newFakeHSM("k")
	tok := openFake(t, f, TokenConfig{KeyLabel: "k"})
	tok.forget("k")
	f.mu.Lock()
	f.loggedInV = false
	f.mu.Unlock()
	if _, err := tok.Wrap(context.Background(), []byte("d"), nil); err != nil {
		t.Fatalf("after the login was lost = %v", err)
	}
	if f.logins != 2 {
		t.Fatalf("logins = %d, want a re-login", f.logins)
	}
	f.inject("encrypt", code(p11.CKR_USER_NOT_LOGGED_IN))
	f.inject("login", code(p11.CKR_PIN_LOCKED))
	if _, err := tok.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, secrets.ErrProviderDenied) {
		t.Fatalf("re-login refused = %v, want denied", err)
	}
}

func TestTokenSessionRecovery(t *testing.T) {
	ctx := context.Background()
	for _, c := range []uint{p11.CKR_SESSION_HANDLE_INVALID, p11.CKR_SESSION_CLOSED, p11.CKR_DEVICE_REMOVED, p11.CKR_TOKEN_NOT_PRESENT} {
		f := newFakeHSM("k")
		tok := openFake(t, f, TokenConfig{KeyLabel: "k", Sessions: 1})
		f.inject("encrypt", code(c))
		if _, err := tok.Wrap(ctx, []byte("d"), nil); err != nil {
			t.Fatalf("code %#x: not recovered: %v", c, err)
		}
	}
	// The token is gone for good: reopening fails and is classified.
	f := newFakeHSM("k")
	tok := openFake(t, f, TokenConfig{KeyLabel: "k", Sessions: 1})
	f.inject("encrypt", code(p11.CKR_DEVICE_REMOVED))
	f.inject("open", code(p11.CKR_SESSION_COUNT))
	if _, err := tok.Wrap(ctx, []byte("d"), nil); !errors.Is(err, secrets.ErrProviderThrottled) {
		t.Fatalf("reopen refused = %v", err)
	}
	// The dead handle stays in the pool and heals on its next use.
	if _, err := tok.Wrap(ctx, []byte("d"), nil); err != nil {
		t.Fatalf("after the token came back = %v", err)
	}
	// A reopened session whose login fails.
	f.inject("encrypt", code(p11.CKR_TOKEN_NOT_PRESENT))
	f.mu.Lock()
	f.loggedInV = false
	f.mu.Unlock()
	f.inject("login", code(p11.CKR_PIN_EXPIRED))
	if _, err := tok.Wrap(ctx, []byte("d"), nil); !errors.Is(err, secrets.ErrProviderDenied) {
		t.Fatalf("login after reopen refused = %v", err)
	}
}

// A cached handle that went stale is searched again (§2).
func TestTokenStaleHandle(t *testing.T) {
	f := newFakeHSM("k")
	tok := openFake(t, f, TokenConfig{KeyLabel: "k"})
	ctx := context.Background()
	w, err := tok.Wrap(ctx, []byte("d"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.rekey("k")
	if _, err := tok.Wrap(ctx, []byte("d"), nil); err != nil {
		t.Fatalf("wrap with a stale handle = %v", err)
	}
	f.rekey("k")
	if got, err := tok.Unwrap(ctx, w, nil); err != nil || string(got) != "d" {
		t.Fatalf("unwrap with a stale handle = %q %v", got, err)
	}
}

func TestTokenErrorClasses(t *testing.T) {
	ctx := context.Background()
	f := newFakeHSM("k")
	tok := openFake(t, f, TokenConfig{KeyLabel: "k"})
	w, err := tok.Wrap(ctx, []byte("d"), nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method string
		err    error
		want   error
	}{
		{"decryptInit", code(p11.CKR_GENERAL_ERROR), secrets.ErrProviderUnavailable},
		{"decrypt", code(p11.CKR_ENCRYPTED_DATA_INVALID), secrets.ErrDecryptFailed},
		{"decrypt", code(p11.CKR_ENCRYPTED_DATA_LEN_RANGE), secrets.ErrDecryptFailed},
		{"decryptInit", code(p11.CKR_KEY_FUNCTION_NOT_PERMITTED), secrets.ErrKeyRevoked},
		{"decryptInit", code(p11.CKR_SESSION_COUNT), secrets.ErrProviderThrottled},
		{"decryptInit", code(p11.CKR_DEVICE_MEMORY), secrets.ErrProviderThrottled},
		{"decryptInit", code(p11.CKR_DEVICE_ERROR), secrets.ErrProviderUnavailable},
		{"find", code(p11.CKR_DEVICE_ERROR), secrets.ErrProviderUnavailable},
	}
	for _, tc := range cases {
		tok.forget("k")
		f.inject(tc.method, tc.err)
		if _, err := tok.Unwrap(ctx, w, nil); !errors.Is(err, tc.want) {
			t.Fatalf("%s %v = %v, want %v", tc.method, tc.err, err, tc.want)
		}
	}
	f.mu.Lock()
	f.objs[f.keys["k"]].noDecrypt = true
	f.mu.Unlock()
	if _, err := tok.Unwrap(ctx, w, nil); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("decrypt turned off on the key = %v, want revoked", err)
	}
	if _, err := tok.Unwrap(ctx, []byte("vault:v1:x"), nil); !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("foreign ciphertext = %v", err)
	}
	if classify(errors.New("not a pkcs11 code")) != secrets.ErrProviderUnavailable {
		t.Fatal("classify of a non-code error")
	}
}

// The pool holds Sessions sessions; a caller that cannot get one by its
// deadline is throttled.
func TestTokenPoolExhausted(t *testing.T) {
	tok := openFake(t, newFakeHSM("k"), TokenConfig{KeyLabel: "k", Sessions: 1})
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = tok.withSession(context.Background(), func(p11.SessionHandle) ([]byte, error) {
			close(held)
			<-release
			return nil, nil
		})
	}()
	<-held
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := tok.Wrap(ctx, []byte("d"), nil); !errors.Is(err, secrets.ErrProviderThrottled) {
		t.Fatalf("no free session = %v", err)
	}
	close(release)
}

func TestTokenOpenRefusals(t *testing.T) {
	good := pinFile(t, 0o400, "1234")
	pinDir := filepath.Join(t.TempDir(), "pin-dir")
	if err := os.Mkdir(pinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		f    *fakeHSM
		cfg  TokenConfig
		want string
	}{
		{"no key label", newFakeHSM(), TokenConfig{TokenLabel: "tok", PINFile: good}, "SB_SECRET_PKCS11_KEY_LABEL"},
		{"no pin file", newFakeHSM("k"), TokenConfig{TokenLabel: "tok", KeyLabel: "k"}, "SB_SECRET_PKCS11_PIN_FILE is required"},
		{"pin readable by group", newFakeHSM("k"), TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinFile(t, 0o640, "1234")}, "allow only its owner"},
		{"empty pin", newFakeHSM("k"), TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinFile(t, 0o600, "\n")}, "is empty"},
		{"pin path is a directory", newFakeHSM("k"), TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinDir}, "read SB_SECRET_PKCS11_PIN_FILE"},
		{"no such token", newFakeHSM("k"), TokenConfig{TokenLabel: "nope", KeyLabel: "k", PINFile: good}, "matches 0 tokens"},
		{"wrong pin", newFakeHSM("k"), TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: pinFile(t, 0o600, "0000")}, "pkcs11 login"},
		{"current key missing", newFakeHSM("other"), TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: good}, "not on the token"},
	}
	for _, tc := range cases {
		if _, err := openToken(tc.f, tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	twice := newFakeHSM("k")
	twice.slotList = append(twice.slotList, slotInfo{ID: 9, Label: "tok"})
	if _, err := openToken(twice, TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: good}); err == nil || !strings.Contains(err.Error(), "matches 2 tokens") {
		t.Fatalf("two matching tokens = %v", err)
	}
	broken := newFakeHSM("k")
	broken.slotsErr = code(p11.CKR_DEVICE_ERROR)
	if _, err := openToken(broken, TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: good}); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("slot list failure = %v", err)
	}
	noSession := newFakeHSM("k")
	noSession.inject("open", code(p11.CKR_SESSION_COUNT))
	if _, err := openToken(noSession, TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: good}); !errors.Is(err, secrets.ErrProviderThrottled) {
		t.Fatalf("session limit at open = %v", err)
	}
	wrongPIN := newFakeHSM("k")
	wrongPIN.pin = "9999"
	if _, err := openToken(wrongPIN, TokenConfig{TokenLabel: "tok", KeyLabel: "k", PINFile: good}); !errors.Is(err, secrets.ErrProviderDenied) {
		t.Fatalf("wrong PIN = %v, want denied", err)
	}
	if _, err := OpenToken(TokenConfig{}); err == nil || !strings.Contains(err.Error(), "SB_SECRET_PKCS11_MODULE") {
		t.Fatalf("no module = %v", err)
	}
	if _, err := OpenToken(TokenConfig{Module: filepath.Join(t.TempDir(), "missing.so")}); err == nil || !strings.Contains(err.Error(), "could not be loaded") {
		t.Fatalf("missing module = %v", err)
	}
}
