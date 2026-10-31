//go:build cgo

package pkcs11

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	p11 "github.com/miekg/pkcs11"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// slotInfo is what the token reports about one slot.
type slotInfo struct {
	ID           uint
	Label        string
	Hardware     bool
	Manufacturer string
	Model        string
}

// hsmAPI is the PKCS#11 surface the token uses. hsm.go implements it on
// miekg/pkcs11; tests implement it in Go. Errors are p11.Error codes, and a
// failure of C_DecryptInit comes back wrapped in initError so a GCM tag
// mismatch from C_Decrypt can be told apart (SoftHSM2 reports it as
// CKR_GENERAL_ERROR, Phase 0).
type hsmAPI interface {
	slots() ([]slotInfo, error)
	openSession(slot uint) (p11.SessionHandle, error)
	closeSession(sh p11.SessionHandle)
	loggedIn(sh p11.SessionHandle) (bool, error)
	login(sh p11.SessionHandle, pin string) error
	findKey(sh p11.SessionHandle, label string) (p11.ObjectHandle, bool, error)
	encryptGCM(sh p11.SessionHandle, key p11.ObjectHandle, iv, aad, pt []byte) (ct, ivUsed []byte, err error)
	decryptGCM(sh p11.SessionHandle, key p11.ObjectHandle, iv, aad, ct []byte) ([]byte, error)
	newProbeKey(sh p11.SessionHandle) (p11.ObjectHandle, error)
	destroy(sh p11.SessionHandle, obj p11.ObjectHandle)
	close()
}

type initError struct{ err error }

func (e initError) Error() string { return "init: " + e.err.Error() }
func (e initError) Unwrap() error { return e.err }

// Token is one HSM token opened by the helper: a logged-in session pool and
// the configured key labels.
type Token struct {
	api      hsmAPI
	slot     slotInfo
	pin      string
	current  string
	decrypt  map[string]bool
	ivMode   string
	sessions chan p11.SessionHandle

	mu      sync.Mutex
	handles map[string]p11.ObjectHandle
}

// OpenToken opens the vendor module and the configured token.
func OpenToken(cfg TokenConfig) (*Token, error) {
	api, err := openModule(cfg.Module)
	if err != nil {
		return nil, err
	}
	t, err := openToken(api, cfg)
	if err != nil {
		api.close()
		return nil, err
	}
	return t, nil
}

func openToken(api hsmAPI, cfg TokenConfig) (*Token, error) {
	if strings.TrimSpace(cfg.KeyLabel) == "" {
		return nil, errors.New("SB_SECRET_PKCS11_KEY_LABEL is required")
	}
	pin, err := readPIN(cfg.PINFile)
	if err != nil {
		return nil, err
	}
	slot, err := findSlot(api, cfg.TokenLabel)
	if err != nil {
		return nil, err
	}
	n := max(cfg.Sessions, 1)
	t := &Token{
		api: api, slot: slot, pin: pin, current: cfg.KeyLabel,
		decrypt: map[string]bool{}, sessions: make(chan p11.SessionHandle, n),
		handles: map[string]p11.ObjectHandle{},
	}
	for _, l := range cfg.DecryptLabels {
		if l = strings.TrimSpace(l); l != "" && l != cfg.KeyLabel {
			t.decrypt[l] = true
		}
	}
	for i := 0; i < n; i++ {
		sh, err := api.openSession(slot.ID)
		if err != nil {
			t.closeSessions()
			return nil, fmt.Errorf("%w: open pkcs11 session: %v", classify(err), err)
		}
		t.sessions <- sh
		if i == 0 {
			// One login covers every session on the token.
			if err := t.ensureLogin(sh); err != nil {
				t.closeSessions()
				return nil, err
			}
		}
	}
	mode, err := t.probeIVMode(cfg.IVMode)
	if err != nil {
		t.closeSessions()
		return nil, err
	}
	t.ivMode = mode
	// A helper that cannot find its current key is not ready.
	if err := t.Ping(context.Background()); err != nil {
		t.closeSessions()
		return nil, err
	}
	return t, nil
}

func readPIN(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("SB_SECRET_PKCS11_PIN_FILE is required")
	}
	if err := secrets.RefuseGroupOtherBits(path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read SB_SECRET_PKCS11_PIN_FILE: %w", err)
	}
	pin := strings.TrimRight(string(raw), "\r\n")
	if pin == "" {
		return "", errors.New("SB_SECRET_PKCS11_PIN_FILE is empty")
	}
	return pin, nil
}

func findSlot(api hsmAPI, label string) (slotInfo, error) {
	slots, err := api.slots()
	if err != nil {
		return slotInfo{}, fmt.Errorf("%w: list pkcs11 slots: %v", secrets.ErrProviderUnavailable, err)
	}
	var match []slotInfo
	for _, s := range slots {
		if s.Label == label {
			match = append(match, s)
		}
	}
	if len(match) != 1 {
		return slotInfo{}, fmt.Errorf("SB_SECRET_PKCS11_TOKEN_LABEL=%q matches %d tokens; it must match exactly one", label, len(match))
	}
	return match[0], nil
}

// probeIVMode decides who picks the GCM IV. AWS CloudHSM writes its own IV
// and refuses the caller's; SoftHSM2 uses the caller's, and given a zeroed
// buffer encrypts with the all-zero IV (Phase 0). The probe runs on a
// throwaway session key, never the real one: on a token like SoftHSM2 it does
// encrypt with the all-zero IV, and doing that with the real key at every
// helper start would repeat a (key, IV) pair, which GCM must never do.
func (t *Token) probeIVMode(mode string) (string, error) {
	switch mode {
	case IVHSM, IVCaller:
		return mode, nil
	case "", IVAuto:
	default:
		return "", fmt.Errorf("SB_SECRET_PKCS11_GCM_IV must be auto, hsm or caller (got %q)", mode)
	}
	out, err := t.withSession(context.Background(), func(sh p11.SessionHandle) ([]byte, error) {
		key, err := t.api.newProbeKey(sh)
		if err != nil {
			return nil, fmt.Errorf("%w: SB_SECRET_PKCS11_GCM_IV=auto needs a session AES key for its probe (%v); set hsm or caller instead", secrets.ErrProviderUnavailable, err)
		}
		defer t.api.destroy(sh, key)
		_, iv, err := t.api.encryptGCM(sh, key, make([]byte, ivLen), nil, make([]byte, 32))
		if err != nil {
			return nil, fmt.Errorf("%w: pkcs11 GCM IV probe: %v", secrets.ErrProviderUnavailable, err)
		}
		if isZero(iv) {
			return []byte(IVCaller), nil
		}
		return []byte(IVHSM), nil
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Info implements backend.
func (t *Token) Info() Info {
	labels := make([]string, 0, len(t.decrypt))
	for l := range t.decrypt {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	return Info{
		HardwareSlot: t.slot.Hardware, TokenLabel: t.slot.Label,
		Manufacturer: t.slot.Manufacturer, Model: t.slot.Model,
		KeyLabel: t.current, DecryptLabels: labels, IVMode: t.ivMode,
	}
}

// Ping implements backend: the current key is on the token right now.
func (t *Token) Ping(ctx context.Context) error {
	_, err := t.withSession(ctx, func(sh p11.SessionHandle) ([]byte, error) {
		t.forget(t.current)
		_, err := t.keyHandle(sh, t.current)
		return nil, err
	})
	return err
}

// Wrap implements backend: AES-GCM under the current label, 128-bit tag.
func (t *Token) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	return t.withSession(ctx, func(sh p11.SessionHandle) ([]byte, error) {
		key, err := t.keyHandle(sh, t.current)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, ivLen)
		if t.ivMode == IVCaller {
			if _, err := rand.Read(iv); err != nil {
				return nil, fmt.Errorf("%w: pkcs11 IV: %v", secrets.ErrProviderUnavailable, err)
			}
		}
		ct, used, err := t.api.encryptGCM(sh, key, iv, aad, dek)
		if err != nil {
			return nil, t.opError(t.current, err)
		}
		if isZero(used) {
			// Never let a nonce repeat: refuse rather than store it.
			return nil, fmt.Errorf("%w: pkcs11 token returned an all-zero GCM IV; set SB_SECRET_PKCS11_GCM_IV=caller", secrets.ErrProviderUnavailable)
		}
		return encodeWrapped(wrappedKey{Label: t.current, IV: used, Ciphertext: ct})
	})
}

// Unwrap implements backend.
func (t *Token) Unwrap(ctx context.Context, raw, aad []byte) ([]byte, error) {
	w, err := decodeWrapped(raw)
	if err != nil {
		return nil, err
	}
	if w.Label != t.current && !t.decrypt[w.Label] {
		return nil, fmt.Errorf("%w: wrapped under an unknown key label %q", secrets.ErrDecryptFailed, w.Label)
	}
	return t.withSession(ctx, func(sh p11.SessionHandle) ([]byte, error) {
		key, err := t.keyHandle(sh, w.Label)
		if err != nil {
			return nil, err
		}
		pt, err := t.api.decryptGCM(sh, key, w.IV, aad, w.Ciphertext)
		if err != nil {
			var ie initError
			if !errors.As(err, &ie) && errors.Is(err, p11.Error(p11.CKR_GENERAL_ERROR)) {
				return nil, fmt.Errorf("%w: pkcs11 decrypt: %v", secrets.ErrDecryptFailed, err)
			}
			return nil, t.opError(w.Label, err)
		}
		return pt, nil
	})
}

// opError passes a return code the session retry acts on through unchanged,
// and drops a stale cached handle so the retry searches the label again.
func (t *Token) opError(label string, err error) error {
	if isCode(err, p11.CKR_OBJECT_HANDLE_INVALID, p11.CKR_KEY_HANDLE_INVALID) {
		t.forget(label)
	}
	return err
}

// withSession runs fn on a pooled session and retries it once after the
// recovery its failure calls for (§2): a lost login logs in again; a stale
// key handle is searched again; a broken session or a token that went away
// (an HSM HA failover) is reopened and logged in. What is left after the
// retry is classified.
func (t *Token) withSession(ctx context.Context, fn func(p11.SessionHandle) ([]byte, error)) ([]byte, error) {
	var sh p11.SessionHandle
	select {
	case sh = <-t.sessions:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: no free pkcs11 session: %v", secrets.ErrProviderThrottled, ctx.Err())
	}
	defer func() { t.sessions <- sh }()
	out, err := fn(sh)
	switch {
	case err == nil:
		return out, nil
	case isCode(err, p11.CKR_USER_NOT_LOGGED_IN):
		if lerr := t.login(sh); lerr != nil {
			return nil, lerr
		}
		out, err = fn(sh)
	case isCode(err, p11.CKR_OBJECT_HANDLE_INVALID, p11.CKR_KEY_HANDLE_INVALID):
		out, err = fn(sh)
	case isCode(err, p11.CKR_SESSION_HANDLE_INVALID, p11.CKR_SESSION_CLOSED, p11.CKR_DEVICE_REMOVED, p11.CKR_TOKEN_NOT_PRESENT):
		fresh, rerr := t.reopen(sh)
		if rerr != nil {
			return nil, rerr
		}
		sh = fresh
		out, err = fn(sh)
	}
	if err != nil && !classed(err) {
		err = fmt.Errorf("%w: pkcs11: %v", classify(err), err)
	}
	return out, err
}

func isCode(err error, codes ...uint) bool {
	for _, c := range codes {
		if errors.Is(err, p11.Error(c)) {
			return true
		}
	}
	return false
}

func classed(err error) bool {
	for _, c := range classes {
		if errors.Is(err, c.err) {
			return true
		}
	}
	return false
}

// reopen replaces a broken session and logs in again: after an HSM HA
// failover the token may have dropped the login with the session.
func (t *Token) reopen(old p11.SessionHandle) (p11.SessionHandle, error) {
	t.api.closeSession(old)
	t.mu.Lock()
	t.handles = map[string]p11.ObjectHandle{}
	t.mu.Unlock()
	sh, err := t.api.openSession(t.slot.ID)
	if err != nil {
		// Keep the dead handle in the pool: its next use fails the same way
		// and tries again.
		return old, fmt.Errorf("%w: reopen pkcs11 session: %v", classify(err), err)
	}
	if err := t.ensureLogin(sh); err != nil {
		return sh, err
	}
	return sh, nil
}

func (t *Token) ensureLogin(sh p11.SessionHandle) error {
	if in, err := t.api.loggedIn(sh); err == nil && in {
		return nil
	}
	return t.login(sh)
}

func (t *Token) login(sh p11.SessionHandle) error {
	if err := t.api.login(sh, t.pin); err != nil && !isCode(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
		return fmt.Errorf("%w: pkcs11 login: %v", classify(err), err)
	}
	return nil
}

func (t *Token) forget(label string) {
	t.mu.Lock()
	delete(t.handles, label)
	t.mu.Unlock()
}

// keyHandle finds label's key object, from cache or by search. A label that
// is not found is classified here, where the login state is known.
func (t *Token) keyHandle(sh p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	t.mu.Lock()
	h, ok := t.handles[label]
	t.mu.Unlock()
	if ok {
		return h, nil
	}
	h, found, err := t.api.findKey(sh, label)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, t.missingLabel(sh, label)
	}
	t.mu.Lock()
	t.handles[label] = h
	t.mu.Unlock()
	return h, nil
}

// missingLabel classifies a key label that is not on the token (§2). Private
// objects are invisible without a login (Phase 0), so a missing label counts
// only while logged in: otherwise this reports CKR_USER_NOT_LOGGED_IN and the
// session retry logs in and searches again. Logged in, the current label gone
// is a revoke; a decrypt-only label gone while the current one exists is a
// retired version; both gone is a revoke, so a revoke during a rotation
// window still trips.
func (t *Token) missingLabel(sh p11.SessionHandle, label string) error {
	if in, err := t.api.loggedIn(sh); err != nil || !in {
		return fmt.Errorf("pkcs11 key %q not visible: %w", label, p11.Error(p11.CKR_USER_NOT_LOGGED_IN))
	}
	if label == t.current {
		return fmt.Errorf("%w: pkcs11 key %q is not on the token", secrets.ErrKeyRevoked, label)
	}
	if _, found, err := t.api.findKey(sh, t.current); err == nil && found {
		return fmt.Errorf("%w: pkcs11 key %q is gone; rows on it need a rewrap", secrets.ErrKeyVersionRetired, label)
	}
	return fmt.Errorf("%w: pkcs11 keys %q and %q are not on the token", secrets.ErrKeyRevoked, label, t.current)
}

// classify maps a PKCS#11 return code to a provider class (§2 table).
func classify(err error) error {
	var code p11.Error
	if !errors.As(err, &code) {
		return secrets.ErrProviderUnavailable
	}
	switch uint(code) {
	case p11.CKR_SESSION_COUNT, p11.CKR_DEVICE_MEMORY:
		return secrets.ErrProviderThrottled
	case p11.CKR_KEY_FUNCTION_NOT_PERMITTED:
		return secrets.ErrKeyRevoked
	case p11.CKR_PIN_INCORRECT, p11.CKR_PIN_EXPIRED, p11.CKR_PIN_LOCKED:
		return secrets.ErrProviderDenied
	case p11.CKR_ENCRYPTED_DATA_INVALID, p11.CKR_ENCRYPTED_DATA_LEN_RANGE:
		return secrets.ErrDecryptFailed
	default:
		return secrets.ErrProviderUnavailable
	}
}

// Close closes every pooled session and finalizes the module.
func (t *Token) Close() {
	t.closeSessions()
	t.api.close()
}

func (t *Token) closeSessions() {
	for {
		select {
		case sh := <-t.sessions:
			t.api.closeSession(sh)
		default:
			return
		}
	}
}
