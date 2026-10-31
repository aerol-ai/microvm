//go:build integration && cgo

package pkcs11

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// TestPKCS11Live runs the pkcs11 provider against any real PKCS#11 module
// (plans/customer-key-custody.md Phase 6): SoftHSM2 in the tag-gated CI job,
// and the one operator-run AWS CloudHSM check. It skips unless
// SB_TEST_PKCS11_MODULE names the module; the token, PIN file and key label
// come from SB_TEST_PKCS11_TOKEN_LABEL, SB_TEST_PKCS11_PIN_FILE and
// SB_TEST_PKCS11_KEY_LABEL. SB_TEST_PKCS11_KEY_LABEL_B, when set, is a second
// key for the rotation checks, and SB_TEST_PKCS11_EXPECT_IV ("hsm" for
// CloudHSM, which writes its own GCM IV) pins what the IV probe must find.
func TestPKCS11Live(t *testing.T) {
	module := os.Getenv("SB_TEST_PKCS11_MODULE")
	if module == "" {
		t.Skip("SB_TEST_PKCS11_MODULE not set; skipping the live PKCS#11 module")
	}
	cfg := TokenConfig{
		Module:     module,
		TokenLabel: os.Getenv("SB_TEST_PKCS11_TOKEN_LABEL"),
		PINFile:    os.Getenv("SB_TEST_PKCS11_PIN_FILE"),
		KeyLabel:   os.Getenv("SB_TEST_PKCS11_KEY_LABEL"),
		IVMode:     IVAuto,
		Sessions:   4,
	}
	labelB := os.Getenv("SB_TEST_PKCS11_KEY_LABEL_B")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	p, err := OpenInProcess(cfg)
	if err != nil {
		t.Fatalf("open %s: %v", module, err)
	}
	info := p.Info()
	t.Logf("token %q (%s %s), hardware slot %v, IV mode %s", info.TokenLabel, info.Manufacturer, info.Model, info.HardwareSlot, info.IVMode)
	if want := os.Getenv("SB_TEST_PKCS11_EXPECT_IV"); want != "" && info.IVMode != want {
		t.Fatalf("IV probe chose %q, want %q", info.IVMode, want)
	}
	if err := secrets.CanaryWrapUnwrap(ctx, p); err != nil {
		t.Fatalf("canary: %v", err)
	}
	encCtx := map[string]string{"aerolvm.ref": "live"}
	dek := []byte("0123456789abcdef0123456789abcdef")
	w1, err := p.Wrap(ctx, dek, encCtx)
	if err != nil || secrets.WrappedKeyVersion(w1) != "p11:"+cfg.KeyLabel {
		t.Fatalf("wrap = %q %v", secrets.WrappedKeyVersion(w1), err)
	}
	w2, _ := p.Wrap(ctx, dek, encCtx)
	if bytes.Equal(w1, w2) {
		t.Fatal("two wraps of one key are identical: the GCM IV is not fresh")
	}
	if got, err := p.Unwrap(ctx, w1, encCtx); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap = %v", err)
	}
	if _, err := p.Unwrap(ctx, w1, map[string]string{"aerolvm.ref": "other"}); !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("unwrap with the wrong context = %v, want ErrDecryptFailed", err)
	}
	p.Close()

	// A label the token does not hold is a revoke (§2), at open or on use.
	missing := cfg
	missing.KeyLabel = "aerolvm-itest-missing-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if m, err := OpenInProcess(missing); err == nil {
		_, err = m.Wrap(ctx, dek, encCtx)
		m.Close()
		if !errors.Is(err, secrets.ErrKeyRevoked) {
			t.Fatalf("wrap with a missing key label = %v, want ErrKeyRevoked", err)
		}
	} else if !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("open with a missing key label = %v, want ErrKeyRevoked", err)
	}

	// Rotation (eng D23): B current with A decrypt-only opens A's wraps and
	// seals under B.
	if labelB != "" {
		rot := cfg
		rot.KeyLabel, rot.DecryptLabels = labelB, []string{cfg.KeyLabel}
		pb, err := OpenInProcess(rot)
		if err != nil {
			t.Fatalf("open with %s current: %v", labelB, err)
		}
		if got, err := pb.Unwrap(ctx, w1, encCtx); err != nil || !bytes.Equal(got, dek) {
			t.Fatalf("decrypt-only label: %v", err)
		}
		wb, err := pb.Wrap(ctx, dek, encCtx)
		if err != nil || secrets.WrappedKeyVersion(wb) != "p11:"+labelB {
			t.Fatalf("wrap under %s = %q %v", labelB, secrets.WrappedKeyVersion(wb), err)
		}
		pb.Close()
	}

	// The helper process with the session pool full: many concurrent calls,
	// every one answered, and the vendor library mapped only in the helper.
	if err := os.Setenv("PKCS11_HELPER_REAL", "1"); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "p11live")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	h, err := StartHelper(HelperOptions{Socket: filepath.Join(dir, "h.sock"), Token: cfg})
	if err != nil {
		t.Fatalf("StartHelper: %v", err)
	}
	defer h.Close()
	const calls = 64
	var wg sync.WaitGroup
	errs := make(chan error, calls)
	start := time.Now()
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := map[string]string{"aerolvm.ref": "live-" + strconv.Itoa(i)}
			w, err := h.Wrap(ctx, dek, c)
			if err == nil {
				var got []byte
				got, err = h.Unwrap(ctx, w, c)
				if err == nil && !bytes.Equal(got, dek) {
					err = errors.New("unwrapped a different key")
				}
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent call through the helper: %v", err)
		}
	}
	t.Logf("%d wrap+unwrap round trips through the helper with %d sessions in %s", calls, cfg.Sessions, time.Since(start).Round(time.Millisecond))
	if runtime.GOOS == "linux" {
		h.mu.Lock()
		pid := h.proc.(cmdProc).cmd.Process.Pid
		h.mu.Unlock()
		lib := filepath.Base(module)
		self, _ := os.ReadFile("/proc/self/maps")
		helper, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
		if strings.Contains(string(self), lib) || !strings.Contains(string(helper), lib) {
			t.Fatalf("%s must be mapped in the helper (pid %d) and not in the parent", lib, pid)
		}
	}
}
