//go:build cgo

package pkcs11

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	p11 "github.com/miekg/pkcs11"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// The real miekg adapter against SoftHSM2. Skips unless the SoftHSM2 module
// and softhsm2-util are installed (CI installs them; `make test` stays
// offline either way: SoftHSM2 is a local library).
func softHSMModule(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("SB_TEST_SOFTHSM_MODULE"),
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so"}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not installed")
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("SoftHSM2 module not installed")
	return ""
}

// newSoftToken initializes a fresh SoftHSM2 token "tok" (user PIN 1234) in a
// temp dir and creates AES-256 keys under labels.
func newSoftToken(t *testing.T, module string, labels ...string) (pinPath string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.MkdirAll(filepath.Join(dir, "tokens"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)
	if out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "tok", "--pin", "1234", "--so-pin", "5678").CombinedOutput(); err != nil {
		t.Fatalf("init token: %v %s", err, out)
	}
	c := p11.New(module)
	if err := c.Initialize(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Finalize(); c.Destroy() }()
	slots, err := c.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	var slot uint
	for _, s := range slots {
		if ti, err := c.GetTokenInfo(s); err == nil && strings.TrimSpace(ti.Label) == "tok" {
			slot = s
		}
	}
	sh, err := c.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Login(sh, p11.CKU_USER, "1234"); err != nil {
		t.Fatal(err)
	}
	for _, l := range labels {
		if _, err := c.GenerateKey(sh, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}, []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY), p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
			p11.NewAttribute(p11.CKA_VALUE_LEN, 32), p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_PRIVATE, true), p11.NewAttribute(p11.CKA_SENSITIVE, true),
			p11.NewAttribute(p11.CKA_EXTRACTABLE, false), p11.NewAttribute(p11.CKA_ENCRYPT, true),
			p11.NewAttribute(p11.CKA_DECRYPT, true), p11.NewAttribute(p11.CKA_LABEL, l),
		}); err != nil {
			t.Fatalf("generate %s: %v", l, err)
		}
	}
	_ = c.Logout(sh)
	_ = c.CloseSession(sh)
	pinPath = filepath.Join(dir, "pin")
	if err := os.WriteFile(pinPath, []byte("1234\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return pinPath
}

func TestSoftHSM(t *testing.T) {
	module := softHSMModule(t)
	pin := newSoftToken(t, module, "kek-a", "kek-b")
	ctx := context.Background()
	aad := []byte("aerolvm.ref\x00r1\x00")

	old, err := OpenToken(TokenConfig{Module: module, TokenLabel: "tok", PINFile: pin, KeyLabel: "kek-a", Sessions: 2})
	if err != nil {
		t.Fatalf("OpenToken: %v", err)
	}
	info := old.Info()
	// Phase 0: SoftHSM2 is not a hardware slot and uses the caller's IV.
	if info.HardwareSlot || info.IVMode != IVCaller {
		t.Fatalf("Info = %+v", info)
	}
	oldRow, err := old.Wrap(ctx, []byte("data-key-a"), aad)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()

	tok, err := OpenToken(TokenConfig{Module: module, TokenLabel: "tok", PINFile: pin, KeyLabel: "kek-b", DecryptLabels: []string{"kek-a"}, Sessions: 2})
	if err != nil {
		t.Fatalf("OpenToken: %v", err)
	}
	defer tok.Close()
	newRow, err := tok.Wrap(ctx, []byte("data-key-b"), aad)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := decodeWrapped(oldRow)
	b, _ := decodeWrapped(newRow)
	if bytes.Equal(a.IV, b.IV) || isZero(b.IV) {
		t.Fatal("IVs must be fresh and non-zero")
	}
	for row, want := range map[string]string{string(oldRow): "data-key-a", string(newRow): "data-key-b"} {
		if got, err := tok.Unwrap(ctx, []byte(row), aad); err != nil || string(got) != want {
			t.Fatalf("Unwrap = %q %v, want %q", got, err, want)
		}
	}
	// Phase 0: a GCM tag mismatch is CKR_GENERAL_ERROR from C_Decrypt.
	if _, err := tok.Unwrap(ctx, newRow, []byte("other")); !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("wrong AAD = %v, want ErrDecryptFailed", err)
	}
	if err := tok.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	destroy := func(label string) {
		t.Helper()
		if _, err := tok.withSession(ctx, func(sh p11.SessionHandle) ([]byte, error) {
			h, found, err := tok.api.findKey(sh, label)
			if err != nil || !found {
				return nil, fmt.Errorf("find %s: %v %v", label, found, err)
			}
			return nil, tok.api.(*miekgHSM).ctx.DestroyObject(sh, h)
		}); err != nil {
			t.Fatal(err)
		}
	}
	destroy("kek-a")
	if _, err := tok.Unwrap(ctx, oldRow, aad); !errors.Is(err, secrets.ErrKeyVersionRetired) {
		t.Fatalf("decrypt-only key destroyed = %v, want retired", err)
	}
	destroy("kek-b")
	if _, err := tok.Unwrap(ctx, newRow, aad); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("current key destroyed = %v, want revoked", err)
	}
}

// eng D5: the vendor library is mapped in the helper and never in sandboxd.
// The check runs in a child test process, because this test process itself
// loads SoftHSM2 in TestSoftHSM.
func TestVendorLibraryStaysInHelper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/<pid>/maps is Linux-only")
	}
	module := softHSMModule(t)
	if os.Getenv("PKCS11_ISOLATION_CHILD") != "1" {
		pin := newSoftToken(t, module, "kek")
		cmd := exec.Command(os.Args[0], "-test.run=^TestVendorLibraryStaysInHelper$", "-test.count=1")
		// The child's helper (this binary again, via TestMain) serves the
		// real token backend.
		cmd.Env = append(os.Environ(), "PKCS11_ISOLATION_CHILD=1", "PKCS11_ISOLATION_PIN="+pin, "PKCS11_HELPER_REAL=1")
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "PASS") {
			t.Fatalf("isolation child: %v\n%s", err, out)
		}
		return
	}
	h, err := StartHelper(HelperOptions{Socket: shortSocket(t), Token: TokenConfig{
		Module: module, TokenLabel: "tok", PINFile: os.Getenv("PKCS11_ISOLATION_PIN"), KeyLabel: "kek", IVMode: IVAuto, Sessions: 2,
	}})
	if err != nil {
		t.Fatalf("StartHelper: %v", err)
	}
	defer h.Close()
	if _, err := h.Wrap(context.Background(), []byte("dek"), nil); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	pid := h.proc.(cmdProc).cmd.Process.Pid
	h.mu.Unlock()
	lib := filepath.Base(module)
	self, _ := os.ReadFile("/proc/self/maps")
	helper, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
	if strings.Contains(string(self), lib) {
		t.Fatalf("%s is mapped in the parent process", lib)
	}
	if !strings.Contains(string(helper), lib) {
		t.Fatalf("%s is not mapped in the helper (pid %d)", lib, pid)
	}
}
