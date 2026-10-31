package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// §3's boot decision, one row per input combination that changes the answer.
func TestDecideCustody(t *testing.T) {
	cases := []struct {
		name string
		in   CustodyInputs
		want CustodyAction
		why  string
	}{
		{"file custody, plaintext present", CustodyInputs{Custody: CustodyFile, PlaintextFileExists: true}, ActionPlaintext, ""},
		{"file custody, first boot", CustodyInputs{Custody: CustodyFile}, ActionPlaintext, ""},
		{"file custody, env key", CustodyInputs{Custody: "", PlaintextEnvSet: true, WrappedFileExists: true}, ActionPlaintext, ""},
		{"file custody, only a wrapped key", CustodyInputs{Custody: CustodyFile, WrappedFileExists: true}, ActionRefuse, "only server key is the wrapped one"},
		{"wrapped, env key left (F1)", CustodyInputs{Custody: CustodyWrapped, PlaintextEnvSet: true, WrappedFileExists: true}, ActionRefuse, "SB_CREDENTIAL_ENCRYPTION_KEY is set"},
		{"wrapped, key file left (F1)", CustodyInputs{Custody: CustodyWrapped, PlaintextFileExists: true, WrappedFileExists: true}, ActionRefuse, "plaintext key file exists"},
		{"wrapped, file present", CustodyInputs{Custody: CustodyWrapped, WrappedFileExists: true, ClusterMode: true, StateDBExists: true}, ActionUnwrap, ""},
		{"wrapped, single node first boot", CustodyInputs{Custody: CustodyWrapped}, ActionGenerateWrapped, ""},
		{"wrapped, single node, db but no key", CustodyInputs{Custody: CustodyWrapped, StateDBExists: true}, ActionRefuse, "restore the wrapped file"},
		{"wrapped, cluster never generates", CustodyInputs{Custody: CustodyWrapped, ClusterMode: true}, ActionRefuse, "copy credential_encryption.key.wrapped from the seed"},
	}
	for _, tc := range cases {
		got, why := DecideCustody(tc.in)
		if got != tc.want || !strings.Contains(why, tc.why) {
			t.Fatalf("%s: %v %q, want %v %q", tc.name, got, why, tc.want, tc.why)
		}
	}
}

func TestWrapServerKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	f, err := WrapServerKey(ctx, fake, key, ProviderAWSKMS, "alias/aerolvm")
	if err != nil {
		t.Fatal(err)
	}
	if f.Format != WrappedKeyFormat || f.Provider != "awskms" || len(f.Check) != 16 {
		t.Fatalf("file = %+v", f)
	}
	got, err := UnwrapServerKey(ctx, fake, f)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap = %v", err)
	}
	// The wrap context binds the purpose: a row DEK unwrap context fails.
	if _, err := fake.Unwrap(ctx, f.Wrapped, map[string]string{"aerolvm.ref": "x"}); err == nil {
		t.Fatal("server-key wrap opened under a row context")
	}
	bad := f
	bad.Check = bytes.Repeat([]byte{1}, 16)
	if _, err := UnwrapServerKey(ctx, fake, bad); !errors.Is(err, ErrServerKeyCheck) {
		t.Fatalf("wrong check = %v", err)
	}
	if _, err := WrapServerKey(ctx, fake, key[:16], "awskms", ""); err == nil {
		t.Fatal("short key wrapped")
	}
	if _, err := WrapServerKey(ctx, nil, key, "awskms", ""); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("no wrapper = %v", err)
	}
	if _, err := UnwrapServerKey(ctx, nil, f); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("no wrapper = %v", err)
	}
	fake.Deny = true
	if _, err := WrapServerKey(ctx, fake, key, "awskms", ""); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("denied wrap = %v", err)
	}
	if _, err := UnwrapServerKey(ctx, fake, f); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("denied unwrap = %v", err)
	}
}

func TestWrappedKeyFileIO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "credential_encryption.key.wrapped")
	f := WrappedKeyFile{Format: 1, Provider: "vault", KeyRef: "transit/k", Wrapped: []byte("vault:v3:abc"), Check: bytes.Repeat([]byte{7}, 16), MigratedFromPlaintext: true}
	if err := WriteWrappedKeyFile(path, f); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v %v", fi.Mode(), err)
	}
	got, err := ReadWrappedKeyFile(path)
	if err != nil || !got.MigratedFromPlaintext || got.KeyVersion() != "vault:v3" || string(got.Wrapped) != "vault:v3:abc" {
		t.Fatalf("read = %+v %v", got, err)
	}
	// The file and its writers' lock sidecar, no temp file.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 || entries[1].Name() != filepath.Base(path)+".lock" {
		t.Fatalf("temp file left behind: %v", entries)
	}
	write := func(body string, mode os.FileMode) string {
		p := filepath.Join(dir, "f"+strings.ReplaceAll(body[:min(4, len(body))], "/", ""))
		_ = os.WriteFile(p, []byte(body), 0o600)
		_ = os.Chmod(p, mode)
		return p
	}
	for name, p := range map[string]string{
		"not json":     write("nope", 0o600),
		"wrong format": write(`{"format":2,"wrapped":"YQ==","check":"AAAAAAAAAAAAAAAAAAAAAA=="}`, 0o600),
		"no check":     write(`{"format":1,"wrapped":"YQ=="}`, 0o600),
		"group read":   write(`{"format":1 }`, 0o640),
		"missing":      filepath.Join(dir, "none"),
	} {
		if _, err := ReadWrappedKeyFile(p); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := WriteWrappedKeyFile("/dev/null/x/y", f); err == nil {
		t.Fatal("unwritable path accepted")
	}
	for wrapped, want := range map[string]string{
		"vault:v12:xyz": "vault:v12",
		"p11:1:\x05kek-b" + strings.Repeat("x", 40): "p11:kek-b",
		"p11:1:":         "",
		"vault:":         "",
		"\x01opaque-kms": "",
	} {
		if got := (WrappedKeyFile{Wrapped: []byte(wrapped)}).KeyVersion(); got != want {
			t.Fatalf("KeyVersion(%q) = %q, want %q", wrapped, got, want)
		}
	}
}

func TestOpenServerKey(t *testing.T) {
	ctx := context.Background()
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := CustodyInputs{Custody: CustodyWrapped, WrappedPath: filepath.Join(dir, "key.wrapped"), PlaintextPath: filepath.Join(dir, "key")}

	// Single node, first boot: generate, write only the wrapped file.
	c1, err := OpenServerKey(ctx, in, "", fake, ProviderAWSKMS, "alias/k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in.PlaintextPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a plaintext key file was written under wrapped custody")
	}
	sealed, err := c1.Encrypt([]byte("toolbox token"))
	if err != nil {
		t.Fatal(err)
	}
	// Next boot: unwrap the same key.
	in.WrappedFileExists = true
	c2, err := OpenServerKey(ctx, in, "", fake, ProviderAWSKMS, "alias/k")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c2.Decrypt(sealed); err != nil || string(got) != "toolbox token" {
		t.Fatalf("second boot opened %q %v", got, err)
	}
	// The key store is down: boot fails closed (systemd restarts it).
	fake.Unavailable = true
	if _, err := OpenServerKey(ctx, in, "", fake, ProviderAWSKMS, ""); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("key store down = %v", err)
	}
	fake.Unavailable = false
	// F1.
	in.PlaintextEnvSet = true
	if _, err := OpenServerKey(ctx, in, "AAAA", fake, ProviderAWSKMS, ""); err == nil || !strings.Contains(err.Error(), "SB_CREDENTIAL_ENCRYPTION_KEY is set") {
		t.Fatalf("plaintext env under wrapped custody = %v", err)
	}
	// File custody keeps today's behavior.
	fileIn := CustodyInputs{Custody: CustodyFile, PlaintextPath: filepath.Join(dir, "plain.key")}
	if _, err := OpenServerKey(ctx, fileIn, "", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	// A corrupt wrapped file.
	bad := CustodyInputs{Custody: CustodyWrapped, WrappedFileExists: true, WrappedPath: filepath.Join(dir, "bad")}
	_ = os.WriteFile(bad.WrappedPath, []byte("{}"), 0o600)
	if _, err := OpenServerKey(ctx, bad, "", fake, "", ""); err == nil {
		t.Fatal("corrupt wrapped file accepted")
	}
	// Generation that cannot be written or verified.
	gen := CustodyInputs{Custody: CustodyWrapped, WrappedPath: "/dev/null/x"}
	if _, err := OpenServerKey(ctx, gen, "", fake, "", ""); err == nil {
		t.Fatal("unwritable wrapped path accepted")
	}
	if _, err := OpenServerKey(ctx, CustodyInputs{Custody: CustodyWrapped, WrappedPath: filepath.Join(dir, "n")}, "", nil, "", ""); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("generate with no key store = %v", err)
	}
	flaky := &onceWrapper{inner: fake}
	if _, err := OpenServerKey(ctx, CustodyInputs{Custody: CustodyWrapped, WrappedPath: filepath.Join(dir, "v")}, "", flaky, "", ""); err == nil || !strings.Contains(err.Error(), "verify new wrapped server key") {
		t.Fatalf("read-back failure = %v", err)
	}
}

// onceWrapper wraps through inner but refuses every unwrap.
type onceWrapper struct{ inner DataKeyWrapper }

func (o *onceWrapper) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	return o.inner.Wrap(ctx, dek, encCtx)
}

func (o *onceWrapper) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, ErrProviderUnavailable
}

func TestLoadPlaintextKey(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{3}, 32)
	b64 := base64.StdEncoding.EncodeToString(key)
	if got, ok, err := LoadPlaintextKey(b64, ""); !ok || err != nil || !bytes.Equal(got, key) {
		t.Fatalf("env = %v %v", ok, err)
	}
	if _, ok, err := LoadPlaintextKey("", filepath.Join(dir, "none")); ok || err != nil {
		t.Fatalf("missing file = %v %v, want not found and no error", ok, err)
	}
	if _, ok, err := LoadPlaintextKey("", ""); ok || err != nil {
		t.Fatal("no source")
	}
	p := filepath.Join(dir, "k")
	_ = os.WriteFile(p, []byte(b64), 0o600)
	if got, ok, err := LoadPlaintextKey("", p); !ok || err != nil || !bytes.Equal(got, key) {
		t.Fatalf("file = %v %v", ok, err)
	}
	if _, ok, err := LoadPlaintextKey("not base64!", ""); ok || err == nil {
		t.Fatal("bad env accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "none")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("LoadPlaintextKey generated a key")
	}
}
