package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// keyEnv points the tool at a temp node with AWS KMS settings and a fake
// key store, through an env file like the unit's.
func keyEnv(t *testing.T, extra map[string]string) (dir string, envFile string, fake *secrets.FakeKMS) {
	t.Helper()
	dir = t.TempDir()
	lines := []string{
		"# sandboxd.env",
		"SB_PAT_TOKEN=operator-pat",
		"SB_DB_PATH=" + filepath.Join(dir, "state.db"),
		"SB_SECRET_PROVIDER=awskms",
		`SB_SECRET_AWS_KMS_KEY_ID="alias/aerolvm"`,
		"SB_CREDENTIAL_ENCRYPTION_KEY_PATH=" + filepath.Join(dir, "credential_encryption.key"),
		"SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH=" + filepath.Join(dir, "credential_encryption.key.wrapped"),
		"; a comment",
		"not a pair",
	}
	for k, v := range extra {
		lines = append(lines, k+"="+v)
	}
	envFile = filepath.Join(dir, "sandboxd.env")
	if err := os.WriteFile(envFile, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	// The tool sets these from the file; t.Setenv restores them afterwards.
	for _, k := range []string{"SB_PAT_TOKEN", "SB_DB_PATH", "SB_SECRET_PROVIDER", "SB_SECRET_AWS_KMS_KEY_ID", "SB_CREDENTIAL_ENCRYPTION_KEY_PATH",
		"SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH", "SB_CREDENTIAL_KEY_CUSTODY", "SB_CREDENTIAL_ENCRYPTION_KEY", "SB_ENABLE_CLUSTER"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	for k := range extra {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	var err error
	fake, err = secrets.NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	orig := openKeyStore
	openKeyStore = func(context.Context, config.Config) (secrets.DataKeyWrapper, func(), error) {
		return fake, func() {}, nil
	}
	t.Cleanup(func() { openKeyStore = orig })
	return dir, envFile, fake
}

func runKey(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runKeyCLI(args, &out)
	return out.String(), err
}

func TestKeyGenerateVerifyStatus(t *testing.T) {
	dir, env, _ := keyEnv(t, map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "wrapped"})
	wrapped := filepath.Join(dir, "credential_encryption.key.wrapped")
	out, err := runKey(t, "wrap", "--generate", "--env-file", env)
	if err != nil || !strings.Contains(out, "no plaintext copy was written") {
		t.Fatalf("generate = %q %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credential_encryption.key")); !os.IsNotExist(err) {
		t.Fatal("generate wrote a plaintext key")
	}
	if out, err := runKey(t, "verify", "--env-file", env); err != nil || !strings.Contains(out, "unwraps through awskms") {
		t.Fatalf("verify = %q %v", out, err)
	}
	out, err = runKey(t, "status", "--check", "--env-file", env)
	if err != nil || !strings.Contains(out, "server key                customer key store (wrapped)") || !strings.Contains(out, "check: every server key unwraps and matches") || !strings.Contains(out, "server keys: 0=current") ||
		!strings.Contains(out, "key: alias/aerolvm") || strings.Contains(out, "migrated from plaintext") {
		t.Fatalf("status = %q %v", out, err)
	}
	if _, err := runKey(t, "wrap", "--generate", "--env-file", env); err == nil || !strings.Contains(err.Error(), "a wrapped key exists") {
		t.Fatalf("second generate = %v", err)
	}
	if out, err := runKey(t, "rewrap", "--env-file", env); err != nil || !strings.Contains(out, "rewrapped: "+wrapped) {
		t.Fatalf("rewrap = %q %v", out, err)
	}
	if out, err := runKey(t, "ack-migration", "--env-file", env); err != nil || !strings.Contains(out, "nothing to acknowledge") {
		t.Fatalf("ack on a generated key = %q %v", out, err)
	}
}

// Migration: wrap the existing plaintext key, idempotently, then the notice
// stays until ack-migration (eng D24).
func TestKeyWrapMigration(t *testing.T) {
	dir, env, fake := keyEnv(t, nil)
	plain := filepath.Join(dir, "credential_encryption.key")
	key := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(plain, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runKey(t, "wrap", "--generate", "--env-file", env); err == nil || !strings.Contains(err.Error(), "a plaintext key exists") {
		t.Fatalf("generate over a plaintext key = %v", err)
	}
	out, err := runKey(t, "wrap", "--env-file", env)
	if err != nil || !strings.Contains(out, "delete the plaintext key file "+plain) {
		t.Fatalf("wrap = %q %v", out, err)
	}
	if _, err := os.Stat(plain); err != nil {
		t.Fatal("wrap deleted the plaintext file itself")
	}
	f, err := secrets.ReadWrappedKeyFile(filepath.Join(dir, "credential_encryption.key.wrapped"))
	if err != nil || !f.MigratedFromPlaintext {
		t.Fatalf("wrapped file = %+v %v", f, err)
	}
	if got, err := secrets.UnwrapServerKey(context.Background(), fake, f); err != nil || !bytes.Equal(got, key) {
		t.Fatal("wrapped file does not hold the plaintext key")
	}
	if out, err := runKey(t, "wrap", "--env-file", env); err != nil || !strings.Contains(out, "already wrapped") {
		t.Fatalf("wrap again = %q %v", out, err)
	}
	out, _ = runKey(t, "status", "--env-file", env)
	if !strings.Contains(out, "migrated from plaintext") || !strings.Contains(out, "plaintext key file still exists") {
		t.Fatalf("status after migration = %q", out)
	}
	if out, err := runKey(t, "ack-migration", "--env-file", env); err != nil || !strings.Contains(out, "acknowledged") {
		t.Fatalf("ack = %q %v", out, err)
	}
	if out, _ := runKey(t, "status", "--env-file", env); strings.Contains(out, "migrated from plaintext") {
		t.Fatal("notice survived ack-migration")
	}
	// A different plaintext key must not replace the wrapped one.
	if err := os.WriteFile(plain, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runKey(t, "wrap", "--env-file", env); err == nil || !strings.Contains(err.Error(), "different server key") {
		t.Fatalf("wrap of another key = %v", err)
	}
	// Rollback (CEO-R1).
	if _, err := runKey(t, "unwrap", "--env-file", env); err == nil || !strings.Contains(err.Error(), "--i-understand-plaintext") {
		t.Fatalf("unwrap without the acknowledgement = %v", err)
	}
	if _, err := runKey(t, "unwrap", "--to-file", "--i-understand-plaintext", "--env-file", env); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("unwrap over a key file = %v", err)
	}
	_ = os.Remove(plain)
	out, err = runKey(t, "unwrap", "--to-file", "--i-understand-plaintext", "--env-file", env)
	if err != nil || !strings.Contains(out, "no longer holds") {
		t.Fatalf("unwrap = %q %v", out, err)
	}
	if got, ok, err := secrets.LoadPlaintextKey("", plain); !ok || err != nil || !bytes.Equal(got, key) {
		t.Fatal("unwrap wrote a different key")
	}
	if fi, _ := os.Stat(plain); fi.Mode().Perm() != 0o600 {
		t.Fatalf("plaintext mode = %v", fi.Mode())
	}
}

// S5: in cluster mode --generate runs only on a fresh seed.
func TestKeyGenerateClusterSeed(t *testing.T) {
	dir, env, _ := keyEnv(t, map[string]string{
		"SB_ENABLE_CLUSTER":    "true",
		"SB_CLUSTER_BOOTSTRAP": "true",
		"SB_GOSSIP_SECRET_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"SB_CLUSTER_TLS_DIR":   "/tmp/tls",
	})
	if _, err := runKey(t, "wrap", "--generate", "--env-file", env); err == nil || !strings.Contains(err.Error(), "without --seed") {
		t.Fatalf("joiner = %v", err)
	}
	raft := filepath.Join(dir, "raft")
	if err := os.MkdirAll(raft, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(raft, "raft.db"), nil, 0o600)
	if _, err := runKey(t, "wrap", "--generate", "--seed", "--env-file", env); err == nil || !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("seed with raft state = %v", err)
	}
	_ = os.RemoveAll(raft)
	_ = os.WriteFile(filepath.Join(dir, "state.db"), nil, 0o600)
	if _, err := runKey(t, "wrap", "--generate", "--seed", "--env-file", env); err == nil || !strings.Contains(err.Error(), "already ran") {
		t.Fatalf("seed with a database = %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "state.db"))
	if out, err := runKey(t, "wrap", "--generate", "--seed", "--env-file", env); err != nil || !strings.Contains(out, "generated") {
		t.Fatalf("fresh seed = %q %v", out, err)
	}
}

func TestKeyCLIErrors(t *testing.T) {
	_, env, fake := keyEnv(t, nil)
	if out, err := runKey(t); err == nil || !strings.Contains(out, "usage") {
		t.Fatalf("no command = %v", err)
	}
	if out, err := runKey(t, "help"); err != nil || !strings.Contains(out, "usage") {
		t.Fatalf("help = %v", err)
	}
	if _, err := runKey(t, "bogus", "--env-file", env); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown = %v", err)
	}
	if _, err := runKey(t, "status", "--bogus"); err == nil {
		t.Fatal("bad flag accepted")
	}
	if out, _ := runKey(t, "status", "--env-file", env, "--env-file", "/nonexistent/env"); !strings.Contains(out, "warning: env file /nonexistent/env") {
		t.Fatalf("missing env file not reported: %q", out)
	}
	if _, err := runKey(t, "wrap", "--env-file", env); err == nil || !strings.Contains(err.Error(), "no plaintext server key") {
		t.Fatalf("wrap with nothing to wrap = %v", err)
	}
	for _, cmd := range []string{"verify", "rewrap", "ack-migration"} {
		if _, err := runKey(t, cmd, "--env-file", env); err == nil {
			t.Fatalf("%s with no wrapped file succeeded", cmd)
		}
	}
	if _, err := runKey(t, "unwrap", "--to-file", "--i-understand-plaintext", "--env-file", env); err == nil {
		t.Fatal("unwrap with no wrapped file succeeded")
	}
	t.Setenv("SB_CREDENTIAL_KEY_CUSTODY", "wrapped")
	if _, err := runKey(t, "status", "--env-file", env); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("status, wrapped custody, no file = %v", err)
	}
	t.Setenv("SB_CREDENTIAL_KEY_CUSTODY", "")
	if _, err := runKey(t, "wrap", "--generate", "--env-file", env); err != nil {
		t.Fatal(err)
	}
	fake.Deny = true
	if _, err := runKey(t, "verify", "--env-file", env); err == nil {
		t.Fatal("verify with a denying key store succeeded")
	}
	if _, err := runKey(t, "status", "--check", "--env-file", env); err == nil {
		t.Fatal("status --check with a denying key store succeeded")
	}
	t.Setenv("SB_SECRET_PROVIDER_MAX_INFLIGHT", "0")
	if _, err := runKey(t, "status", "--env-file", env); err == nil || !strings.Contains(err.Error(), "load config") {
		t.Fatalf("bad config = %v", err)
	}
}

func TestLoadEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "env")
	_ = os.WriteFile(p, []byte("A_KC_TEST='quoted value'\nB_KC_TEST=\"x\"\nC_KC_TEST=keep\n=nokey\n"), 0o600)
	t.Setenv("C_KC_TEST", "from-process")
	t.Setenv("A_KC_TEST", "")
	_ = os.Unsetenv("A_KC_TEST")
	t.Setenv("B_KC_TEST", "")
	_ = os.Unsetenv("B_KC_TEST")
	if err := loadEnvFile(p); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("A_KC_TEST") != "quoted value" || os.Getenv("B_KC_TEST") != "x" || os.Getenv("C_KC_TEST") != "from-process" {
		t.Fatalf("env = %q %q %q", os.Getenv("A_KC_TEST"), os.Getenv("B_KC_TEST"), os.Getenv("C_KC_TEST"))
	}
}

// The default opener, on the paths that need no key store.
func TestDefaultOpenKeyStore(t *testing.T) {
	ctx := context.Background()
	if _, _, err := openKeyStore(ctx, config.Config{SecretProvider: "local"}); err == nil {
		t.Fatal("local opened a key store")
	}
	if _, _, err := openKeyStore(ctx, config.Config{SecretProvider: "pkcs11", SecretPKCS11Module: "/nonexistent.so", SecretPKCS11KeyLabel: "k"}); err == nil {
		t.Fatal("pkcs11 with a missing module opened")
	}
	w, closeFn, err := openKeyStore(ctx, config.Config{SecretProvider: "vault", SecretVaultAddr: "http://127.0.0.1:1", SecretVaultKeyName: "k", SecretProviderMaxInFlight: 2})
	if err != nil || w == nil {
		t.Fatalf("vault (unreachable, policy checked later) = %v", err)
	}
	closeFn()
	if _, _, err := openKeyStore(ctx, config.Config{SecretProvider: "vault"}); err == nil {
		t.Fatal("vault without settings opened")
	}
}

func TestMainKeySubcommand(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	origExit := osExit
	code := -1
	osExit = func(c int) { code = c }
	t.Cleanup(func() { osExit = origExit })
	os.Args = []string{"sandboxd", "key", "help"}
	main()
	if code != -1 {
		t.Fatalf("key help exited %d", code)
	}
	os.Args = []string{"sandboxd", "key"}
	main()
	if code != 1 {
		t.Fatalf("key with no command exited %d", code)
	}
}
