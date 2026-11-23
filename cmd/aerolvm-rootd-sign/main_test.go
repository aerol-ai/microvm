package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootswap"
)

const testVersion = "v9.9.9"

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
)

// helperBinary is the real aerolvm-rootd, built once as a release builds
// it, with the version linked in. Its packages are built already for this
// test, so only the link is new.
func helperBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds aerolvm-rootd")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build aerolvm-rootd")
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rootd-sign")
		if err != nil {
			buildErr = err
			return
		}
		builtBin = filepath.Join(dir, "aerolvm-rootd")
		out, err := exec.Command(goBin, "build", "-o", builtBin,
			"-ldflags", "-X github.com/aerol-ai/microvm/internal/version.Version="+testVersion,
			helperPath).CombinedOutput()
		if err != nil {
			buildErr = err
			builtBin = string(out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build aerolvm-rootd: %v\n%s", buildErr, builtBin)
	}
	// Each test signs its own copy: the signature files go next to it.
	bin := filepath.Join(t.TempDir(), "aerolvm-rootd")
	b, err := os.ReadFile(builtBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestMain(m *testing.M) {
	code := m.Run()
	if builtBin != "" && buildErr == nil {
		_ = os.RemoveAll(filepath.Dir(builtBin))
	}
	os.Exit(code)
}

func run(args ...string) (code int, stdout, stderr string) {
	var out, errs bytes.Buffer
	code = mainCode(args, &out, &errs)
	return code, out.String(), errs.String()
}

// newKey makes a throwaway key with -genkey: the private key file and the
// public key it printed.
func newKey(t *testing.T) (keyFile, pubFile string) {
	t.Helper()
	dir := t.TempDir()
	keyFile, pubFile = filepath.Join(dir, "release.key"), filepath.Join(dir, "release-keys.pub")
	code, out, errs := run("-genkey", keyFile)
	if code != 0 {
		t.Fatalf("-genkey: %d %s", code, errs)
	}
	if err := os.WriteFile(pubFile, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyFile, pubFile
}

// TestGenKey: the private key is the owner's alone and never written over;
// the public key printed is what the runtime image's key file holds.
func TestGenKey(t *testing.T) {
	keyFile, pubFile := newKey(t)
	fi, err := os.Stat(keyFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v, %v", fi.Mode(), err)
	}
	raw, _ := os.ReadFile(pubFile)
	keys, err := rootswap.ParseKeys(raw)
	if err != nil || len(keys) != 1 {
		t.Fatalf("printed public key: %v %v", keys, err)
	}
	priv, err := readPrivateKey(keyFile)
	if err != nil || !priv.Public().(ed25519.PublicKey).Equal(keys[0]) {
		t.Fatalf("the private key does not match the public one: %v", err)
	}
	before, _ := os.ReadFile(keyFile)
	if code, _, _ := run("-genkey", keyFile); code != 1 {
		t.Fatalf("-genkey over an existing key: exit %d", code)
	}
	if after, _ := os.ReadFile(keyFile); !bytes.Equal(before, after) {
		t.Fatal("-genkey wrote over an existing key")
	}
	if code, _, _ := run("-genkey", filepath.Join(t.TempDir(), "no", "such", "dir", "k")); code != 1 {
		t.Fatal("-genkey into a missing folder succeeded")
	}
}

// TestSignTheRealHelper is the release's flow end to end: sign the built
// helper, check it with the public key, then stage it and let the
// supervisor's own check install it; the copy reports the signed version.
func TestSignTheRealHelper(t *testing.T) {
	bin := helperBinary(t)
	keyFile, pubFile := newKey(t)
	code, out, errs := run("-key", keyFile, "-version", testVersion, bin)
	if code != 0 {
		t.Fatalf("sign: %d %s", code, errs)
	}
	if !strings.Contains(out, "signed "+bin+": "+testVersion) || !strings.Contains(out, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Fatalf("sign printed %q", out)
	}
	if code, out, errs := run("-verify", pubFile, bin); code != 0 || !strings.Contains(out, "ok "+bin) {
		t.Fatalf("verify: %d %s %s", code, out, errs)
	}

	stage, binDir := filepath.Join(t.TempDir(), "stage"), filepath.Join(shortDir(t), "rootd")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{bin: rootswap.BinaryName, bin + ".manifest": rootswap.ManifestName, bin + ".sig": rootswap.SignatureName} {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, to), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(pubFile)
	keys, _ := rootswap.ParseKeys(raw)
	stage, _ = filepath.EvalSymlinks(stage)
	m, err := rootswap.ReadStaged(stage, keys)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != testVersion || m.API != rootdpb.APIVersion {
		t.Fatalf("manifest %+v", m)
	}
	inst, err := rootswap.Install(stage, binDir, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := exec.Command(inst.Path, "--version").Output()
	if err != nil || strings.TrimSpace(string(got)) != "aerolvm-rootd "+testVersion+" (API 1)" {
		t.Fatalf("the installed copy reports %q, %v", got, err)
	}
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestSignRefuses: the tool signs only the helper, only as the version it
// reports, only as a release, and only with an ed25519 key.
func TestSignRefuses(t *testing.T) {
	keyFile, _ := newKey(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(t.TempDir(), "notes")
	_ = os.WriteFile(text, []byte("not a program"), 0o644)
	for _, tc := range []struct {
		name string
		args func(t *testing.T) []string
		want string
	}{
		{"another program", func(*testing.T) []string { return []string{"-key", keyFile, "-version", testVersion, self} }, "not " + helperPath},
		{"not a program", func(*testing.T) []string { return []string{"-key", keyFile, "-version", testVersion, text} }, text},
		{"a version the binary does not report", func(t *testing.T) []string {
			return []string{"-key", keyFile, "-version", "v9.9.8", helperBinary(t)}
		}, "it reports"},
		{"no version", func(t *testing.T) []string { return []string{"-key", keyFile, helperBinary(t)} }, "it reports"},
		{"a missing key", func(t *testing.T) []string {
			return []string{"-key", filepath.Join(t.TempDir(), "none"), "-version", testVersion, self}
		}, "no such file"},
		{"a key file with no key", func(*testing.T) []string { return []string{"-key", text, "-version", testVersion, self} }, "no PRIVATE KEY"},
		{"a key that is not ed25519", func(t *testing.T) []string {
			return []string{"-key", ecKeyFile(t), "-version", testVersion, self}
		}, "want an ed25519 key"},
		{"a private key block that does not parse", func(t *testing.T) []string {
			p := filepath.Join(t.TempDir(), "bad.key")
			_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}), 0o600)
			return []string{"-key", p, "-version", testVersion, self}
		}, "bad.key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := run(tc.args(t)...)
			if code != 1 || !strings.Contains(errs, tc.want) {
				t.Fatalf("exit %d, %q; want %q", code, errs, tc.want)
			}
		})
	}
}

func ecKeyFile(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ec.key")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSignForAnotherPlatform: a binary this machine cannot run is signed
// on the strength of -version, says so, and names its own platform; a dev
// build is still refused.
func TestSignForAnotherPlatform(t *testing.T) {
	bin := helperBinary(t)
	keyFile, pubFile := newKey(t)
	old := host
	host = "plan9/mips"
	t.Cleanup(func() { host = old })
	if code, _, errs := run("-key", keyFile, "-version", "dev", bin); code != 1 || !strings.Contains(errs, rootswap.ReasonNotRelease) {
		t.Fatalf("a dev version: %d %s", code, errs)
	}
	code, out, errs := run("-key", keyFile, "-version", testVersion, bin)
	if code != 0 || !strings.Contains(out, "cannot run here") {
		t.Fatalf("sign: %d %s %s", code, out, errs)
	}
	if code, _, errs := run("-verify", pubFile, bin); code != 0 {
		t.Fatalf("verify: %s", errs)
	}
}

// TestVerifyRefuses: a binary changed after signing, a key the runtime
// image does not hold, and missing or broken files all fail the check.
func TestVerifyRefuses(t *testing.T) {
	bin := helperBinary(t)
	keyFile, pubFile := newKey(t)
	if code, _, errs := run("-key", keyFile, "-version", testVersion, bin); code != 0 {
		t.Fatal(errs)
	}
	_, otherPub := newKey(t)
	text := filepath.Join(t.TempDir(), "notes")
	_ = os.WriteFile(text, []byte("not a program"), 0o644)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) []string
		want  string
	}{
		{"another release key", func(*testing.T) []string { return []string{"-verify", otherPub, bin} }, rootswap.ReasonBadSignature},
		{"a missing keys file", func(t *testing.T) []string { return []string{"-verify", filepath.Join(t.TempDir(), "none"), bin} }, "no such file"},
		{"a broken keys file", func(t *testing.T) []string {
			p := filepath.Join(t.TempDir(), "keys.pem")
			_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), 0o644)
			return []string{"-verify", p, bin}
		}, "want PUBLIC KEY"},
		{"not the helper", func(*testing.T) []string { return []string{"-verify", pubFile, text} }, text},
		{"no manifest", func(t *testing.T) []string {
			c := copyOf(t, bin)
			_ = os.WriteFile(c+".sig", nil, 0o644)
			return []string{"-verify", pubFile, c}
		}, ".manifest"},
		{"no signature", func(t *testing.T) []string {
			c := copyOf(t, bin)
			b, _ := os.ReadFile(bin + ".manifest")
			_ = os.WriteFile(c+".manifest", b, 0o644)
			return []string{"-verify", pubFile, c}
		}, ".sig"},
		{"a binary changed after signing", func(t *testing.T) []string {
			c := copyOf(t, bin)
			for _, ext := range []string{".manifest", ".sig"} {
				b, _ := os.ReadFile(bin + ext)
				_ = os.WriteFile(c+ext, b, 0o644)
			}
			f, err := os.OpenFile(c, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write([]byte{0})
			_ = f.Close()
			return []string{"-verify", pubFile, c}
		}, "the signed manifest says"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := run(tc.setup(t)...)
			if code != 1 || !strings.Contains(errs, tc.want) {
				t.Fatalf("exit %d, %q; want %q", code, errs, tc.want)
			}
		})
	}
}

func copyOf(t *testing.T, bin string) string {
	t.Helper()
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	c := filepath.Join(t.TempDir(), "aerolvm-rootd")
	if err := os.WriteFile(c, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-nope"},
		{"-genkey", "k", "-key", "k"},
		{"-key", "k"},
		{"-verify", "k"},
		{"-genkey", "k", "extra"},
		{"-check-version", "v1.0.0"},
		{"-verify", "k", "-no-exec", "b"},
		{"-check-version", "v1.0.0", "-no-exec", "b"},
		{"-genkey", "k", "-no-exec"},
		{"-check-version", "v1.0.0", "-key", "k", "b"},
	} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// The release checks the helper's version in a step with no key, then
// signs with -no-exec, so no helper binary ever runs while the key is on
// disk or in the environment (M1 PR 10 review).
func TestCheckVersionThenSignWithoutRunning(t *testing.T) {
	bin := helperBinary(t)
	if code, out, errs := run("-check-version", testVersion, bin); code != 0 || !strings.Contains(out, "version ok") {
		t.Fatalf("-check-version: %d %s %s", code, out, errs)
	}
	if code, _, errs := run("-check-version", "v1.2.3", bin); code != 1 || !strings.Contains(errs, "would misname it") {
		t.Fatalf("-check-version with the wrong release: %d %s", code, errs)
	}
	keyFile, pubFile := newKey(t)
	// Without -no-exec the signer runs the binary and refuses the wrong
	// release. With it, nothing runs: the same wrong release is signed,
	// which shows the binary was never started (the earlier check is what
	// holds the version).
	if code, _, errs := run("-key", keyFile, "-version", "v1.2.3", bin); code != 1 || !strings.Contains(errs, "would misname it") {
		t.Fatalf("sign, running the binary: %d %s", code, errs)
	}
	code, out, errs := run("-key", keyFile, "-version", "v1.2.3", "-no-exec", bin)
	if code != 0 || !strings.Contains(out, "not run (-no-exec)") {
		t.Fatalf("sign -no-exec: %d %s %s", code, out, errs)
	}
	if code, _, errs := run("-verify", pubFile, bin); code != 0 {
		t.Fatalf("verify: %d %s", code, errs)
	}
	if code, _, _ := run("-check-version", testVersion, filepath.Join(t.TempDir(), "missing")); code != 1 {
		t.Fatal("-check-version of a missing file passed")
	}
}
