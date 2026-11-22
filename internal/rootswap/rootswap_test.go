package rootswap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// throwaway is a key made for one test: what a release key is to the
// supervisor, and what no test ever ships.
func throwaway(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// manifestFor is a manifest for body on this machine.
func manifestFor(t testing.TB, body []byte, version string) Manifest {
	t.Helper()
	m, err := NewManifest(bytes.NewReader(body), version, 1, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// signRaw signs any bytes, as a release key would sign a manifest the
// signer itself refuses to write: the verifier must refuse it all the same.
func signRaw(priv ed25519.PrivateKey, manifest []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)))
}

func TestSignVerify(t *testing.T) {
	pub, priv := throwaway(t)
	m := manifestFor(t, []byte("helper bytes"), "v0.7.8")
	manifest, sig, err := Sign(priv, m)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := throwaway(t)
	got, err := Verify([]ed25519.PublicKey{other, pub}, manifest, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got != m {
		t.Fatalf("Verify = %+v, want %+v", got, m)
	}
	if _, _, err := Sign(priv[:10], m); err == nil {
		t.Fatal("Sign took a short key")
	}
	bad := m
	bad.Version = "dev"
	if _, _, err := Sign(priv, bad); ReasonOf(err) != ReasonNotRelease {
		t.Fatalf("Sign of a dev build = %v, want %s", err, ReasonNotRelease)
	}
}

// TestVerifyRefuses: unsigned, wrongly signed and malformed manifests, and
// ones for another machine, are refused, each with its own reason.
func TestVerifyRefuses(t *testing.T) {
	pub, priv := throwaway(t)
	_, otherPriv := throwaway(t)
	good := manifestFor(t, []byte("helper"), "v1.2.3")
	signedJSON := func(v any) ([]byte, []byte) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b, signRaw(priv, b)
	}
	with := func(f func(m *Manifest)) ([]byte, []byte) {
		m := good
		f(&m)
		return signedJSON(m)
	}
	goodBytes, goodSig := signedJSON(good)
	for _, tc := range []struct {
		name     string
		keys     []ed25519.PublicKey
		manifest []byte
		sig      []byte
		reason   string
	}{
		{"no release key built in", nil, goodBytes, goodSig, ReasonNoKey},
		{"unsigned", []ed25519.PublicKey{pub}, goodBytes, nil, ReasonUnsigned},
		{"blank signature", []ed25519.PublicKey{pub}, goodBytes, []byte(" \n"), ReasonUnsigned},
		{"not base64", []ed25519.PublicKey{pub}, goodBytes, []byte("!!!"), ReasonBadSignature},
		{"a short signature", []ed25519.PublicKey{pub}, goodBytes, []byte(base64.StdEncoding.EncodeToString([]byte("short"))), ReasonBadSignature},
		{"signed by another key", []ed25519.PublicKey{pub}, goodBytes, signRaw(otherPriv, goodBytes), ReasonBadSignature},
		{"a manifest changed after signing", []ed25519.PublicKey{pub}, bytes.Replace(goodBytes, []byte("v1.2.3"), []byte("v9.2.3"), 1), goodSig, ReasonBadSignature},
		{"signed but not JSON", []ed25519.PublicKey{pub}, []byte("not json"), signRaw(priv, []byte("not json")), ReasonBadManifest},
		{"an unknown field", []ed25519.PublicKey{pub}, nil, nil, ReasonBadManifest},
		{"data after it", []ed25519.PublicKey{pub}, append(bytes.Clone(goodBytes), []byte(" {}")...), signRaw(priv, append(bytes.Clone(goodBytes), []byte(" {}")...)), ReasonBadManifest},
		{"another kind", []ed25519.PublicKey{pub}, nil, nil, ReasonBadManifest},
		{"a bad hash", []ed25519.PublicKey{pub}, nil, nil, ReasonBadManifest},
		{"no size", []ed25519.PublicKey{pub}, nil, nil, ReasonBadManifest},
		{"no platform", []ed25519.PublicKey{pub}, nil, nil, ReasonBadManifest},
		{"a dev build", []ed25519.PublicKey{pub}, nil, nil, ReasonNotRelease},
		{"API 0", []ed25519.PublicKey{pub}, nil, nil, ReasonNotRelease},
		{"another architecture", []ed25519.PublicKey{pub}, nil, nil, ReasonPlatform},
		{"another OS", []ed25519.PublicKey{pub}, nil, nil, ReasonPlatform},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest, sig := tc.manifest, tc.sig
			switch tc.name {
			case "an unknown field":
				manifest, sig = signedJSON(map[string]any{"kind": Kind, "version": "v1.2.3", "api": 1, "os": runtime.GOOS,
					"arch": runtime.GOARCH, "size": good.Size, "sha256": good.SHA256, "run_as": "root"})
			case "another kind":
				manifest, sig = with(func(m *Manifest) { m.Kind = "aerolvm-upgrade" })
			case "a bad hash":
				manifest, sig = with(func(m *Manifest) { m.SHA256 = strings.ToUpper(m.SHA256) })
			case "no size":
				manifest, sig = with(func(m *Manifest) { m.Size = 0 })
			case "no platform":
				manifest, sig = with(func(m *Manifest) { m.OS = "" })
			case "a dev build":
				manifest, sig = with(func(m *Manifest) { m.Version = "v0.7.6-12-gabcdef-dirty" })
			case "API 0":
				manifest, sig = with(func(m *Manifest) { m.API = 0 })
			case "another architecture":
				manifest, sig = with(func(m *Manifest) { m.Arch = map[bool]string{true: "arm64", false: "amd64"}[runtime.GOARCH == "amd64"] })
			case "another OS":
				manifest, sig = with(func(m *Manifest) { m.OS = "windows" })
			}
			_, err := Verify(tc.keys, manifest, sig)
			if ReasonOf(err) != tc.reason {
				t.Fatalf("Verify = %v, want reason %s", err, tc.reason)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("error %q does not name its reason", err)
			}
		})
	}
}

func TestNewManifest(t *testing.T) {
	m, err := NewManifest(strings.NewReader("abc"), "v1.0.0", 2, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if m.Size != 3 || m.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || m.Kind != Kind || m.API != 2 {
		t.Fatalf("%+v", m)
	}
	if _, err := NewManifest(strings.NewReader(""), "v1.0.0", 1, "linux", "amd64"); ReasonOf(err) != ReasonBadManifest {
		t.Fatalf("an empty binary = %v", err)
	}
	if _, err := NewManifest(errReader{}, "v1.0.0", 1, "linux", "amd64"); err == nil || ReasonOf(err) != "" {
		t.Fatalf("a read error = %v, want it as it is", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk gone") }

// TestCheckNewer: older versions and lower API levels are refused; the same
// version and anything newer pass, across release lines by semver.
func TestCheckNewer(t *testing.T) {
	run := Manifest{Version: "v0.7.8", API: 2}
	for _, tc := range []struct {
		version string
		api     uint32
		ok      bool
	}{
		{"v0.7.8", 2, true},
		{"v0.7.9", 2, true},
		{"v0.8.0", 3, true},
		{"v1.0.0", 2, true},
		{"v0.7.7", 2, false},
		{"v0.6.15", 2, false}, // a patch on an older line
		{"v0.7.8-rc.1", 2, false},
		{"v0.7.9", 1, false}, // newer, but takes a call away
	} {
		err := CheckNewer(Manifest{Version: tc.version, API: tc.api}, &run)
		if (err == nil) != tc.ok || (err != nil && ReasonOf(err) != ReasonOlder) {
			t.Errorf("%s API %d over %s: %v, want ok %v", tc.version, tc.api, run.Version, err, tc.ok)
		}
	}
	if err := CheckNewer(Manifest{Version: "v0.0.1", API: 1}, nil); err != nil {
		t.Fatalf("with nothing running: %v", err)
	}
}

// TestCompareVersions is semver's own precedence list, plus numbers past
// one digit and versions that do not parse.
func TestCompareVersions(t *testing.T) {
	order := []string{
		"v0.9.9", "v0.10.0", "v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta",
		"v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "v1.0.1", "v1.1.0", "v2.0.0",
	}
	for i, a := range order {
		for j, b := range order {
			want := cmpUint(uint64(i), uint64(j))
			if got := compareVersions(a, b); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"dev", "v0.0.1", -1},
		{"v0.0.1", "dev", 1},
		{"dev", "other", 0},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	for _, bad := range []string{"0.7.8", "v0.7", "v01.0.0", "v1.0.0-", "v1.0.0-rc..1", "v1.0.0+build", "v99999999999999999999.0.0", "v1.0.0-r_c"} {
		if _, err := parseVersion(bad); err == nil {
			t.Errorf("parseVersion(%q) took it", bad)
		}
	}
}

// TestParseKeys: the PUBLIC KEY form openssl and x509 write, one key or
// several, with text around them; anything else fails loudly.
func TestParseKeys(t *testing.T) {
	pub1, _ := throwaway(t)
	pub2, _ := throwaway(t)
	der, err := x509.MarshalPKIXPublicKey(pub1)
	if err != nil {
		t.Fatal(err)
	}
	viaX509 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if !bytes.Equal(viaX509, MarshalPublicKey(pub1)) {
		t.Fatalf("MarshalPublicKey differs from x509's:\n%s\n%s", viaX509, MarshalPublicKey(pub1))
	}
	file := append([]byte("release key, 2026\n"), viaX509...)
	file = append(file, []byte("next key:\n")...)
	file = append(file, MarshalPublicKey(pub2)...)
	keys, err := ParseKeys(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !keys[0].Equal(pub1) || !keys[1].Equal(pub2) {
		t.Fatalf("keys = %v", keys)
	}
	if keys, err := ParseKeys([]byte("no keys here")); err != nil || len(keys) != 0 {
		t.Fatalf("no blocks = %v, %v", keys, err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"a private key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"an RSA key":    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}),
		"a short key":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der[:20]}),
	} {
		if _, err := ParseKeys(bad); err == nil {
			t.Errorf("%s: ParseKeys took it", name)
		}
	}
}

// TestReleaseKeys: the built-in key file always parses, so a bad key
// committed there fails here and not on a node. It also holds at least one
// key: with none, the supervisor refuses every staged helper (ReasonNoKey),
// so an edit that drops the last key would quietly turn the signed swap off.
func TestReleaseKeys(t *testing.T) {
	keys, err := ReleaseKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("release-keys.pub lists no key: every staged helper would be refused")
	}
	t.Logf("%d release key(s) built in", len(keys))
}

func TestRefusalError(t *testing.T) {
	err := refuse(ReasonHash, "sha %s", "x")
	if err.Error() != "staged root helper refused (hash_mismatch): sha x" {
		t.Fatalf("%q", err)
	}
	if ReasonOf(errors.New("plain")) != "" {
		t.Fatal("a plain error has a reason")
	}
}
