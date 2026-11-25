// Package rootswap is the check the runtime supervisor makes before it
// runs a root helper (plans/security-gaps-m1-m4.md §3.3 "Upgrades", eng
// review D4): the helper ships with each release, the agent stages it, and
// root runs it only when a release key signed it and it is not older than
// the helper running now.
//
// A release signs a small manifest, not the binary: the binary's SHA-256
// and size, its version as aerolvm-rootd reports it (internal/version),
// its API level (rootdpb.APIVersion) and the platform it was built for.
// The signature is a detached ed25519 signature over the manifest's exact
// bytes, base64 in a file of its own. Everything here is the standard
// library and runs offline: the supervisor has no network to ask, and the
// release's keyless cosign signatures on its images need one, so they are
// not this check.
//
// The release public keys are built in (release-keys.pub, embedded), so
// they come with the runtime image and nothing the agent writes can add
// one. A release sets them by committing the public key to that file; see
// the file itself. (Not a .pem: the repo ignores those, as secrets.) With
// no key, every staged helper is refused.
//
// The agent can write the staged folder, so nothing there is trusted until
// it is checked, and the check is never made on the staged file itself
// (outside review O3): Install copies the binary into a folder only root
// can write, hashes the copy, and the supervisor runs that copy. Replacing
// the staged file after the check changes nothing that runs.
package rootswap

import (
	"bytes"
	"crypto/ed25519"
	_ "embed" // the release keys
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// The staged files, by fixed names: the supervisor never takes a name from
// the staged folder.
const (
	BinaryName    = "aerolvm-rootd"
	ManifestName  = BinaryName + ".manifest"
	SignatureName = BinaryName + ".sig"
)

// Kind is the manifest's kind. A release key may sign other things later
// (the VM upgrade's artifacts, §3.3 ApplyUpgrade); the kind keeps one
// signed manifest from passing for another.
const Kind = "aerolvm-rootd"

// Size bounds. The helper is a few tens of MiB; the bound only stops a
// staged file from filling root's folder. The manifest and signature are
// a few hundred bytes.
const (
	MaxBinarySize    = 256 << 20
	maxManifestSize  = 4 << 10
	maxSignatureSize = 1 << 10
)

// Reasons a staged helper is refused: short, stable codes for the
// supervisor's log, like the helper's own refusal reasons.
const (
	ReasonNoKey        = "no_release_key"
	ReasonUnsigned     = "unsigned"
	ReasonBadSignature = "bad_signature"
	ReasonBadManifest  = "bad_manifest"
	ReasonNotRelease   = "not_a_release"
	ReasonPlatform     = "other_platform"
	ReasonOlder        = "older"
	ReasonMissing      = "missing"
	ReasonNotFile      = "not_a_file"
	ReasonTruncated    = "truncated"
	ReasonWrongSize    = "wrong_size"
	ReasonHash         = "hash_mismatch"
)

// Refusal is a staged helper root will not run, and why.
type Refusal struct {
	Reason string
	Detail string
}

func (r *Refusal) Error() string { return "staged root helper refused (" + r.Reason + "): " + r.Detail }

func refuse(reason, format string, args ...any) error {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf is err's refusal reason, or "" when err is no refusal (an I/O
// error in root's own folder, say).
func ReasonOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// Manifest is what a release signs for one helper binary.
type Manifest struct {
	Kind string `json:"kind"`
	// Version is the release, as the binary reports it: vMAJOR.MINOR.PATCH
	// with an optional -prerelease, the form release.yml accepts as a tag.
	Version string `json:"version"`
	// API is the binary's rootdpb.APIVersion.
	API  uint32 `json:"api"`
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Size and SHA256 (lowercase hex) are the binary's.
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var (
	// releaseVersion is release.yml's tag rule, made strict where semver
	// is (no leading zeros, no empty prerelease part), so two versions
	// always compare one way.
	releaseVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$`)
	platformWord   = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	hexDigest      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// check is every rule a manifest must meet on any machine: the signer
// refuses to sign what the verifier would refuse anywhere.
func (m Manifest) check() error {
	switch {
	case m.Kind != Kind:
		return refuse(ReasonBadManifest, "kind %q, want %q", m.Kind, Kind)
	case !hexDigest.MatchString(m.SHA256):
		return refuse(ReasonBadManifest, "sha256 %q is not a lowercase SHA-256", m.SHA256)
	case m.Size <= 0 || m.Size > MaxBinarySize:
		return refuse(ReasonBadManifest, "size %d is not between 1 and %d", m.Size, MaxBinarySize)
	case !platformWord.MatchString(m.OS) || !platformWord.MatchString(m.Arch):
		return refuse(ReasonBadManifest, "platform %q/%q is not a GOOS/GOARCH pair", m.OS, m.Arch)
	case m.API == 0:
		return refuse(ReasonNotRelease, "API level 0: no helper speaks it")
	}
	if _, err := parseVersion(m.Version); err != nil {
		return refuse(ReasonNotRelease, "%v", err)
	}
	return nil
}

// NewManifest describes the binary read from r: its size and SHA-256, and
// what the caller says of it.
func NewManifest(r io.Reader, version string, api uint32, goos, goarch string) (Manifest, error) {
	h := newHash()
	n, err := io.Copy(h, io.LimitReader(r, MaxBinarySize+1))
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Kind: Kind, Version: version, API: api, OS: goos, Arch: goarch, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
	return m, m.check()
}

// Sign signs m and returns the manifest's bytes and the signature file's.
func Sign(priv ed25519.PrivateKey, m Manifest) (manifest, signature []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("not an ed25519 private key")
	}
	if err := m.check(); err != nil {
		return nil, nil, err
	}
	manifest, err = json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	manifest = append(manifest, '\n')
	sig := ed25519.Sign(priv, manifest)
	return manifest, []byte(base64.StdEncoding.EncodeToString(sig) + "\n"), nil
}

// Verify checks a staged manifest and its signature against keys and
// returns the manifest: signed by one of keys, well formed, a release, and
// for this machine's platform. It says nothing of the binary yet; Install
// checks that, on root's own copy.
func Verify(keys []ed25519.PublicKey, manifest, signature []byte) (Manifest, error) {
	return VerifyFor(keys, manifest, signature, runtime.GOOS, runtime.GOARCH)
}

// VerifyFor is Verify for a binary built for goos/goarch: the release's own
// check of what it signed for every platform, on one machine.
func VerifyFor(keys []ed25519.PublicKey, manifest, signature []byte, goos, goarch string) (Manifest, error) {
	if len(keys) == 0 {
		return Manifest{}, refuse(ReasonNoKey, "this runtime image has no release key, so no helper can be checked")
	}
	if len(bytes.TrimSpace(signature)) == 0 {
		return Manifest{}, refuse(ReasonUnsigned, "no signature is staged with the helper")
	}
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(signature)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Manifest{}, refuse(ReasonBadSignature, "the signature file does not hold one base64 ed25519 signature")
	}
	signed := false
	for _, k := range keys {
		if ed25519.Verify(k, manifest, sig) {
			signed = true
			break
		}
	}
	if !signed {
		return Manifest{}, refuse(ReasonBadSignature, "no release key signed this manifest")
	}
	// Only signed bytes are parsed: a release wrote them.
	m, err := parseManifest(manifest)
	if err != nil {
		return Manifest{}, err
	}
	if m.OS != goos || m.Arch != goarch {
		return Manifest{}, refuse(ReasonPlatform, "the helper is built for %s/%s; this machine is %s/%s", m.OS, m.Arch, goos, goarch)
	}
	return m, nil
}

// parseManifest reads one manifest, strictly: no field it does not know,
// nothing after it, and every rule of check. The bytes are a release's
// (Verify) or root's own (ReadFloor).
func parseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, refuse(ReasonBadManifest, "%v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Manifest{}, refuse(ReasonBadManifest, "data after the manifest")
	}
	if err := m.check(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// CheckNewer refuses next when it is older than running, the helper that
// runs now, or ran last before a restart (ReadFloor; nil: none ran): an
// older version, or a lower API level, which
// would take calls away from an agent that uses them. The same version
// passes, so a release cut again under its tag can still be swapped in.
//
// Versions order as semver does across every release line: a patch on an
// older line (v0.6.15) is older than any newer line's release (v0.7.0), so
// a node never moves back to it. An agent rolled back keeps working with
// the newer helper, which only ever adds calls (rootdpb, eng review D5).
func CheckNewer(next Manifest, running *Manifest) error {
	if running == nil {
		return nil
	}
	if compareVersions(next.Version, running.Version) < 0 {
		return refuse(ReasonOlder, "version %s is older than the running helper's %s", next.Version, running.Version)
	}
	if next.API < running.API {
		return refuse(ReasonOlder, "API level %d is lower than the running helper's %d", next.API, running.API)
	}
	return nil
}

// version is a parsed release version.
type version struct {
	core [3]uint64
	pre  []string // empty for a release; it sorts after any prerelease
}

func parseVersion(s string) (version, error) {
	m := releaseVersion.FindStringSubmatch(s)
	if m == nil {
		return version{}, fmt.Errorf("version %q is not a release version (vMAJOR.MINOR.PATCH, optionally -PRERELEASE)", s)
	}
	var v version
	for i := range v.core {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return version{}, fmt.Errorf("version %q: %w", s, err)
		}
		v.core[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, nil
}

// compareVersions orders two release versions by semver precedence. Both
// have passed parseVersion; one that has not sorts first.
func compareVersions(a, b string) int {
	va, errA := parseVersion(a)
	vb, errB := parseVersion(b)
	switch {
	case errA != nil && errB != nil:
		return 0
	case errA != nil:
		return -1
	case errB != nil:
		return 1
	}
	for i := range va.core {
		if c := cmpUint(va.core[i], vb.core[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1
	case len(vb.pre) == 0:
		return -1
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		if c := comparePre(va.pre[i], vb.pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(va.pre)), uint64(len(vb.pre)))
}

// comparePre orders two prerelease parts: numbers by value and before
// words, words by their bytes.
func comparePre(a, b string) int {
	na, errA := strconv.ParseUint(a, 10, 64)
	nb, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		return cmpUint(na, nb)
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

//go:embed release-keys.pub
var releaseKeysPEM []byte

// ReleaseKeys are the public keys built into this binary.
func ReleaseKeys() ([]ed25519.PublicKey, error) { return ParseKeys(releaseKeysPEM) }

// ParseKeys reads every PUBLIC KEY block in pemBytes, each an ed25519 key
// in the usual SubjectPublicKeyInfo form (`openssl pkey -pubout`). Text
// around the blocks is ignored; a block of another type or key is an
// error, so a mistyped key file fails loudly instead of trusting nothing.
func ParseKeys(pemBytes []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for rest := pemBytes; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return keys, nil
		}
		if b.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("release key file: a %q block, want PUBLIC KEY", b.Type)
		}
		k, err := parsePublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
}

// spkiPrefix starts every ed25519 SubjectPublicKeyInfo (RFC 8410): the
// algorithm (OID 1.3.101.112, no parameters) and a 33-byte bit string with
// no unused bits. Reading it by its fixed shape keeps crypto/x509, and its
// parsers, out of the supervisor.
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

func parsePublicKey(der []byte) (ed25519.PublicKey, error) {
	if len(der) != len(spkiPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, spkiPrefix) {
		return nil, errors.New("release key file: a key that is not ed25519")
	}
	return ed25519.PublicKey(bytes.Clone(der[len(spkiPrefix):])), nil
}

// MarshalPublicKey is k as a PUBLIC KEY block, the form ParseKeys reads.
func MarshalPublicKey(k ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: append(bytes.Clone(spkiPrefix), k...)})
}
