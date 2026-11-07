package nodeupgrade

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/release"
)

// Roles of the files one upgrade carries. The swap order is fixed
// (swapOrder): toolboxd, then caddy, then sandboxd last, so a sandboxd on
// disk that is new means every other file already is (Recover relies on
// it).
const (
	roleSandboxd = "sandboxd"
	roleToolboxd = "toolboxd"
	roleCaddy    = "caddy"
	roleRelease  = release.FileName
)

var swapOrder = []string{roleToolboxd, roleCaddy, roleSandboxd}

// Request is one `sandboxd upgrade node` invocation.
type Request struct {
	// Version is the release the node should run afterwards.
	Version string
	// SHA256 maps each file to install, by its release asset name
	// (sandboxd_linux_amd64, release.json, ...), to its hex SHA-256. Every
	// file is checked against it before anything stops.
	SHA256 map[string]string
	// From is a directory holding the files; empty downloads them from the
	// release URL.
	From string
	// Rollback allows a downgrade. With no SHA256 it puts back the *.prev
	// files the last upgrade kept (§6.8).
	Rollback bool
	// AllowUnversioned allows a target or installed version that is not a
	// release tag (dev and test builds), which cannot be ordered.
	AllowUnversioned bool
	// SkipHostApply says the caller already applied this release's host
	// setup (install.sh's hand-off), so host apply never runs.
	SkipHostApply bool
	// Op names the operation; empty makes one up.
	Op string
	// HealthTimeout bounds the wait for the new sandboxd; zero is the
	// default.
	HealthTimeout time.Duration
}

// DefaultHealthTimeout is how long the upgrader waits for the new sandboxd
// to answer /health with the target version.
const DefaultHealthTimeout = 2 * time.Minute

var (
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	opRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	hashRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A release asset: an optional "<tag>_" prefix (release.yml ships each
	// file under both names), the binary and an optional OS and CPU type.
	assetRe = regexp.MustCompile(`^(?:v[0-9][A-Za-z0-9.+-]*_)?(sandboxd|toolboxd|caddy)(?:_([a-z0-9]+)_([a-z0-9]+))?$`)
)

// ErrUsage marks a request the command line got wrong.
var ErrUsage = errors.New("usage")

func usageErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, a...))
}

// NewOpID makes an operation ID: the UTC time and four random bytes.
func NewOpID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102t150405") + "-" + hex.EncodeToString(b[:])
}

// fileSpec is one file of the request after validation.
type fileSpec struct {
	role   string
	asset  string
	sha256 string
}

// validate checks every input that reaches a path, a URL or a unit name,
// and maps the files to their roles.
func (r *Request) validate(goos, goarch string) ([]fileSpec, error) {
	if !versionRe.MatchString(r.Version) {
		return nil, usageErr("version %q is not a release tag", r.Version)
	}
	if r.Op != "" && !opRe.MatchString(r.Op) {
		return nil, usageErr("--op %q must be 1-64 letters, digits, '-' or '_'", r.Op)
	}
	if r.HealthTimeout < 0 {
		return nil, usageErr("--health-timeout must not be negative")
	}
	if len(r.SHA256) == 0 {
		if !r.Rollback {
			return nil, usageErr("give each file's SHA-256 with --sha256 <file>=<hash> (from the release's checksums.txt)")
		}
		if r.From != "" {
			return nil, usageErr("--from needs --sha256 for each file in it")
		}
		return nil, nil
	}
	names := make([]string, 0, len(r.SHA256))
	for n := range r.SHA256 {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]string{}
	var specs []fileSpec
	for _, name := range names {
		sum := strings.ToLower(strings.TrimSpace(r.SHA256[name]))
		if !hashRe.MatchString(sum) {
			return nil, usageErr("--sha256 %s: %q is not a hex SHA-256", name, r.SHA256[name])
		}
		role, err := roleOf(name, goos, goarch)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[role]; dup {
			return nil, usageErr("--sha256 names two %s files: %s and %s", role, prev, name)
		}
		seen[role] = name
		specs = append(specs, fileSpec{role: role, asset: name, sha256: sum})
	}
	for _, need := range []string{roleSandboxd, roleToolboxd} {
		if _, ok := seen[need]; !ok {
			return nil, usageErr("--sha256 names no %s file; an upgrade carries sandboxd and toolboxd", need)
		}
	}
	return specs, nil
}

// roleOf maps a release asset name to the file it installs. A name for
// another CPU type is refused: installing it would leave a binary the node
// cannot run.
func roleOf(asset, goos, goarch string) (string, error) {
	if asset == roleRelease {
		return roleRelease, nil
	}
	m := assetRe.FindStringSubmatch(asset)
	if m == nil {
		return "", usageErr("--sha256 %s: not a release file (sandboxd, toolboxd, caddy or release.json, optionally _linux_<arch>)", asset)
	}
	if m[2] != "" {
		if m[2] != goos || !archMatches(m[3], goarch) {
			return "", fmt.Errorf("%s is built for %s_%s, and this node is %s_%s", asset, m[2], m[3], goos, goarch)
		}
	}
	return m[1], nil
}

func archMatches(suffix, goarch string) bool {
	if suffix == goarch {
		return true
	}
	// release.yml names 32-bit ARM builds armv6 and armv7.
	return goarch == "arm" && strings.HasPrefix(suffix, "armv")
}

// Args is the command line that runs r: what Launch passes to
// systemd-run, and what a caller prints for an operator to run by hand.
// Each value is its own argument; nothing is ever joined into a shell
// string.
func (r Request) Args() []string {
	args := []string{"upgrade", "node", r.Version}
	names := make([]string, 0, len(r.SHA256))
	for n := range r.SHA256 {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		args = append(args, "--sha256", n+"="+r.SHA256[n])
	}
	if r.From != "" {
		args = append(args, "--from", r.From)
	}
	if r.Rollback {
		args = append(args, "--rollback")
	}
	if r.AllowUnversioned {
		args = append(args, "--allow-unversioned")
	}
	if r.SkipHostApply {
		args = append(args, "--skip-host-apply")
	}
	if r.Op != "" {
		args = append(args, "--op", r.Op)
	}
	if r.HealthTimeout > 0 {
		args = append(args, "--health-timeout", r.HealthTimeout.String())
	}
	return args
}
