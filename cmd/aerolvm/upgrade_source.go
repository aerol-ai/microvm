package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Where release files come from for `aerolvm upgrade` and `aerolvm release
// pull` (plans/kubectl-style-cluster-ops.md §6.3, §7.1): the release URL, a
// directory (--from ./dist) or an offline bundle (--from x.tgz). Every file
// is checked against the release's checksums.txt before anything reaches a
// server; reading is streamed, so a 77 MiB sandboxd never sits in memory.

// defaultReleaseURL is the GitHub release download base. A file is at
// <base>/<version>/<asset>, as install.sh and the node upgrader fetch it.
const defaultReleaseURL = "https://github.com/aerol-ai/microvm/releases/download"

const (
	checksumsName = "checksums.txt"
	manifestName  = "manifest.json"
	// bundleFormat is the offline bundle layout this aerolvm writes and
	// reads. A bundle with another number is refused before anything is
	// read from it.
	bundleFormat = 1
	// Caps on what aerolvm reads: small metadata files, and release files
	// at the server's upload cap.
	maxMetaBytes       = 1 << 20
	maxProvenanceBytes = 16 << 20
	maxBundleEntries   = 128
)

var (
	// releaseVersionRe is the shape of a version argument before it reaches
	// a URL or a file name (the node upgrader's own rule).
	releaseVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	// upgradeAssetRe is a release file an upgrade carries: a Linux
	// sandboxd, toolboxd or caddy for one CPU type.
	upgradeAssetRe = regexp.MustCompile(`^(sandboxd|toolboxd|caddy)_linux_([a-z0-9]+)$`)
)

// releaseSet is one release's files, checked.
type releaseSet struct {
	version string
	// origin says where the files came from, for messages.
	origin string
	// files maps each file an upgrade carries (upgradeAssetRe names and
	// release.json) to its SHA-256.
	files map[string]string
	// paths maps each of files to a local copy; nil for the release URL,
	// where the nodes download them.
	paths map[string]string
	// meta is release.json; nil when the release has none (releases before
	// v0.6.12, dev builds).
	meta *release.Metadata
	// bundle is set for an offline bundle: its manifest.
	bundle *bundleManifest
	// cleanup removes temporary files; never nil.
	cleanup func()
}

func (s *releaseSet) offline() bool { return s.paths != nil }

// arches lists the CPU types the set carries a sandboxd for, sorted.
func (s *releaseSet) arches() []string {
	var out []string
	for name := range s.files {
		if m := upgradeAssetRe.FindStringSubmatch(name); m != nil && m[1] == "sandboxd" {
			out = append(out, m[2])
		}
	}
	sort.Strings(out)
	return out
}

// sortedFiles is files' names, sorted.
func (s *releaseSet) sortedFiles() []string {
	names := make([]string, 0, len(s.files))
	for n := range s.files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// parseChecksums reads sha256sum output: "<hex>  <name>" (or "<hex> *<name>")
// per line. A line it cannot read is an error, not a skip: checksums.txt is
// what every check stands on.
func parseChecksums(r io.Reader) (map[string]string, error) {
	sums := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, maxMetaBytes))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		sum, name, ok := strings.Cut(text, " ")
		name = strings.TrimPrefix(strings.TrimSpace(name), "*")
		if !ok || !upgradewire.SHA256Re.MatchString(sum) || name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
			return nil, fmt.Errorf("%s line %d is not \"<sha256>  <file>\"", checksumsName, line)
		}
		if prev, dup := sums[name]; dup && prev != sum {
			return nil, fmt.Errorf("%s names %s twice with different hashes", checksumsName, name)
		}
		sums[name] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", checksumsName, err)
	}
	if len(sums) == 0 {
		return nil, fmt.Errorf("%s is empty", checksumsName)
	}
	return sums, nil
}

// pickUpgradeFiles chooses, from names, the files an upgrade carries: for
// each CPU type with a sandboxd (limited to arches when given), its
// sandboxd, toolboxd and caddy, plus release.json. Every CPU type needs a
// toolboxd beside its sandboxd.
func pickUpgradeFiles(names map[string]string, arches []string) (map[string]string, error) {
	want := map[string]bool{}
	for _, a := range arches {
		want[a] = true
	}
	have := map[string]map[string]bool{}
	for name := range names {
		if m := upgradeAssetRe.FindStringSubmatch(name); m != nil {
			if len(want) > 0 && !want[m[2]] {
				continue
			}
			if have[m[2]] == nil {
				have[m[2]] = map[string]bool{}
			}
			have[m[2]][m[1]] = true
		}
	}
	out := map[string]string{}
	for arch, roles := range have {
		if !roles["sandboxd"] {
			continue // a toolboxd-only platform (freebsd, darwin builds) is not a node
		}
		if !roles["toolboxd"] {
			return nil, fmt.Errorf("there is a sandboxd_linux_%s but no toolboxd_linux_%s", arch, arch)
		}
		for role := range roles {
			name := role + "_linux_" + arch
			out[name] = names[name]
		}
	}
	for _, a := range arches {
		if have[a] == nil || !have[a]["sandboxd"] {
			return nil, fmt.Errorf("no sandboxd_linux_%s: --arch %s is not in this release", a, a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no sandboxd_linux_<cpu> file")
	}
	if sum, ok := names[release.FileName]; ok {
		out[release.FileName] = sum
	}
	return out, nil
}

// hashFile streams a file through SHA-256.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// readMeta parses a local release.json and checks it describes version.
func readMeta(path, version string) (*release.Metadata, error) {
	raw, err := readCapped(path, maxMetaBytes)
	if err != nil {
		return nil, err
	}
	m, err := release.Parse(raw)
	if err != nil {
		return nil, err
	}
	if m.Version != version {
		return nil, fmt.Errorf("%s describes %s, not %s", release.FileName, m.Version, version)
	}
	return &m, nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), max)
	}
	return raw, nil
}

// loadDirSource checks a directory of release files (--from ./dist): every
// upgrade file in it must match its line in the directory's checksums.txt.
func loadDirSource(dir, version string, arches []string) (*releaseSet, error) {
	sumsFile, err := os.Open(filepath.Join(dir, checksumsName))
	if err != nil {
		return nil, fmt.Errorf("--from %s: %w (the directory needs the release's %s)", dir, err, checksumsName)
	}
	sums, err := parseChecksums(sumsFile)
	sumsFile.Close()
	if err != nil {
		return nil, fmt.Errorf("--from %s: %w", dir, err)
	}
	present := map[string]string{}
	for name, sum := range sums {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && fi.Mode().IsRegular() {
			present[name] = sum
		}
	}
	files, err := pickUpgradeFiles(present, arches)
	if err != nil {
		return nil, fmt.Errorf("--from %s: %w", dir, err)
	}
	set := &releaseSet{version: version, origin: dir, files: files, paths: map[string]string{}, cleanup: func() {}}
	for _, name := range set.sortedFiles() {
		path := filepath.Join(dir, name)
		got, size, err := hashFile(path)
		if err != nil {
			return nil, fmt.Errorf("--from %s: %w", dir, err)
		}
		if got != files[name] {
			return nil, fmt.Errorf("--from %s: %s has SHA-256 %s, but %s says %s; refusing to send it", dir, name, got, checksumsName, files[name])
		}
		if size > upgradewire.MaxUploadBytes {
			return nil, fmt.Errorf("--from %s: %s is larger than the 256 MiB upload limit", dir, name)
		}
		set.paths[name] = path
	}
	if p, ok := set.paths[release.FileName]; ok {
		if set.meta, err = readMeta(p, version); err != nil {
			return nil, fmt.Errorf("--from %s: %w", dir, err)
		}
	}
	return set, nil
}

// bundleManifest is manifest.json in an offline bundle (§7.1).
type bundleManifest struct {
	BundleFormat int          `json:"bundle_format"`
	Version      string       `json:"version"`
	CreatedAt    time.Time    `json:"created_at"`
	Files        []bundleFile `json:"files"`
}

type bundleFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// errUnknownBundleFormat is the refusal of a bundle from another aerolvm.
var errUnknownBundleFormat = errors.New("unknown bundle format")

// isBundlePath says whether --from names a bundle file rather than a
// directory.
func isBundlePath(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// loadBundleSource unpacks an offline bundle into a temporary directory and
// checks it twice: every file against manifest.json, and every release file
// against the bundle's checksums.txt. manifest.json must come first, so a
// format this aerolvm does not know is refused before anything else is
// read. Nothing is sent anywhere until both checks pass.
func loadBundleSource(path, version string, arches []string) (set *releaseSet, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("bundle %s: not a .tgz: %w", path, err)
	}
	tmp, err := os.MkdirTemp("", "aerolvm-bundle-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	fail := func(format string, a ...any) error {
		return fmt.Errorf("bundle %s: %s; refusing it", path, fmt.Sprintf(format, a...))
	}
	tr := tar.NewReader(zr)
	var manifest *bundleManifest
	got := map[string]string{}
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fail("read: %v", err)
		}
		name := hdr.Name
		switch {
		case i >= maxBundleEntries:
			return nil, fail("more than %d files", maxBundleEntries)
		case hdr.Typeflag != tar.TypeReg:
			return nil, fail("%s is not a plain file", name)
		case name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || name == "." || name == "..":
			return nil, fail("entry %q is not a plain file name", name)
		case got[name] != "":
			return nil, fail("%s appears twice", name)
		case hdr.Size > upgradewire.MaxUploadBytes:
			return nil, fail("%s is larger than 256 MiB", name)
		case i == 0 && name != manifestName:
			return nil, fail("its first file is %s, not %s", name, manifestName)
		}
		if name == manifestName {
			raw, err := io.ReadAll(io.LimitReader(tr, maxMetaBytes+1))
			if err != nil || len(raw) > maxMetaBytes {
				return nil, fail("%s is unreadable or too large", manifestName)
			}
			var m bundleManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fail("%s: %v", manifestName, err)
			}
			if m.BundleFormat != bundleFormat {
				return nil, fmt.Errorf("bundle %s has bundle format %d, and this aerolvm reads format %d: %w; use the aerolvm that made it, or a newer one",
					path, m.BundleFormat, bundleFormat, errUnknownBundleFormat)
			}
			if m.Version != version {
				return nil, fail("it holds %s, not %s", m.Version, version)
			}
			manifest = &m
			got[name] = "manifest"
			continue
		}
		sum, size, err := streamToFile(tr, filepath.Join(tmp, name), hdr.Size)
		if err != nil {
			return nil, fail("%s: %v", name, err)
		}
		if size != hdr.Size {
			return nil, fail("%s is cut short", name)
		}
		got[name] = sum
	}
	if manifest == nil {
		return nil, fail("it has no %s", manifestName)
	}
	listed := map[string]bool{}
	for _, mf := range manifest.Files {
		listed[mf.Name] = true
		sum, ok := got[mf.Name]
		if !ok {
			return nil, fail("%s lists %s, which is not in it", manifestName, mf.Name)
		}
		if sum != mf.SHA256 {
			return nil, fail("%s has SHA-256 %s, but %s says %s", mf.Name, sum, manifestName, mf.SHA256)
		}
	}
	for name := range got {
		if name != manifestName && !listed[name] {
			return nil, fail("%s is not listed in %s", name, manifestName)
		}
	}
	set, err = loadDirSource(tmp, version, arches)
	if err != nil {
		return nil, fail("%v", strings.TrimPrefix(err.Error(), "--from "+tmp+": "))
	}
	set.origin = path
	set.bundle = manifest
	set.cleanup = func() { _ = os.RemoveAll(tmp) }
	return set, nil
}

// streamToFile copies at most max bytes of r to path, hashing on the way.
func streamToFile(r io.Reader, path string, max int64) (string, int64, error) {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("larger than %d bytes", max)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// releaseFetcher reads files of published releases.
type releaseFetcher struct {
	base   string
	client *http.Client
}

func (a *app) releaseFetcher(c *commonFlags, flagURL string) *releaseFetcher {
	base := strings.TrimSpace(flagURL)
	if base == "" {
		base = strings.TrimSpace(a.getenv("AEROLVM_RELEASE_URL"))
	}
	if base == "" {
		base = defaultReleaseURL
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 60 * time.Second
	var rt http.RoundTripper = transport
	if c != nil && c.debug {
		rt = &debugTransport{base: transport, out: a.stderr}
	}
	return &releaseFetcher{base: strings.TrimRight(base, "/"), client: &http.Client{Transport: rt}}
}

func (f *releaseFetcher) url(version, name string) string {
	return f.base + "/" + version + "/" + name
}

// errNotPublished is a 404 from the release URL.
var errNotPublished = errors.New("not published")

// open starts a download. The caller closes the body.
func (f *releaseFetcher) open(ctx context.Context, version, name string) (io.ReadCloser, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url(version, name), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("%s: %w", f.url(version, name), errNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("GET %s: %s", f.url(version, name), resp.Status)
	}
	return resp.Body, resp.ContentLength, nil
}

// small downloads a metadata file whole.
func (f *releaseFetcher) small(ctx context.Context, version, name string, max int64) ([]byte, error) {
	body, _, err := f.open(ctx, version, name)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", f.url(version, name), err)
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", f.url(version, name), max)
	}
	return raw, nil
}

// download streams one file to path, hashing on the way, and checks it.
func (f *releaseFetcher) download(ctx context.Context, version, name, path, want string, max int64) (int64, error) {
	body, _, err := f.open(ctx, version, name)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	sum, n, err := streamToFile(body, path, max)
	if err != nil {
		return 0, fmt.Errorf("download %s: %w", name, err)
	}
	if want != "" && sum != want {
		_ = os.Remove(path)
		return 0, fmt.Errorf("%s downloaded with SHA-256 %s, but %s says %s; refusing it", name, sum, checksumsName, want)
	}
	return n, nil
}

// checksums downloads and parses a release's checksums.txt.
func (f *releaseFetcher) checksums(ctx context.Context, version string) (map[string]string, error) {
	raw, err := f.small(ctx, version, checksumsName, maxMetaBytes)
	if err != nil {
		return nil, err
	}
	return parseChecksums(strings.NewReader(string(raw)))
}

// meta downloads release.json for version, checked against sum when given.
// A release without one answers nil, nil.
func (f *releaseFetcher) meta(ctx context.Context, version, sum string) (*release.Metadata, error) {
	raw, err := f.small(ctx, version, release.FileName, maxMetaBytes)
	if errors.Is(err, errNotPublished) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if sum != "" {
		h := sha256.Sum256(raw)
		if got := hex.EncodeToString(h[:]); got != sum {
			return nil, fmt.Errorf("%s of %s has SHA-256 %s, but %s says %s", release.FileName, version, got, checksumsName, sum)
		}
	}
	m, err := release.Parse(raw)
	if err != nil {
		return nil, err
	}
	if m.Version != version {
		return nil, fmt.Errorf("%s of %s describes %s", release.FileName, version, m.Version)
	}
	return &m, nil
}

// loadReleaseSource reads a published release's hashes: the nodes download
// the files themselves, and check them against these.
func (f *releaseFetcher) loadReleaseSource(ctx context.Context, version string, arches []string) (*releaseSet, error) {
	sums, err := f.checksums(ctx, version)
	if err != nil {
		return nil, fmt.Errorf("read the release's %s: %w", checksumsName, err)
	}
	files, err := pickUpgradeFiles(sums, arches)
	if err != nil {
		return nil, fmt.Errorf("release %s: %w", version, err)
	}
	set := &releaseSet{version: version, origin: f.base + "/" + version, files: files, cleanup: func() {}}
	if sum, ok := files[release.FileName]; ok {
		if set.meta, err = f.meta(ctx, version, sum); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// loadSource is --from (a directory or a bundle) or the release URL.
func (a *app) loadSource(ctx context.Context, c *commonFlags, from, releaseURL, version string, arches []string) (*releaseSet, error) {
	switch {
	case from == "":
		return a.releaseFetcher(c, releaseURL).loadReleaseSource(ctx, version, arches)
	case isBundlePath(from):
		return loadBundleSource(from, version, arches)
	}
	return loadDirSource(from, version, arches)
}

// parseArches reads --arch amd64,arm64.
func parseArches(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if !regexp.MustCompile(`^[a-z0-9]{1,16}$`).MatchString(a) {
			return nil, fmt.Errorf("--arch %q is not a CPU type such as amd64 or arm64", a)
		}
		out = append(out, a)
	}
	return out, nil
}

// humanBytes formats a size for progress lines.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
