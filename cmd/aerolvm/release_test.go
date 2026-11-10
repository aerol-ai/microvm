package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/release"
)

// bundleEntry is one file in a bundle, as a test reads or writes it.
type bundleEntry struct {
	name string
	body []byte
	kind byte
}

func readBundle(t *testing.T, path string) []bundleEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var out []bundleEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		out = append(out, bundleEntry{name: hdr.Name, body: body, kind: hdr.Typeflag})
	}
}

func writeBundleEntries(t *testing.T, path string, entries []bundleEntry) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: kind}
		if kind != tar.TypeReg {
			hdr.Size, hdr.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			_, _ = tw.Write(e.body)
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// publishStd publishes v0.6.12 and v0.6.13 (release.json in both) and
// v0.6.11 (none), for amd64 and arm64.
func publishStd(r *fakeReleases) {
	r.publish("v0.6.11", releaseFiles("v0.6.11", nil, "amd64", "arm64"), true)
	r.publish("v0.6.12", releaseFiles("v0.6.12", releaseMeta("v0.6.12", "v0.6.11", "install-12", []int{1}), "amd64", "arm64"), true)
	r.publish("v0.6.13", releaseFiles("v0.6.13", releaseMeta("v0.6.13", "v0.6.12", "install-13", []int{1, 2}, 7), "amd64", "arm64"), true)
}

func pullHarness(t *testing.T) (*harness, *fakeReleases, string) {
	r := newFakeReleases(t)
	publishStd(r)
	h := newHarness(t)
	h.env["AEROLVM_RELEASE_URL"] = r.base()
	h.app.now = func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) }
	return h, r, t.TempDir()
}

func TestReleasePullRoundTrip(t *testing.T) {
	h, r, dir := pullHarness(t)
	out := filepath.Join(dir, "x.tgz")
	if code := h.run("release", "pull", "v0.6.13", "-o", out); code != exitOK {
		t.Fatalf("pull = %d %s", code, h.stderr.String())
	}
	// The gzip size depends on the Go release; the rest is stable.
	got := regexp.MustCompile(`, [0-9.]+ (B|KiB|MiB) `).ReplaceAllString(h.transcript(exitOK), ", <size> ")
	checkGoldenIn(t, "upgrade", "release-pull.golden", strings.ReplaceAll(got, dir, "<dir>"))
	entries := readBundle(t, out)
	var names []string
	for _, e := range entries {
		names = append(names, e.name)
	}
	want := "manifest.json checksums.txt caddy_linux_amd64 caddy_linux_arm64 release.json sandboxd_linux_amd64 sandboxd_linux_arm64 toolboxd_linux_amd64 toolboxd_linux_arm64 v0.6.13.intoto.jsonl"
	if strings.Join(names, " ") != want {
		t.Fatalf("bundle = %s", strings.Join(names, " "))
	}
	// checksums.txt and the provenance travel unchanged.
	if !bytes.Equal(entries[1].body, r.files["v0.6.13"][checksumsName]) || !bytes.Equal(entries[9].body, r.files["v0.6.13"]["v0.6.13.intoto.jsonl"]) {
		t.Fatal("checksums.txt or the provenance changed on the way")
	}
	var m bundleManifest
	if err := json.Unmarshal(entries[0].body, &m); err != nil || m.BundleFormat != bundleFormat || m.Version != "v0.6.13" || len(m.Files) != 9 {
		t.Fatalf("manifest = %+v %v", m, err)
	}
	// And back: apply --from reads it and every check passes.
	set, err := loadBundleSource(out, "v0.6.13", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer set.cleanup()
	if strings.Join(set.arches(), ",") != "amd64,arm64" || set.meta == nil || set.meta.OneWayMigrations[0] != 7 || set.bundle == nil || len(set.files) != 7 {
		t.Fatalf("set = %+v", set)
	}
	if got, _ := os.ReadFile(set.paths["sandboxd_linux_arm64"]); !bytes.Equal(got, r.files["v0.6.13"]["sandboxd_linux_arm64"]) {
		t.Fatal("bundle sandboxd differs from the release's")
	}
	// --arch limits the bundle; --json prints the manifest.
	out2 := filepath.Join(dir, "amd64.tgz")
	if code := h.run("release", "pull", "v0.6.13", "-o", out2, "--arch", "amd64", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var m2 bundleManifest
	h.jsonOut(&m2)
	if len(m2.Files) != 6 || strings.Contains(h.stdout.String(), "arm64") {
		t.Fatalf("amd64 manifest = %s", h.stdout.String())
	}
	// The default name is aerolvm-<version>.tgz in the current directory.
	t.Chdir(dir)
	if code := h.run("release", "pull", "v0.6.12", "--arch", "arm64"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "aerolvm-v0.6.12.tgz")); err != nil {
		t.Fatal(err)
	}
}

func TestReleasePullRefusals(t *testing.T) {
	h, r, dir := pullHarness(t)
	out := filepath.Join(dir, "x.tgz")
	r.lie["v0.6.13/sandboxd_linux_arm64"] = true
	if code := h.run("release", "pull", "v0.6.13", "-o", out); code != exitError || !strings.Contains(h.stderr.String(), "sandboxd_linux_arm64 downloaded with SHA-256") {
		t.Fatalf("lying mirror = %d %s", code, h.stderr.String())
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("a refused pull left %d files", len(left))
	}
	delete(r.lie, "v0.6.13/sandboxd_linux_arm64")
	// A release without provenance still bundles, with a warning.
	delete(r.files["v0.6.12"], "v0.6.12.intoto.jsonl")
	if code := h.run("release", "pull", "v0.6.12", "-o", out); code != exitOK || !strings.Contains(h.stderr.String(), "no v0.6.12.intoto.jsonl") {
		t.Fatalf("no provenance = %d %s", code, h.stderr.String())
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"release", "pull", "v9.9.9", "-o", out}, exitError, "not published"},
		{[]string{"release", "pull", "v0.6.13", "-o", out, "--arch", "riscv64"}, exitError, "--arch riscv64 is not in this release"},
		{[]string{"release", "pull", "v0.6.13", "--arch", "AMD"}, exitUsage, "not a CPU type"},
		{[]string{"release", "pull"}, exitUsage, "pull needs one version"},
		{[]string{"release", "pull", "../x"}, exitUsage, "is not a version"},
		{[]string{"release", "pull", "--bogus"}, exitUsage, "bogus"},
		{[]string{"release"}, exitUsage, "expected a subcommand: pull"},
		{[]string{"release", "push"}, exitUsage, `unknown subcommand "push"`},
		{[]string{"release", "pull", "v0.6.13", "-o", filepath.Join(dir, "missing", "x.tgz")}, exitError, "no such file"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d %q, want %d with %q", tc.args, code, h.stderr.String(), tc.code, tc.want)
		}
	}
	// A release.json that describes another version is refused.
	files := releaseFiles("v0.6.14", releaseMeta("v0.6.99", "v0.6.12", "x", []int{1}), "amd64")
	r.publish("v0.6.14", files, false)
	if code := h.run("release", "pull", "v0.6.14", "-o", out); code != exitError || !strings.Contains(h.stderr.String(), "describes v0.6.99") {
		t.Fatalf("wrong release.json = %d %s", code, h.stderr.String())
	}
	// A checksums.txt that is not one.
	r.files["v0.6.14"][checksumsName] = []byte("hello world\n")
	if code := h.run("release", "pull", "v0.6.14", "-o", out); code != exitError || !strings.Contains(h.stderr.String(), "line 1") {
		t.Fatalf("bad checksums = %d %s", code, h.stderr.String())
	}
}

// Every way a bundle can be tampered with is refused before any server is
// called.
func TestBundleTamperingIsRefused(t *testing.T) {
	h, _, dir := pullHarness(t)
	good := filepath.Join(dir, "good.tgz")
	if code := h.run("release", "pull", "v0.6.13", "-o", good, "--arch", "amd64"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	orig := readBundle(t, good)
	find := func(entries []bundleEntry, name string) int {
		for i, e := range entries {
			if e.name == name {
				return i
			}
		}
		t.Fatalf("no %s", name)
		return -1
	}
	clone := func() []bundleEntry {
		out := make([]bundleEntry, len(orig))
		for i, e := range orig {
			out[i] = bundleEntry{name: e.name, body: append([]byte(nil), e.body...)}
		}
		return out
	}
	setManifest := func(entries []bundleEntry, mut func(*bundleManifest)) {
		var m bundleManifest
		if err := json.Unmarshal(entries[0].body, &m); err != nil {
			t.Fatal(err)
		}
		mut(&m)
		entries[0].body, _ = json.Marshal(m)
	}
	for _, tc := range []struct {
		name string
		make func() []bundleEntry
		want string
	}{
		{"binary changed", func() []bundleEntry {
			e := clone()
			e[find(e, "sandboxd_linux_amd64")].body = []byte("evil")
			return e
		}, "but manifest.json says"},
		{"binary and manifest changed", func() []bundleEntry {
			e := clone()
			i := find(e, "sandboxd_linux_amd64")
			e[i].body = []byte("evil")
			setManifest(e, func(m *bundleManifest) {
				for j := range m.Files {
					if m.Files[j].Name == "sandboxd_linux_amd64" {
						m.Files[j].SHA256 = sha([]byte("evil"))
					}
				}
			})
			return e
		}, "but checksums.txt says"},
		{"unknown format", func() []bundleEntry {
			e := clone()
			setManifest(e, func(m *bundleManifest) { m.BundleFormat = 2 })
			return e
		}, "bundle format 2, and this aerolvm reads format 1"},
		{"another version", func() []bundleEntry {
			e := clone()
			setManifest(e, func(m *bundleManifest) { m.Version = "v0.6.12" })
			return e
		}, "it holds v0.6.12, not v0.6.13"},
		{"manifest not first", func() []bundleEntry {
			e := clone()
			e[0], e[1] = e[1], e[0]
			return e
		}, "its first file is checksums.txt"},
		{"extra file", func() []bundleEntry {
			return append(clone(), bundleEntry{name: "hook.sh", body: []byte("#!/bin/sh")})
		}, "hook.sh is not listed"},
		{"listed file missing", func() []bundleEntry {
			e := clone()
			i := find(e, "caddy_linux_amd64")
			return append(e[:i], e[i+1:]...)
		}, "lists caddy_linux_amd64, which is not in it"},
		{"path in a name", func() []bundleEntry {
			return append(clone(), bundleEntry{name: "../evil", body: []byte("x")})
		}, "is not a plain file name"},
		{"symlink", func() []bundleEntry {
			return append(clone(), bundleEntry{name: "link", kind: tar.TypeSymlink})
		}, "link is not a plain file"},
		{"twice", func() []bundleEntry {
			e := clone()
			return append(e, e[find(e, "release.json")])
		}, "release.json appears twice"},
		{"no manifest", func() []bundleEntry { return nil }, "it has no manifest.json"},
		{"bad manifest", func() []bundleEntry {
			e := clone()
			e[0].body = []byte("{")
			return e
		}, "manifest.json:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.tgz")
			writeBundleEntries(t, path, tc.make())
			f := newFakeUpgrade(t, false, "v0.6.12")
			uh := upgradeHarness(t, f)
			uh.env["AEROLVM_RELEASE_URL"] = h.env["AEROLVM_RELEASE_URL"]
			if code := uh.run("upgrade", "apply", "v0.6.13", "--from", path); code != exitError || !strings.Contains(uh.stderr.String(), tc.want) {
				t.Fatalf("apply = %d %q, want %q", code, uh.stderr.String(), tc.want)
			}
			if len(f.calls) != 0 {
				t.Fatalf("a refused bundle reached sandboxd: %v", f.calls)
			}
		})
	}
	if _, err := loadBundleSource(filepath.Join(dir, "missing.tgz"), "v0.6.13", nil); err == nil {
		t.Fatal("a missing bundle loaded")
	}
	notGzip := filepath.Join(dir, "plain.tgz")
	_ = os.WriteFile(notGzip, []byte("not gzip"), 0o644)
	if _, err := loadBundleSource(notGzip, "v0.6.13", nil); err == nil || !strings.Contains(err.Error(), "not a .tgz") {
		t.Fatalf("not gzip = %v", err)
	}
	if _, err := loadBundleSource(good, "v0.6.13", nil); err != nil {
		t.Fatalf("the untouched bundle: %v", err)
	}
	var unknown error
	writeBundleEntries(t, filepath.Join(dir, "v2.tgz"), []bundleEntry{{name: manifestName, body: []byte(`{"bundle_format":2}`)}})
	_, unknown = loadBundleSource(filepath.Join(dir, "v2.tgz"), "v0.6.13", nil)
	if !errors.Is(unknown, errUnknownBundleFormat) {
		t.Fatalf("format 2 = %v", unknown)
	}
}

func TestParseChecksumsAndPickFiles(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, tc := range []struct {
		in, want string
	}{
		{a + "  sandboxd_linux_amd64\n\n" + b + " *toolboxd_linux_amd64\n", ""},
		{"", "is empty"},
		{a + "\n", "line 1"},
		{"xyz  file\n", "line 1"},
		{a + "  dir/file\n", "line 1"},
		{a + "  f\n" + b + "  f\n", "names f twice"},
	} {
		sums, err := parseChecksums(strings.NewReader(tc.in))
		if tc.want == "" {
			if err != nil || sums["toolboxd_linux_amd64"] != b {
				t.Fatalf("%q = %v %v", tc.in, sums, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q = %v, want %q", tc.in, err, tc.want)
		}
	}
	// The same line twice is fine.
	if _, err := parseChecksums(strings.NewReader(a + "  f\n" + a + "  f\n")); err != nil {
		t.Fatal(err)
	}
	names := map[string]string{"sandboxd_linux_amd64": a, "toolboxd_linux_amd64": a, "caddy_linux_amd64": a,
		"sandboxd_linux_arm64": b, "toolboxd_freebsd_amd64": b, "toolboxd_linux_386": b, "release.json": b, "install.sh": a}
	if !strings.Contains(err2(pickUpgradeFiles(names, nil)), "no toolboxd_linux_arm64") {
		t.Fatal("a sandboxd with no toolboxd was picked")
	}
	delete(names, "sandboxd_linux_arm64")
	got, err := pickUpgradeFiles(names, nil)
	if err != nil || len(got) != 4 || got["toolboxd_linux_386"] != "" || got["release.json"] != b {
		t.Fatalf("pick = %v %v", got, err)
	}
	if _, err := pickUpgradeFiles(names, []string{"arm64"}); err == nil || !strings.Contains(err.Error(), "--arch arm64") {
		t.Fatalf("missing arch = %v", err)
	}
	if _, err := pickUpgradeFiles(map[string]string{"install.sh": a}, nil); err == nil || !strings.Contains(err.Error(), "no sandboxd_linux") {
		t.Fatalf("no sandboxd = %v", err)
	}
	if got := humanBytes(5); got != "5 B" {
		t.Fatal(got)
	}
	if got := humanBytes(3 << 30); got != "3.0 GiB" {
		t.Fatal(got)
	}
	if got := humanBytes(2048); got != "2.0 KiB" {
		t.Fatal(got)
	}
}

func err2(_ map[string]string, err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestLoadDirSource(t *testing.T) {
	write := func(dir string, files map[string][]byte, sums []byte) {
		for n, b := range files {
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if sums != nil {
			_ = os.WriteFile(filepath.Join(dir, checksumsName), sums, 0o644)
		}
	}
	all := releaseFiles("v0.6.13", releaseMeta("v0.6.13", "v0.6.12", "i", []int{1}), "amd64", "arm64")
	sums := checksumsFor(all)
	// A dist directory with only amd64 files and the full checksums.txt.
	dir := t.TempDir()
	write(dir, map[string][]byte{"sandboxd_linux_amd64": all["sandboxd_linux_amd64"], "toolboxd_linux_amd64": all["toolboxd_linux_amd64"],
		"release.json": all["release.json"], "buildinfo.json": []byte("{}")}, sums)
	set, err := loadDirSource(dir, "v0.6.13", nil)
	if err != nil || len(set.files) != 3 || set.meta == nil || strings.Join(set.arches(), ",") != "amd64" {
		t.Fatalf("dir = %+v %v", set, err)
	}
	for _, tc := range []struct {
		name    string
		setup   func(dir string)
		version string
		want    string
	}{
		{"no checksums", func(d string) { write(d, map[string][]byte{"sandboxd_linux_amd64": []byte("x")}, nil) }, "v0.6.13", "needs the release's checksums.txt"},
		{"bad checksums", func(d string) { write(d, nil, []byte("nope\n")) }, "v0.6.13", "line 1"},
		{"mismatch", func(d string) {
			write(d, map[string][]byte{"sandboxd_linux_amd64": []byte("evil"), "toolboxd_linux_amd64": all["toolboxd_linux_amd64"]}, sums)
		}, "v0.6.13", "refusing to send it"},
		{"no sandboxd", func(d string) { write(d, map[string][]byte{"install.sh": all["install.sh"]}, sums) }, "v0.6.13", "no sandboxd_linux"},
		{"release.json of another version", func(d string) {
			write(d, map[string][]byte{"sandboxd_linux_amd64": all["sandboxd_linux_amd64"], "toolboxd_linux_amd64": all["toolboxd_linux_amd64"],
				"release.json": all["release.json"]}, sums)
		}, "v0.6.14", "describes v0.6.13, not v0.6.14"},
	} {
		d := t.TempDir()
		tc.setup(d)
		if _, err := loadDirSource(d, tc.version, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s = %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := readMeta(filepath.Join(dir, "missing"), "v1"); err == nil {
		t.Fatal("missing release.json read")
	}
	big := filepath.Join(dir, "big.json")
	_ = os.WriteFile(big, bytes.Repeat([]byte(" "), maxMetaBytes+1), 0o644)
	if _, err := readMeta(big, "v1"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("big release.json = %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{}"), 0o644)
	if _, err := readMeta(bad, "v1"); err == nil {
		t.Fatal("an invalid release.json was read")
	}
	if _, _, err := hashFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("hashed a missing file")
	}
	if !isBundlePath(filepath.Join(dir, checksumsName)) || isBundlePath(dir) {
		t.Fatal("isBundlePath")
	}
}

// eng T14: a release file streams to disk while it hashes; memory does not
// grow with its size.
func TestDownloadMemoryStaysFlat(t *testing.T) {
	const size = 96 << 20
	block := bytes.Repeat([]byte("aerolvm!"), 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for sent := 0; sent < size; sent += len(block) {
			if _, err := w.Write(block); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	f := &releaseFetcher{base: srv.URL, client: srv.Client()}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	n, err := f.download(context.Background(), "v1", "big", filepath.Join(t.TempDir(), "big"), "", size)
	close(stop)
	<-done
	if err != nil || n != size {
		t.Fatalf("download = %d %v", n, err)
	}
	if grew := int64(peak.Load()) - int64(before.HeapAlloc); grew > 16<<20 {
		t.Fatalf("heap grew %s for a %s download", humanBytes(grew), humanBytes(size))
	}
	// Past the cap, the download stops and keeps nothing.
	dst := filepath.Join(t.TempDir(), "capped")
	if _, err := f.download(context.Background(), "v1", "big", dst, "", 1<<20); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("capped = %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("a capped download left its file")
	}
}

func TestReleaseFetcherErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/release.json":
			_, _ = w.Write([]byte("{"))
		case "/v2/release.json":
			raw, _ := release.Marshal(*releaseMeta("v9.0.0", "v0.6.11", "x", []int{1}))
			_, _ = w.Write(raw)
		case "/v3/release.json":
			_, _ = w.Write(bytes.Repeat([]byte(" "), maxMetaBytes+1))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	f := &releaseFetcher{base: srv.URL, client: srv.Client()}
	ctx := context.Background()
	if _, err := f.meta(ctx, "v1", ""); err == nil {
		t.Fatal("bad json")
	}
	if _, err := f.meta(ctx, "v2", ""); err == nil || !strings.Contains(err.Error(), "describes v9.0.0") {
		t.Fatalf("wrong version = %v", err)
	}
	if _, err := f.meta(ctx, "v2", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "checksums.txt says") {
		t.Fatalf("wrong hash = %v", err)
	}
	if _, err := f.meta(ctx, "v3", ""); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("too big = %v", err)
	}
	if _, err := f.meta(ctx, "v4", ""); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500 = %v", err)
	}
	if _, err := f.loadReleaseSource(ctx, "v4", nil); err == nil || !strings.Contains(err.Error(), "checksums.txt") {
		t.Fatalf("no checksums = %v", err)
	}
	bad := &releaseFetcher{base: "http://127.0.0.1:1", client: srv.Client()}
	if _, _, err := bad.open(ctx, "v1", "x"); err == nil {
		t.Fatal("unreachable")
	}
	if _, _, err := (&releaseFetcher{base: "%zz", client: srv.Client()}).open(ctx, "v1", "x"); err == nil {
		t.Fatal("bad URL")
	}
	h := newHarness(t)
	h.env["AEROLVM_RELEASE_URL"] = "https://mirror.example/r/"
	if got := h.app.releaseFetcher(&commonFlags{debug: true}, "").url("v1", "x"); got != "https://mirror.example/r/v1/x" {
		t.Fatal(got)
	}
	h.env["AEROLVM_RELEASE_URL"] = ""
	if got := h.app.releaseFetcher(nil, "").url("v1", "x"); got != defaultReleaseURL+"/v1/x" {
		t.Fatal(got)
	}
}
