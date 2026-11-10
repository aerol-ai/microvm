package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const setupDir = "../../setup"

func untar(t *testing.T, data []byte) (map[string][]byte, []*tar.Header) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	var hdrs []*tar.Header
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, hdrs
		}
		if err != nil {
			t.Fatal(err)
		}
		hdrs = append(hdrs, h)
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			files[h.Name] = b
		}
	}
}

// The bundle carries what setup/ has: every alert rule file, Alertmanager
// config, dashboard and runbook, byte for byte, and nothing that is not in
// setup/. The globs here are written out on their own, so a file type the
// walk in opsFiles stops picking up fails this test.
func TestBundleCarriesWhatSetupHas(t *testing.T) {
	files, err := opsFiles(setupDir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := build(setupDir, "v9.9.9", files, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := untar(t, data)
	const top = "aerolvm-ops-v9.9.9/"
	if string(got[top+"VERSION"]) != "v9.9.9\n" {
		t.Fatalf("VERSION = %q", got[top+"VERSION"])
	}
	for _, pattern := range []string{"prometheus/*.yml", "alertmanager/*.yml", "grafana/*.json", "runbooks/*.md"} {
		matches, err := filepath.Glob(filepath.Join(setupDir, pattern))
		if err != nil || len(matches) == 0 {
			t.Fatalf("setup/%s matches nothing (%v); the check would pass vacuously", pattern, err)
		}
		for _, m := range matches {
			rel, _ := filepath.Rel(setupDir, m)
			if _, ok := got[top+filepath.ToSlash(rel)]; !ok {
				t.Errorf("the bundle lacks setup/%s", rel)
			}
		}
	}
	for name, body := range got {
		rel := strings.TrimPrefix(name, top)
		if rel == "VERSION" {
			continue
		}
		disk, err := os.ReadFile(filepath.Join(setupDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("the bundle has %s, which setup/ does not: %v", rel, err)
			continue
		}
		if !bytes.Equal(disk, body) {
			t.Errorf("%s differs from setup/%s", name, rel)
		}
		if strings.HasSuffix(rel, ".go") || strings.Contains(rel, "/fixtures/") {
			t.Errorf("the bundle ships the test file %s", rel)
		}
	}
	if len(got) != len(files)+1 {
		t.Errorf("the bundle has %d files, want %d", len(got), len(files)+1)
	}
}

// The same tree gives the same bytes, so checksums.txt is stable across
// re-runs of the release job.
func TestBundleIsReproducible(t *testing.T) {
	files, err := opsFiles(setupDir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := build(setupDir, "v1", files, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := build(setupDir, "v1", files, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two builds of one tree differ")
	}
	_, hdrs := untar(t, a)
	var names []string
	for _, h := range hdrs {
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(time.Unix(1700000000, 0)) {
			t.Errorf("%s: uid %d gid %d time %v", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		if (h.Typeflag == tar.TypeDir) != (h.Mode == 0o755) {
			t.Errorf("%s mode %o", h.Name, h.Mode)
		}
	}
	// Each directory comes before what it holds.
	seen := map[string]bool{}
	for _, n := range names {
		if d := filepath.Dir(strings.TrimSuffix(n, "/")); d != "." && !seen[d+"/"] {
			t.Errorf("%s comes before its directory", n)
		}
		seen[n] = true
	}
}

func TestOpsFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		"prometheus/rules.yml", "prometheus/alerts_test.go", "alertmanager/am.yml", "grafana/d.json",
		"grafana/fixtures/known.txt", "grafana/testdata/x.json", "grafana/.hidden/y.json", "grafana/.DS_Store",
		"runbooks/a.md", "runbooks/sub/b.md", "obs/not-shipped.yml",
	} {
		write(f)
	}
	got, err := opsFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alertmanager/am.yml", "grafana/d.json", "prometheus/rules.yml", "runbooks/a.md", "runbooks/sub/b.md"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("opsFiles = %v, want %v", got, want)
	}
	if err := os.RemoveAll(filepath.Join(dir, "alertmanager")); err != nil {
		t.Fatal(err)
	}
	if _, err := opsFiles(dir); err == nil {
		t.Fatal("a missing ops directory was not an error")
	}
	if err := os.MkdirAll(filepath.Join(dir, "alertmanager"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := opsFiles(dir); err == nil || !strings.Contains(err.Error(), "no files to ship") {
		t.Fatalf("an empty ops directory: %v", err)
	}
	if _, err := build(dir, "v1", nil, time.Unix(0, 0)); err == nil {
		t.Fatal("built an empty bundle")
	}
	if _, err := build(dir, "v1", []string{"runbooks/gone.md"}, time.Unix(0, 0)); err == nil {
		t.Fatal("built a bundle with a missing file")
	}
}

func TestRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ops.tgz")
	env := func(k string) string {
		return map[string]string{"VERSION": "v0.6.12", "SOURCE_DATE_EPOCH": "1700000000"}[k]
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-setup", setupDir, "-o", out}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	files, hdrs := untar(t, data)
	if string(files["aerolvm-ops-v0.6.12/VERSION"]) != "v0.6.12\n" || !hdrs[0].ModTime.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("VERSION %q, time %v", files["aerolvm-ops-v0.6.12/VERSION"], hdrs[0].ModTime)
	}
	if !strings.Contains(stdout.String(), "wrote "+out) {
		t.Errorf("stdout: %s", stdout.String())
	}

	// The default name, written in the working directory.
	wd, _ := os.Getwd()
	setupAbs, _ := filepath.Abs(setupDir)
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if code := run([]string{"-setup", setupAbs, "-version", "v1"}, func(string) string { return "" }, io.Discard, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, "aerolvm-ops-v1.tar.gz")); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	if code := run([]string{"-setup", setupAbs, "-list"}, func(string) string { return "" }, &stdout, io.Discard); code != 0 {
		t.Fatalf("-list exit %d", code)
	}
	listed := strings.Fields(stdout.String())
	if !sort.StringsAreSorted(listed) || len(listed) == 0 || !strings.Contains(stdout.String(), "runbooks/lost-quorum-recovery.md") {
		t.Fatalf("-list:\n%s", stdout.String())
	}

	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"-setup", setupAbs}, 2},
		{[]string{"-bogus"}, 2},
		{[]string{"extra"}, 2},
		{[]string{"-setup", filepath.Join(tmp, "none"), "-version", "v1"}, 1},
		{[]string{"-setup", setupAbs, "-version", "v1", "-o", filepath.Join(tmp, "no", "dir", "x.tgz")}, 1},
	} {
		if code := run(tc.args, func(string) string { return "" }, io.Discard, io.Discard); code != tc.code {
			t.Errorf("%v: exit %d, want %d", tc.args, code, tc.code)
		}
	}
	if got := sourceDateEpoch(func(string) string { return "nope" }); got != 0 {
		t.Errorf("sourceDateEpoch(nope) = %d", got)
	}
}
