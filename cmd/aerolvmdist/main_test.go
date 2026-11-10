package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const repoRoot = "../.."

// fakeDist writes a stand-in binary for every target and a license, and
// returns the dist directory and the license path.
func fakeDist(t *testing.T) (string, string) {
	t.Helper()
	dist := t.TempDir()
	for _, tg := range targets {
		if err := os.WriteFile(filepath.Join(dist, tg.binary()), []byte("binary for "+tg.goos+"/"+tg.goarch), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	license := filepath.Join(t.TempDir(), "LICENSE")
	if err := os.WriteFile(license, []byte("MIT License\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dist, license
}

func sha(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestBuildWritesArchivesManifestAndFormula(t *testing.T) {
	dist, license := fakeDist(t)
	var stderr bytes.Buffer
	if code := run([]string{"-version", "v1.2.3", "-dist", dist, "-repo", "aerol-ai/microvm", "-license", license}, func(string) string { return "" }, &stderr); code != 0 {
		t.Fatalf("run = %d: %s", code, stderr.String())
	}

	// Every archive holds exactly the binary (0755) and LICENSE (0644).
	for _, tg := range targets {
		entries := readArchive(t, filepath.Join(dist, tg.archive()))
		if len(entries) != 2 || entries[0].name != tg.exe() || entries[0].mode != 0o755 || entries[0].body != "binary for "+tg.goos+"/"+tg.goarch ||
			entries[1].name != "LICENSE" || entries[1].mode != 0o644 || entries[1].body != "MIT License\n" {
			t.Fatalf("%s holds %+v", tg.archive(), entries)
		}
	}

	// The Krew manifest names each archive by its release URL and hash.
	raw, err := os.ReadFile(filepath.Join(dist, krewManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var plugin krewPlugin
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&plugin); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if plugin.APIVersion != "krew.googlecontainertools.github.com/v1alpha2" || plugin.Kind != "Plugin" || plugin.Metadata.Name != "aerolvm" ||
		plugin.Spec.Version != "v1.2.3" || len(plugin.Spec.ShortDescription) > 50 || plugin.Spec.Description == "" {
		t.Fatalf("manifest = %+v", plugin)
	}
	if len(plugin.Spec.Platforms) != len(targets) {
		t.Fatalf("platforms = %d, want %d", len(plugin.Spec.Platforms), len(targets))
	}
	for i, tg := range targets {
		p := plugin.Spec.Platforms[i]
		want := "https://github.com/aerol-ai/microvm/releases/download/v1.2.3/" + tg.archive()
		if p.Selector.MatchLabels["os"] != tg.goos || p.Selector.MatchLabels["arch"] != tg.goarch || p.URI != want ||
			p.SHA256 != sha(t, filepath.Join(dist, tg.archive())) || p.Bin != tg.exe() ||
			!slices.Equal(p.Files, []krewFile{{From: tg.exe(), To: "."}, {From: "LICENSE", To: "."}}) {
			t.Fatalf("platform %d = %+v", i, p)
		}
	}

	// The formula names the macOS and Linux archives by URL and hash, and
	// never Windows.
	formula, err := os.ReadFile(filepath.Join(dist, brewFormulaFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range targets {
		url := "https://github.com/aerol-ai/microvm/releases/download/v1.2.3/" + tg.archive()
		pair := "url \"" + url + "\"\n      sha256 \"" + sha(t, filepath.Join(dist, tg.archive())) + "\""
		if got := strings.Contains(string(formula), pair); got != (tg.goos != "windows") {
			t.Errorf("formula has %s = %v", tg.archive(), got)
		}
	}
	if !strings.Contains(string(formula), `version "1.2.3"`) || !strings.Contains(string(formula), `bin.install "aerolvm"`) {
		t.Fatalf("formula:\n%s", formula)
	}

	// The same inputs give the same bytes, so a re-run hashes the same.
	first := sha(t, filepath.Join(dist, targets[0].archive()))
	if code := run([]string{"-version", "v1.2.3", "-dist", dist, "-repo", "aerol-ai/microvm", "-license", license}, func(string) string { return "" }, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if again := sha(t, filepath.Join(dist, targets[0].archive())); again != first {
		t.Fatalf("archive changed between runs: %s then %s", first, again)
	}
}

// The manifest and formula for fixed archives, as golden files: a reviewer
// sees exactly what Krew and Homebrew get.
func TestManifestAndFormulaGolden(t *testing.T) {
	var out []packaged
	for i, tg := range targets {
		out = append(out, packaged{target: tg, url: "https://github.com/aerol-ai/microvm/releases/download/v0.7.0/" + tg.archive(),
			sha256: strings.Repeat(string(rune('a'+i)), 64)})
	}
	manifest, err := krewManifest("v0.7.0", "aerol-ai/microvm", out)
	if err != nil {
		t.Fatal(err)
	}
	formula, err := brewFormula("v0.7.0", "aerol-ai/microvm", out)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"aerolvm.krew.yaml": manifest, "aerolvm.rb": formula} {
		path := filepath.Join("testdata", name+".golden")
		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden (run with -update): %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed; review and run with -update:\n--- got\n%s--- want\n%s", name, got, want)
		}
	}
	if _, err := brewFormula("v0.7.0", "aerol-ai/microvm", out[:1]); err == nil {
		t.Fatal("a formula without both macOS archives was written")
	}
}

func TestRunRefusesBadInput(t *testing.T) {
	dist, license := fakeDist(t)
	env := func(k string) string {
		return map[string]string{"VERSION": "v2.0.0", "GITHUB_REPOSITORY": "aerol-ai/microvm"}[k]
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-dist", dist, "-license", license}, 0, ""},
		{[]string{"-dist", dist, "-license", license, "-version", "1.2.3"}, 1, "-version must look like v1.2.3"},
		{[]string{"-dist", dist, "-license", license, "-version", "v1.2.3;rm"}, 1, "-version must look like"},
		{[]string{"-dist", dist, "-license", license, "-repo", "evil repo"}, 1, "-repo must look like owner/repo"},
		{[]string{"-dist", dist, "-license", filepath.Join(dist, "nope")}, 1, "read license"},
		{[]string{"-dist", t.TempDir(), "-license", license}, 1, "read the darwin/amd64 binary"},
		{[]string{"-dist", filepath.Join(dist, "aerolvm_linux_amd64"), "-license", license}, 1, "read the darwin/amd64 binary"},
		{[]string{"-nope"}, 2, "flag provided but not defined"},
		{[]string{"extra"}, 2, "unexpected arguments"},
	} {
		var stderr bytes.Buffer
		if code := run(tc.args, env, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("run %v = %d %q, want %d %q", tc.args, code, stderr.String(), tc.code, tc.want)
		}
	}
	// $VERSION and $GITHUB_REPOSITORY are the defaults.
	if b, err := os.ReadFile(filepath.Join(dist, krewManifestFile)); err != nil || !strings.Contains(string(b), "version: v2.0.0") {
		t.Fatalf("defaults: %v\n%s", err, b)
	}
	// A dist the archives can't be written to fails cleanly.
	ro := t.TempDir()
	for _, tg := range targets {
		if err := os.WriteFile(filepath.Join(ro, tg.binary()), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(ro, targets[0].archive()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := build("v1.0.0", ro, "a/b", license); err == nil {
		t.Fatal("writing over a directory succeeded")
	}
	if err := os.Remove(filepath.Join(ro, targets[0].archive())); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{krewManifestFile, brewFormulaFile} {
		if err := os.Mkdir(filepath.Join(ro, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := build("v1.0.0", ro, "a/b", license); err == nil {
			t.Fatalf("writing %s over a directory succeeded", name)
		}
		if err := os.Remove(filepath.Join(ro, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// targets is the list release.yml's cli job builds; npm, Krew and Homebrew
// all read the binaries it makes.
func TestTargetsMatchReleaseWorkflow(t *testing.T) {
	wf := releaseWorkflow(t)
	loop := regexp.MustCompile(`for target in ([a-z0-9/ ]+); do`).FindStringSubmatch(wf)
	if loop == nil {
		t.Fatal("release.yml has no `for target in ...; do` loop building aerolvm")
	}
	var want []string
	for _, tg := range targets {
		want = append(want, tg.goos+"/"+tg.goarch)
	}
	got := strings.Fields(loop[1])
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("release.yml builds %v, aerolvmdist packages %v", got, want)
	}
}

// release.yml runs the generator in the release job, after the aerolvm
// binaries are downloaded into dist/ and before the tagged copies and
// checksums.txt, so the archives, the manifest and the formula are covered
// by both; and the Homebrew job is gated on that job, an opt-in variable
// and a stable release.
func TestReleaseWorkflowPackagesForKrewAndHomebrew(t *testing.T) {
	wf := releaseWorkflow(t)
	gen := strings.Index(wf, "go run ./cmd/aerolvmdist")
	if gen < 0 {
		t.Fatal("release.yml never runs ./cmd/aerolvmdist")
	}
	line := wf[gen : gen+strings.IndexByte(wf[gen:], '\n')]
	for _, want := range []string{`-version "$VERSION"`, "-dist dist", `-repo "$GITHUB_REPOSITORY"`} {
		if !strings.Contains(line, want) {
			t.Errorf("release.yml runs %q without %s", line, want)
		}
	}
	download := strings.Index(wf, "name: Download all build artifacts")
	tagged := strings.Index(wf, `cp "$asset" "${VERSION}_${asset}"`)
	sums := strings.Index(wf, "sha256sum * > checksums.txt")
	if download < 0 || tagged < 0 || sums < 0 {
		t.Fatalf("release.yml lost the download (%d), tagged-copy (%d) or checksums (%d) step; this guard needs updating", download, tagged, sums)
	}
	if gen < download || gen > tagged || gen > sums {
		t.Error("aerolvmdist must run after the binaries are downloaded and before the tagged copies and checksums.txt")
	}

	var doc struct {
		Jobs map[string]struct {
			Needs any    `yaml:"needs"`
			If    string `yaml:"if"`
			Steps []struct {
				Name string            `yaml:"name"`
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(wf), &doc); err != nil {
		t.Fatalf("release.yml is not YAML: %v", err)
	}
	inRelease := false
	for _, s := range doc.Jobs["release"].Steps {
		if strings.Contains(s.Run, "go run ./cmd/aerolvmdist") {
			inRelease = true
		}
	}
	if !inRelease {
		t.Error("aerolvmdist runs outside the release job, which is the one that publishes dist/")
	}
	brew, ok := doc.Jobs["homebrew"]
	if !ok {
		t.Fatal("release.yml has no homebrew job")
	}
	if brew.Needs != "release" {
		t.Errorf("homebrew needs %v, want release (the formula comes from the published release)", brew.Needs)
	}
	for _, want := range []string{"vars.AEROLVM_HOMEBREW_TAP != ''", "!github.event.release.prerelease"} {
		if !strings.Contains(brew.If, want) {
			t.Errorf("homebrew job runs when %q, missing %q", brew.If, want)
		}
	}
	var script strings.Builder
	for _, s := range brew.Steps {
		script.WriteString(s.Run)
		if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["token"] != "${{ secrets.HOMEBREW_TAP_TOKEN }}" {
			t.Errorf("the tap checkout uses token %q", s.With["token"])
		}
	}
	for _, want := range []string{"gh release download \"$VERSION\" --pattern aerolvm.rb", "cp formula/aerolvm.rb tap/Formula/aerolvm.rb", "git push", `"$newest" != "$VERSION"`} {
		if !strings.Contains(script.String(), want) {
			t.Errorf("homebrew job does not %q", want)
		}
	}
}

func releaseWorkflow(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type entry struct {
	name string
	mode int64
	body string
}

func readArchive(t *testing.T, path string) []entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []entry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.ModTime.IsZero() || !hdr.ModTime.Equal(archiveTime) || hdr.Uid != 0 || hdr.Gid != 0 {
			t.Fatalf("%s: entry %s has time %s, uid %d, gid %d", path, hdr.Name, hdr.ModTime, hdr.Uid, hdr.Gid)
		}
		body, _ := io.ReadAll(tr)
		out = append(out, entry{name: hdr.Name, mode: hdr.Mode, body: string(body)})
	}
}
