// Command aerolvmdist packages the aerolvm CLI for Krew and Homebrew
// (plans/kubectl-style-cluster-ops.md §7 and D13). release.yml runs it once
// the aerolvm binaries are in dist/, before the tagged copies and
// checksums.txt, so both cover what it writes:
//
//	go run ./cmd/aerolvmdist -version "$VERSION" -dist dist -repo "$GITHUB_REPOSITORY"
//
// It writes, into -dist:
//
//   - aerolvm_<os>_<arch>.tar.gz for every aerolvm target: the binary as
//     aerolvm (aerolvm.exe on Windows) and LICENSE. Krew installs only from
//     an archive, and Homebrew uses the same ones. The archives are the
//     same bytes on every run (fixed times and owners), so a re-run of the
//     release job hashes the same.
//   - aerolvm.krew.yaml: the Krew plugin manifest, built from those
//     archives' names and SHA-256s. `kubectl krew install
//     --manifest-url=<release URL of it>` installs `kubectl aerolvm`; it is
//     also what a krew-index pull request would carry.
//   - aerolvm.rb: the Homebrew formula (macOS and Linux) the release
//     workflow's homebrew job copies into the tap.
//
// Nothing here is synced by hand: the target list must match release.yml's
// build loop, and the tests check both files against the archives.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// target is one platform release.yml builds aerolvm for.
type target struct{ goos, goarch string }

// targets must match the `for target in ...` loop in release.yml's cli job
// (TestTargetsMatchReleaseWorkflow).
var targets = []target{
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"linux", "amd64"}, {"linux", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

func (t target) exe() string {
	if t.goos == "windows" {
		return "aerolvm.exe"
	}
	return "aerolvm"
}

// binary is the release binary's name in dist/.
func (t target) binary() string {
	name := "aerolvm_" + t.goos + "_" + t.goarch
	if t.goos == "windows" {
		name += ".exe"
	}
	return name
}

func (t target) archive() string { return "aerolvm_" + t.goos + "_" + t.goarch + ".tar.gz" }

// The same tag rule as release.yml, which already refused anything else.
var (
	versionRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

const (
	krewManifestFile = "aerolvm.krew.yaml"
	brewFormulaFile  = "aerolvm.rb"
	// Krew's index caps shortDescription; Homebrew's audit refuses a desc
	// that starts with the formula's name or ends with a period.
	shortDescription = "Manage AerolVM sandboxes and clusters"
	brewDescription  = "Drive AerolVM sandboxes and clusters from a shell or an AI agent"
)

// archiveTime is every archive entry's time: fixed, so the bytes never change.
var archiveTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stderr))
}

func run(args []string, getenv func(string) string, stderr io.Writer) int {
	fs := flag.NewFlagSet("aerolvmdist", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", getenv("VERSION"), "release tag, like v1.2.3 (default $VERSION)")
	dist := fs.String("dist", "dist", "directory holding the aerolvm_<os>_<arch> binaries; output goes here too")
	repo := fs.String("repo", getenv("GITHUB_REPOSITORY"), "GitHub owner/repo the release is published in (default $GITHUB_REPOSITORY)")
	license := fs.String("license", "LICENSE", "license file packed into every archive")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aerolvmdist: unexpected arguments %v\n", fs.Args())
		return 2
	}
	if err := build(*version, *dist, *repo, *license); err != nil {
		fmt.Fprintf(stderr, "aerolvmdist: %v\n", err)
		return 1
	}
	return 0
}

// packaged is one archive written to dist.
type packaged struct {
	target
	url, sha256 string
}

func build(version, dist, repo, license string) error {
	if !versionRE.MatchString(version) {
		return fmt.Errorf("-version must look like v1.2.3, got %q", version)
	}
	if !repoRE.MatchString(repo) {
		return fmt.Errorf("-repo must look like owner/repo, got %q", repo)
	}
	licenseText, err := os.ReadFile(license)
	if err != nil {
		return fmt.Errorf("read license: %w", err)
	}
	base := "https://github.com/" + repo + "/releases/download/" + version + "/"
	var out []packaged
	for _, t := range targets {
		bin, err := os.ReadFile(filepath.Join(dist, t.binary()))
		if err != nil {
			return fmt.Errorf("read the %s binary: %w", t.goos+"/"+t.goarch, err)
		}
		data, err := archive(t.exe(), bin, licenseText)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dist, t.archive()), data, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		out = append(out, packaged{target: t, url: base + t.archive(), sha256: hex.EncodeToString(sum[:])})
	}
	manifest, err := krewManifest(version, repo, out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dist, krewManifestFile), manifest, 0o644); err != nil {
		return err
	}
	formula, err := brewFormula(version, repo, out)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dist, brewFormulaFile), formula, 0o644)
}

// archive is a gzipped tar of the binary (mode 0755) and LICENSE (0644).
func archive(exe string, bin, license []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf) // no name and a zero time in the header
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		mode int64
		data []byte
	}{{exe, 0o755, bin}, {"LICENSE", 0o644, license}} {
		hdr := &tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), ModTime: archiveTime, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// krewPlugin is the Krew v1alpha2 Plugin manifest.
type krewPlugin struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   krewMetadata `yaml:"metadata"`
	Spec       krewSpec     `yaml:"spec"`
}

type krewMetadata struct {
	Name string `yaml:"name"`
}

type krewSpec struct {
	Version          string         `yaml:"version"`
	Homepage         string         `yaml:"homepage"`
	ShortDescription string         `yaml:"shortDescription"`
	Description      string         `yaml:"description"`
	Platforms        []krewPlatform `yaml:"platforms"`
}

type krewPlatform struct {
	Selector struct {
		MatchLabels map[string]string `yaml:"matchLabels"`
	} `yaml:"selector"`
	URI    string     `yaml:"uri"`
	SHA256 string     `yaml:"sha256"`
	Files  []krewFile `yaml:"files"`
	Bin    string     `yaml:"bin"`
}

type krewFile struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

func krewManifest(version, repo string, out []packaged) ([]byte, error) {
	p := krewPlugin{
		APIVersion: "krew.googlecontainertools.github.com/v1alpha2",
		Kind:       "Plugin",
		Metadata:   krewMetadata{Name: "aerolvm"},
		Spec: krewSpec{
			Version:          version,
			Homepage:         "https://github.com/" + repo,
			ShortDescription: shortDescription,
			Description: "kubectl aerolvm runs the aerolvm CLI: get, describe and delete\n" +
				"sandboxes, snapshots, tokens and nodes of an AerolVM cluster, cordon\n" +
				"and drain nodes, and exec or open a shell in a sandbox. It is the same\n" +
				"binary as aerolvm and talks to sandboxd's API, not to Kubernetes.\n",
		},
	}
	for _, o := range out {
		var pl krewPlatform
		pl.Selector.MatchLabels = map[string]string{"os": o.goos, "arch": o.goarch}
		pl.URI, pl.SHA256, pl.Bin = o.url, o.sha256, o.exe()
		pl.Files = []krewFile{{From: o.exe(), To: "."}, {From: "LICENSE", To: "."}}
		p.Spec.Platforms = append(p.Spec.Platforms, pl)
	}
	var buf bytes.Buffer
	buf.WriteString("# Generated by cmd/aerolvmdist for " + version + ". Do not edit.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

var formulaTemplate = template.Must(template.New("formula").Parse(`# Generated by cmd/aerolvmdist for {{.Tag}}. Do not edit.
class Aerolvm < Formula
  desc "{{.Desc}}"
  homepage "{{.Homepage}}"
  version "{{.Version}}"
  license "MIT"
{{range .OS}}
  on_{{.Name}} do
    on_arm do
      url "{{.Arm.URL}}"
      sha256 "{{.Arm.SHA256}}"
    end
    on_intel do
      url "{{.Intel.URL}}"
      sha256 "{{.Intel.SHA256}}"
    end
  end
{{end}}
  def install
    bin.install "aerolvm"
  end

  test do
    assert_equal "v#{version}", shell_output("#{bin}/aerolvm version").strip
  end
end
`))

type brewAsset struct{ URL, SHA256 string }

type brewOS struct {
	Name       string // Homebrew's word: macos, linux
	Arm, Intel brewAsset
}

// brewFormula covers macOS and Linux; Homebrew has no Windows.
func brewFormula(version, repo string, out []packaged) ([]byte, error) {
	byTarget := map[target]brewAsset{}
	for _, o := range out {
		byTarget[o.target] = brewAsset{URL: o.url, SHA256: o.sha256}
	}
	var oses []brewOS
	for _, p := range []struct{ goos, word string }{{"darwin", "macos"}, {"linux", "linux"}} {
		arm, okArm := byTarget[target{p.goos, "arm64"}]
		intel, okIntel := byTarget[target{p.goos, "amd64"}]
		if !okArm || !okIntel {
			return nil, fmt.Errorf("no %s archive for both arm64 and amd64", p.goos)
		}
		oses = append(oses, brewOS{Name: p.word, Arm: arm, Intel: intel})
	}
	var buf bytes.Buffer
	err := formulaTemplate.Execute(&buf, map[string]any{
		"Tag": version, "Version": strings.TrimPrefix(version, "v"), "Desc": brewDescription,
		"Homepage": "https://github.com/" + repo, "OS": oses,
	})
	return buf.Bytes(), err
}
