package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// `aerolvm release pull` (plans/kubectl-style-cluster-ops.md §7.1, CEO D9):
// one file holding a whole release for sites whose nodes can't reach the
// internet. It runs where the internet is; `aerolvm upgrade apply --from
// <file>.tgz` checks the bundle again and pushes it to the cluster.

const releaseHelp = `Download a release into one file for sites without internet access.

Usage: aerolvm release pull <version> [-o <file>.tgz] [--arch amd64,arm64] [--release-url URL]

pull downloads the release's checksums.txt, then sandboxd, toolboxd and
caddy for every Linux CPU type the release builds (or only --arch), and its
release.json. Each file is checked against checksums.txt as it downloads;
one mismatch stops the pull and nothing is written. The bundle also holds
checksums.txt and the SLSA provenance (<version>.intoto.jsonl) unchanged,
and a manifest.json with every file's SHA-256 and the bundle format.

Take the file to a machine that reaches sandboxd and run:
  aerolvm upgrade apply <version> --from <file>.tgz
apply checks every file in the bundle again before it sends anything, and
refuses a bundle whose files were changed or whose format it does not know.

Flags:
  -o <file>          the bundle to write (default aerolvm-<version>.tgz)
  --arch a,b         only these CPU types, such as amd64,arm64
  --release-url URL  where releases are published (default GitHub;
                     AEROLVM_RELEASE_URL)
  --json             print the manifest

Example:
  aerolvm release pull v0.6.12 -o aerolvm-v0.6.12.tgz
`

func runRelease(ctx context.Context, a *app, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "pull":
		return runReleasePull(ctx, a, args)
	case "":
		return a.usageError(nil, "release", "expected a subcommand: pull")
	}
	return a.usageError(nil, "release", "unknown subcommand %q: expected pull", sub)
}

func runReleasePull(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("release pull")
	var out, archFlag, releaseURL string
	fs.StringVar(&out, "o", "", "")
	fs.StringVar(&out, "output", "", "")
	fs.StringVar(&archFlag, "arch", "", "")
	fs.StringVar(&releaseURL, "release-url", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "release", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "release", "pull needs one version, such as `aerolvm release pull v0.6.12`")
	}
	version := pos[0]
	if !releaseVersionRe.MatchString(version) {
		return a.usageError(c, "release", "%q is not a version", version)
	}
	arches, err := parseArches(archFlag)
	if err != nil {
		return a.usageError(c, "release", "%v", err)
	}
	if out == "" {
		out = "aerolvm-" + version + ".tgz"
	}
	manifest, size, err := a.pullRelease(ctx, a.releaseFetcher(c, releaseURL), version, arches, out)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(manifest)
		return exitOK
	}
	fmt.Fprintf(a.stdout, "wrote %s: %s, %d files, %s (CPU types: %s)\n", out, version, len(manifest.Files), humanBytes(size),
		strings.Join((&releaseSet{files: fileSums(manifest)}).arches(), ", "))
	return exitOK
}

func fileSums(m *bundleManifest) map[string]string {
	out := map[string]string{}
	for _, f := range m.Files {
		out[f.Name] = f.SHA256
	}
	return out
}

// pullRelease downloads version into a temporary directory beside out,
// checks every file, packs the bundle as out.part and renames it to out, so
// out is either a whole checked bundle or absent.
func (a *app) pullRelease(ctx context.Context, f *releaseFetcher, version string, arches []string, out string) (*bundleManifest, int64, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(out), ".aerolvm-pull-*")
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(tmp)

	sumsPath := filepath.Join(tmp, checksumsName)
	if _, err := f.download(ctx, version, checksumsName, sumsPath, "", maxMetaBytes); err != nil {
		return nil, 0, fmt.Errorf("release %s: %w", version, err)
	}
	sumsFile, err := os.Open(sumsPath)
	if err != nil {
		return nil, 0, err
	}
	sums, err := parseChecksums(sumsFile)
	sumsFile.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("release %s: %w", version, err)
	}
	files, err := pickUpgradeFiles(sums, arches)
	if err != nil {
		return nil, 0, fmt.Errorf("release %s: %w", version, err)
	}
	set := &releaseSet{files: files}
	manifest := &bundleManifest{BundleFormat: bundleFormat, Version: version, CreatedAt: a.clock().UTC().Truncate(time.Second)}
	var order []string
	add := func(name string) error {
		sum, size, err := hashFile(filepath.Join(tmp, name))
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, bundleFile{Name: name, SHA256: sum, Size: size})
		order = append(order, name)
		return nil
	}
	if err := add(checksumsName); err != nil {
		return nil, 0, err
	}
	for _, name := range set.sortedFiles() {
		a.note("aerolvm: downloading %s", name)
		if _, err := f.download(ctx, version, name, filepath.Join(tmp, name), files[name], upgradewire.MaxUploadBytes); err != nil {
			return nil, 0, err
		}
		if name == release.FileName {
			if _, err := readMeta(filepath.Join(tmp, name), version); err != nil {
				return nil, 0, err
			}
		}
		if err := add(name); err != nil {
			return nil, 0, err
		}
	}
	// The SLSA provenance is published after checksums.txt is made, so
	// checksums.txt can't name it; it travels unchanged for
	// RELEASE-VERIFICATION.md's check.
	provenance := version + ".intoto.jsonl"
	if _, err := f.download(ctx, version, provenance, filepath.Join(tmp, provenance), "", maxProvenanceBytes); err != nil {
		if !errors.Is(err, errNotPublished) {
			return nil, 0, err
		}
		a.note("aerolvm: warning: %s publishes no %s; the bundle has no provenance to check", version, provenance)
	} else if err := add(provenance); err != nil {
		return nil, 0, err
	}
	size, err := writeBundle(tmp, out, manifest, order)
	if err != nil {
		return nil, 0, err
	}
	return manifest, size, nil
}

// writeBundle packs manifest.json first, then the files in order, streaming
// each from disk.
func writeBundle(dir, out string, manifest *bundleManifest, order []string) (int64, error) {
	part := out + ".part"
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	ok := false
	defer func() {
		if !ok {
			file.Close()
			_ = os.Remove(part)
		}
	}()
	zw := gzip.NewWriter(file)
	tw := tar.NewWriter(zw)
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return 0, err
	}
	raw = append(raw, '\n')
	mod := manifest.CreatedAt
	if err := tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o644, Size: int64(len(raw)), ModTime: mod, Typeflag: tar.TypeReg}); err != nil {
		return 0, err
	}
	if _, err := tw.Write(raw); err != nil {
		return 0, err
	}
	for _, name := range order {
		if err := addTarFile(tw, filepath.Join(dir, name), name, mod); err != nil {
			return 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	if err := file.Sync(); err != nil {
		return 0, err
	}
	fi, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if err := file.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(part, out); err != nil {
		return 0, err
	}
	ok = true
	return fi.Size(), nil
}

func addTarFile(tw *tar.Writer, path, name string, mod time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	mode := int64(0o644)
	if upgradeAssetRe.MatchString(name) {
		mode = 0o755
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: fi.Size(), ModTime: mod, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}
