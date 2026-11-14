// Package movebundle writes and reads the files a sandbox takes to another
// worker when it moves with its memory (plans/kubernetes-v2-architecture.md
// §10.5): a tar stream of regular files. The cluster seals the stream for
// the one target and incarnation (pkg/secrets.NewSealWriter), so this
// format only has to refuse what a move never sends: links, devices,
// names outside the set, a file twice.
package movebundle

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestName is the first entry of a WriteDir stream.
const ManifestName = "manifest.json"

const (
	manifestVersion = 1
	// maxManifest and maxFiles bound what a reader accepts before it
	// writes anything: a checkpoint is a handful of files.
	maxManifest = 1 << 20
	maxFiles    = 64
)

// Manifest lists a WriteDir stream's files.
type Manifest struct {
	Version   int      `json:"version"`
	SandboxID string   `json:"sandbox_id"`
	Files     []string `json:"files"`
}

// Inside is dir's child name, refusing a name that would leave dir. The
// names a move uses are checked already (a sandbox ID's charset, the
// manifest's names), but they arrive from another worker, and this is the
// check code scanning recognizes (go/path-injection, go/zipslip).
func Inside(dir, name string) (string, error) {
	// The checked value is the one returned: code scanning trusts only it.
	p := filepath.Clean(filepath.Join(dir, name))
	if !strings.HasPrefix(p, filepath.Clean(dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is not a name inside %s", name, dir)
	}
	return p, nil
}

// AddFile appends the regular file at path to tw as name.
func AddFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), Typeflag: tar.TypeReg, ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// CreateFile writes r to a new file at path, synced before it returns.
func CreateFile(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// WriteDir writes every file of dir to w: a manifest naming sandboxID and
// the files, then the files. dir holds regular files only.
func WriteDir(ctx context.Context, w io.Writer, dir, sandboxID string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	m := Manifest{Version: manifestVersion, SandboxID: sandboxID}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", e.Name())
		}
		if e.Name() == ManifestName {
			return fmt.Errorf("%s holds a file named %s", dir, ManifestName)
		}
		m.Files = append(m.Files, e.Name())
	}
	if len(m.Files) == 0 || len(m.Files) > maxFiles {
		return fmt.Errorf("%s holds %d files", dir, len(m.Files))
	}
	sort.Strings(m.Files)
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(raw); err != nil {
		return err
	}
	for _, name := range m.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := AddFile(tw, filepath.Join(dir, name), name); err != nil {
			return err
		}
	}
	return tw.Close()
}

// ReadDir reads a WriteDir stream for sandboxID into dir, an empty
// directory: the manifest first, then exactly the files it names. On an
// error dir may hold part of the stream; the caller removes it.
func ReadDir(ctx context.Context, r io.Reader, dir, sandboxID string) (*Manifest, error) {
	tr := tar.NewReader(r)
	h, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("no manifest: %w", err)
	}
	if h.Name != ManifestName || h.Typeflag != tar.TypeReg || h.Size > maxManifest {
		return nil, fmt.Errorf("the manifest must come first, got %q", h.Name)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(tr, maxManifest)).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode the manifest: %w", err)
	}
	if err := m.check(sandboxID); err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(m.Files))
	for _, name := range m.Files {
		want[name] = true
	}
	got := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch {
		case h.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("%q is not a regular file", h.Name)
		case !want[h.Name]:
			return nil, fmt.Errorf("%q is not in the manifest", h.Name)
		case got[h.Name]:
			return nil, fmt.Errorf("%q sent twice", h.Name)
		}
		path, err := Inside(dir, h.Name)
		if err != nil {
			return nil, err
		}
		if err := CreateFile(path, tr); err != nil {
			return nil, err
		}
		got[h.Name] = true
	}
	for _, name := range m.Files {
		if !got[name] {
			return nil, fmt.Errorf("%s missing", name)
		}
	}
	return &m, nil
}

func (m *Manifest) check(sandboxID string) error {
	switch {
	case m.Version != manifestVersion:
		return fmt.Errorf("manifest version %d is unsupported", m.Version)
	case m.SandboxID != sandboxID:
		return fmt.Errorf("the manifest belongs to %q", m.SandboxID)
	case len(m.Files) == 0 || len(m.Files) > maxFiles:
		return fmt.Errorf("the manifest names %d files", len(m.Files))
	}
	seen := map[string]bool{}
	for _, name := range m.Files {
		if name == "" || name == "." || name == ".." || name == ManifestName ||
			strings.ContainsAny(name, `/\`) || filepath.Base(name) != name || seen[name] {
			return fmt.Errorf("the manifest names %q", name)
		}
		seen[name] = true
	}
	return nil
}
