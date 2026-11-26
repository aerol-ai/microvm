package kubepod

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// specStore keeps each sandbox's pod as the worker made it, one JSON file
// per pod name, on the worker's state volume. A stopped sandbox has no pod
// (Stop deletes it), so this file is what Start makes the pod again from,
// and what tells Inspect a stopped sandbox from one that is gone. It holds
// nothing secret: neither does the pod (plan D8).
type specStore struct {
	dir string
}

func newSpecStore(dir string) (*specStore, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("kubepod: the spec folder must be an absolute path, got %q", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("kubepod: spec folder: %w", err)
	}
	return &specStore{dir: dir}, nil
}

const specSuffix = ".json"

func (s *specStore) path(name string) string {
	return filepath.Join(s.dir, name+specSuffix)
}

// put writes p under its name, all at once: a crash leaves the old file or
// the new one, never half of one.
func (s *specStore) put(p *Pod) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".spec-*")
	if err != nil {
		return fmt.Errorf("kubepod: keep spec: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("kubepod: keep spec: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("kubepod: keep spec: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("kubepod: keep spec: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path(p.Metadata.Name)); err != nil {
		return fmt.Errorf("kubepod: keep spec: %w", err)
	}
	return nil
}

// get reads the kept pod of name; a missing one is fs.ErrNotExist.
func (s *specStore) get(name string) (*Pod, error) {
	raw, err := os.ReadFile(s.path(name))
	if err != nil {
		return nil, err
	}
	var p Pod
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("kubepod: kept spec %s: %w", name, err)
	}
	return &p, nil
}

func (s *specStore) has(name string) (bool, error) {
	_, err := os.Stat(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// remove forgets name. Forgetting a name with no file is not an error.
func (s *specStore) remove(name string) error {
	err := os.Remove(s.path(name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("kubepod: forget spec: %w", err)
	}
	return nil
}

// list returns every kept pod.
func (s *specStore) list() ([]*Pod, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("kubepod: spec folder: %w", err)
	}
	var out []*Pod
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), specSuffix)
		if !ok || e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p, err := s.get(name)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
