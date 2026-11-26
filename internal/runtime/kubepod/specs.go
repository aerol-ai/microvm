package kubepod

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
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

// list returns every kept pod, and the names of the files that could not
// be read. One damaged file must not hide every other sandbox: the caller
// lists the rest, and a sandbox whose file is damaged answers Inspect with
// an error (unknown), never "gone", so reconcile keeps its row.
func (s *specStore) list() (pods []*Pod, bad []string, err error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, nil, fmt.Errorf("kubepod: spec folder: %w", err)
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), specSuffix)
		if !ok || e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p, err := s.get(name)
		if err != nil {
			bad = append(bad, name)
			continue
		}
		pods = append(pods, p)
	}
	return pods, bad, nil
}

// sandboxRequestOf reads back, from a pod renderPod made, the sandbox's own
// create inputs: its ID and runtime (annotations), and its image, command,
// size and no-root rule (the sandbox container). Anything it cannot read
// exactly as renderPod writes it is an error, never a guess.
func sandboxRequestOf(p *Pod) (models.CreateSandboxRequest, string, error) {
	var req models.CreateSandboxRequest
	id := p.Metadata.Annotations[AnnotationSandboxID]
	req.Runtime = p.Metadata.Annotations[AnnotationRuntime]
	if id == "" || req.Runtime == "" {
		return req, "", errors.New("it has no sandbox ID or runtime annotation")
	}
	var c *Container
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == sandboxContainer {
			c = &p.Spec.Containers[i]
		}
	}
	if c == nil || c.Resources == nil {
		return req, "", errors.New("it has no sandbox container with resources")
	}
	req.Image = c.Image
	req.ContainerCommand = c.Args
	limits := c.Resources.Limits
	milli, err := quantityInt(limits["cpu"], "m")
	if err != nil {
		return req, "", fmt.Errorf("cpu: %w", err)
	}
	req.CPU = float64(milli) / 1000
	if req.MemoryMB, err = quantityInt(limits["memory"], "Mi"); err != nil {
		return req, "", fmt.Errorf("memory: %w", err)
	}
	if disk, ok := limits["ephemeral-storage"]; ok {
		if req.DiskGB, err = quantityInt(disk, "Gi"); err != nil {
			return req, "", fmt.Errorf("ephemeral-storage: %w", err)
		}
	}
	if sc := c.SecurityContext; sc != nil && sc.RunAsNonRoot != nil {
		req.RequireNonRootUser = *sc.RunAsNonRoot
	}
	return req, id, nil
}

// quantityInt reads a positive whole quantity with exactly unit, the way
// renderPod writes it ("1500m", "512Mi", "4Gi").
func quantityInt(q, unit string) (int, error) {
	num, ok := strings.CutSuffix(q, unit)
	if !ok {
		return 0, fmt.Errorf("%q is not in %s", q, unit)
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%q is not a positive whole number of %s", q, unit)
	}
	return n, nil
}
