package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const placementRecoveryRefPrefix = "recovery:v1:"

type placementRecoveryStore interface {
	Put(sandboxID string, rec placementRecovery) (string, error)
	Get(ref string) (placementRecovery, bool, error)
	Delete(ref string) error
}

type placementRecoveryStoreRecord struct {
	SandboxID string            `json:"sandbox_id"`
	Recovery  placementRecovery `json:"recovery"`
}

func newPlacementFSMWithFileRecovery(raftDataDir string) (*placementFSM, error) {
	if strings.TrimSpace(raftDataDir) == "" {
		return newPlacementFSM(), nil
	}
	store, err := newPlacementRecoveryFileStore(filepath.Join(raftDataDir, "recovery"))
	if err != nil {
		return nil, err
	}
	return newPlacementFSMWithRecoveryStore(store), nil
}

type placementRecoveryFileStore struct {
	dir string
}

func newPlacementRecoveryFileStore(dir string) (*placementRecoveryFileStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("placement recovery store: empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("placement recovery store: mkdir: %w", err)
	}
	return &placementRecoveryFileStore{dir: dir}, nil
}

func (s *placementRecoveryFileStore) Put(sandboxID string, rec placementRecovery) (string, error) {
	if strings.TrimSpace(sandboxID) == "" {
		return "", errors.New("placement recovery store: empty sandbox id")
	}
	record := placementRecoveryStoreRecord{
		SandboxID: sandboxID,
		Recovery:  clonePlacementRecovery(rec),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("placement recovery store: marshal: %w", err)
	}
	sum := sha256.Sum256(payload)
	ref := placementRecoveryRefPrefix + hex.EncodeToString(sum[:])
	path, err := s.pathForRef(ref)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", fmt.Errorf("placement recovery store: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-recovery-*")
	if err != nil {
		return "", fmt.Errorf("placement recovery store: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("placement recovery store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("placement recovery store: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("placement recovery store: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("placement recovery store: rename: %w", err)
	}
	return ref, nil
}

func (s *placementRecoveryFileStore) Get(ref string) (placementRecovery, bool, error) {
	path, err := s.pathForRef(ref)
	if err != nil {
		return placementRecovery{}, false, err
	}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return placementRecovery{}, false, nil
	}
	if err != nil {
		return placementRecovery{}, false, fmt.Errorf("placement recovery store: read: %w", err)
	}
	var record placementRecoveryStoreRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return placementRecovery{}, false, fmt.Errorf("placement recovery store: decode: %w", err)
	}
	return clonePlacementRecovery(record.Recovery), true, nil
}

func (s *placementRecoveryFileStore) Delete(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return nil
	}
	path, err := s.pathForRef(ref)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("placement recovery store: delete: %w", err)
	}
	return nil
}

func (s *placementRecoveryFileStore) pathForRef(ref string) (string, error) {
	sum := strings.TrimPrefix(ref, placementRecoveryRefPrefix)
	if sum == ref || len(sum) != sha256.Size*2 {
		return "", fmt.Errorf("placement recovery store: invalid ref %q", ref)
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", fmt.Errorf("placement recovery store: invalid ref %q: %w", ref, err)
	}
	return filepath.Join(s.dir, sum+".json"), nil
}

type placementRecoveryMemoryStore struct {
	mu   sync.RWMutex
	rows map[string]placementRecovery
}

func newPlacementRecoveryMemoryStore() *placementRecoveryMemoryStore {
	return &placementRecoveryMemoryStore{rows: make(map[string]placementRecovery)}
}

func (s *placementRecoveryMemoryStore) Put(sandboxID string, rec placementRecovery) (string, error) {
	if strings.TrimSpace(sandboxID) == "" {
		return "", errors.New("placement recovery store: empty sandbox id")
	}
	record := placementRecoveryStoreRecord{
		SandboxID: sandboxID,
		Recovery:  clonePlacementRecovery(rec),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("placement recovery store: marshal: %w", err)
	}
	sum := sha256.Sum256(payload)
	ref := placementRecoveryRefPrefix + hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[ref] = clonePlacementRecovery(rec)
	return ref, nil
}

func (s *placementRecoveryMemoryStore) Get(ref string) (placementRecovery, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.rows[ref]
	if !ok {
		return placementRecovery{}, false, nil
	}
	return clonePlacementRecovery(rec), true, nil
}

func (s *placementRecoveryMemoryStore) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, ref)
	return nil
}
