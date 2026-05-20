package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const placementRecoveryRefPrefix = "recovery:v1:"
const placementRecoverySnapshotRefSets = 3

type placementRecoveryStore interface {
	Put(sandboxID string, rec placementRecovery) (string, error)
	Get(ref string) (placementRecovery, bool, error)
	GetRecord(ref string) (placementRecoveryStoreRecord, bool, error)
	Delete(ref string) error
	RetainSnapshotRefs(refs []string) error
}

type placementRecoveryStoreRecord struct {
	SandboxID string            `json:"sandbox_id"`
	Recovery  placementRecovery `json:"recovery"`
}

type RecoveryBlob struct {
	Ref           string                       `json:"ref"`
	SandboxID     string                       `json:"sandbox_id"`
	Spec          *models.CreateSandboxRequest `json:"spec,omitempty"`
	SecretRef     string                       `json:"secret_ref,omitempty"`
	SecretVersion int                          `json:"secret_version,omitempty"`
	SealedSecrets []byte                       `json:"sealed_secrets,omitempty"`
}

type placementRecoveryGCManifest struct {
	Snapshots []placementRecoverySnapshotRefs `json:"snapshots"`
}

type placementRecoverySnapshotRefs struct {
	CreatedUnix int64    `json:"created_unix"`
	Refs        []string `json:"refs"`
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

func newRecoveryBlob(sandboxID string, rec placementRecovery) (RecoveryBlob, error) {
	record := placementRecoveryStoreRecord{
		SandboxID: sandboxID,
		Recovery:  clonePlacementRecovery(rec),
	}
	ref, _, err := encodePlacementRecoveryRecord(record)
	if err != nil {
		return RecoveryBlob{}, err
	}
	return recoveryBlobFromRecord(ref, record), nil
}

func recoveryBlobFromRecord(ref string, record placementRecoveryStoreRecord) RecoveryBlob {
	return RecoveryBlob{
		Ref:           ref,
		SandboxID:     record.SandboxID,
		Spec:          cloneCreateSandboxRequest(record.Recovery.Spec),
		SecretRef:     record.Recovery.SecretRef,
		SecretVersion: record.Recovery.SecretVersion,
		SealedSecrets: cloneBytes(record.Recovery.SealedSecrets),
	}
}

func (b RecoveryBlob) recovery() placementRecovery {
	return placementRecovery{
		Spec:          cloneCreateSandboxRequest(b.Spec),
		SecretRef:     b.SecretRef,
		SecretVersion: b.SecretVersion,
		SealedSecrets: cloneBytes(b.SealedSecrets),
	}
}

func encodePlacementRecoveryRecord(record placementRecoveryStoreRecord) (string, []byte, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return "", nil, fmt.Errorf("placement recovery store: marshal: %w", err)
	}
	sum := sha256.Sum256(payload)
	return placementRecoveryRefPrefix + hex.EncodeToString(sum[:]), payload, nil
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
	ref, payload, err := encodePlacementRecoveryRecord(record)
	if err != nil {
		return "", err
	}
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
	record, ok, err := s.GetRecord(ref)
	if err != nil || !ok {
		return placementRecovery{}, ok, err
	}
	return clonePlacementRecovery(record.Recovery), true, nil
}

func (s *placementRecoveryFileStore) GetRecord(ref string) (placementRecoveryStoreRecord, bool, error) {
	path, err := s.pathForRef(ref)
	if err != nil {
		return placementRecoveryStoreRecord{}, false, err
	}
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return placementRecoveryStoreRecord{}, false, nil
	}
	if err != nil {
		return placementRecoveryStoreRecord{}, false, fmt.Errorf("placement recovery store: read: %w", err)
	}
	var record placementRecoveryStoreRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return placementRecoveryStoreRecord{}, false, fmt.Errorf("placement recovery store: decode: %w", err)
	}
	return record, true, nil
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

func (s *placementRecoveryFileStore) RetainSnapshotRefs(refs []string) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("placement recovery store: mkdir: %w", err)
	}
	manifest, err := s.readGCManifest()
	if err != nil {
		return err
	}
	manifest.Snapshots = append(manifest.Snapshots, placementRecoverySnapshotRefs{
		CreatedUnix: time.Now().Unix(),
		Refs:        normalizeRecoveryRefs(refs),
	})
	if len(manifest.Snapshots) > placementRecoverySnapshotRefSets {
		manifest.Snapshots = manifest.Snapshots[len(manifest.Snapshots)-placementRecoverySnapshotRefSets:]
	}
	if err := s.writeGCManifest(manifest); err != nil {
		return err
	}
	keep := make(map[string]struct{})
	for _, snap := range manifest.Snapshots {
		for _, ref := range snap.Refs {
			keep[ref] = struct{}{}
		}
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("placement recovery store: list: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isRecoveryBlobFilename(entry.Name()) {
			continue
		}
		ref := placementRecoveryRefPrefix + strings.TrimSuffix(entry.Name(), ".json")
		if _, ok := keep[ref]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("placement recovery store: gc: %w", err)
		}
	}
	return nil
}

func (s *placementRecoveryFileStore) gcManifestPath() string {
	return filepath.Join(s.dir, "snapshots.json")
}

func (s *placementRecoveryFileStore) readGCManifest() (placementRecoveryGCManifest, error) {
	payload, err := os.ReadFile(s.gcManifestPath())
	if errors.Is(err, os.ErrNotExist) {
		return placementRecoveryGCManifest{}, nil
	}
	if err != nil {
		return placementRecoveryGCManifest{}, fmt.Errorf("placement recovery store: read gc manifest: %w", err)
	}
	var manifest placementRecoveryGCManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return placementRecoveryGCManifest{}, fmt.Errorf("placement recovery store: decode gc manifest: %w", err)
	}
	return manifest, nil
}

func (s *placementRecoveryFileStore) writeGCManifest(manifest placementRecoveryGCManifest) error {
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("placement recovery store: encode gc manifest: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-recovery-gc-*")
	if err != nil {
		return fmt.Errorf("placement recovery store: create gc temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("placement recovery store: write gc manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("placement recovery store: sync gc manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("placement recovery store: close gc manifest: %w", err)
	}
	if err := os.Rename(tmpName, s.gcManifestPath()); err != nil {
		return fmt.Errorf("placement recovery store: rename gc manifest: %w", err)
	}
	return nil
}

func normalizeRecoveryRefs(refs []string) []string {
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		seen[ref] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func isRecoveryBlobFilename(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	sum := strings.TrimSuffix(name, ".json")
	if len(sum) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(sum)
	return err == nil
}

type placementRecoveryMemoryStore struct {
	mu   sync.RWMutex
	rows map[string]placementRecoveryStoreRecord
}

func newPlacementRecoveryMemoryStore() *placementRecoveryMemoryStore {
	return &placementRecoveryMemoryStore{rows: make(map[string]placementRecoveryStoreRecord)}
}

func (s *placementRecoveryMemoryStore) Put(sandboxID string, rec placementRecovery) (string, error) {
	if strings.TrimSpace(sandboxID) == "" {
		return "", errors.New("placement recovery store: empty sandbox id")
	}
	record := placementRecoveryStoreRecord{
		SandboxID: sandboxID,
		Recovery:  clonePlacementRecovery(rec),
	}
	ref, _, err := encodePlacementRecoveryRecord(record)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[ref] = record
	return ref, nil
}

func (s *placementRecoveryMemoryStore) Get(ref string) (placementRecovery, bool, error) {
	record, ok, err := s.GetRecord(ref)
	if err != nil || !ok {
		return placementRecovery{}, ok, err
	}
	return clonePlacementRecovery(record.Recovery), true, nil
}

func (s *placementRecoveryMemoryStore) GetRecord(ref string) (placementRecoveryStoreRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.rows[ref]
	if !ok {
		return placementRecoveryStoreRecord{}, false, nil
	}
	record.Recovery = clonePlacementRecovery(record.Recovery)
	return record, true, nil
}

func (s *placementRecoveryMemoryStore) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, ref)
	return nil
}

func (s *placementRecoveryMemoryStore) RetainSnapshotRefs([]string) error { return nil }
