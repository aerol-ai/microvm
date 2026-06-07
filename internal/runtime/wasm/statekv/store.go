// Package statekv implements the host KV capability for durable WASM sandboxes
// (plans/wasm-runtime.md §4.6).
package statekv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
)

// Store is the durable per-sandbox key-value API.
type Store interface {
	Get(ctx context.Context, sandboxID, key string) ([]byte, bool, error)
	Set(ctx context.Context, sandboxID, key string, value []byte) error
	Delete(ctx context.Context, sandboxID, key string) error
	ListKeys(ctx context.Context, sandboxID string) ([]string, error)
}

// SQLiteStore persists KV rows in the wasm_state_kv table.
type SQLiteStore struct {
	st *store.Store
}

// NewSQLiteStore wraps the daemon SQLite store.
func NewSQLiteStore(st *store.Store) *SQLiteStore {
	return &SQLiteStore{st: st}
}

func (s *SQLiteStore) Get(ctx context.Context, sandboxID, key string) ([]byte, bool, error) {
	if s == nil || s.st == nil {
		return nil, false, errors.New("statekv store not configured")
	}
	return s.st.GetWasmStateKV(ctx, sandboxID, key)
}

func (s *SQLiteStore) Set(ctx context.Context, sandboxID, key string, value []byte) error {
	if s == nil || s.st == nil {
		return errors.New("statekv store not configured")
	}
	return s.st.PutWasmStateKV(ctx, sandboxID, key, value)
}

func (s *SQLiteStore) Delete(ctx context.Context, sandboxID, key string) error {
	if s == nil || s.st == nil {
		return errors.New("statekv store not configured")
	}
	return s.st.DeleteWasmStateKV(ctx, sandboxID, key)
}

func (s *SQLiteStore) ListKeys(ctx context.Context, sandboxID string) ([]string, error) {
	if s == nil || s.st == nil {
		return nil, errors.New("statekv store not configured")
	}
	return s.st.ListWasmStateKVKeys(ctx, sandboxID)
}

// ValidateKey rejects empty or oversized keys.
func ValidateKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("statekv key is required")
	}
	if len(key) > 512 {
		return fmt.Errorf("statekv key exceeds 512 bytes")
	}
	return nil
}

// ValidateValue caps value size to keep SQLite rows bounded.
func ValidateValue(value []byte) error {
	const maxValue = 4 << 20 // 4 MiB
	if len(value) > maxValue {
		return fmt.Errorf("statekv value exceeds %d bytes", maxValue)
	}
	return nil
}

// ErrNotFound is returned when a key is absent.
var ErrNotFound = errors.New("statekv: not found")
