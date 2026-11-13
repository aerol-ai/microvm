package clustercreate

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDeterministicSandboxID(t *testing.T) {
	// A blank key keeps the create non-idempotent (the opt-in contract): the
	// caller mints a fresh random id when this returns "".
	if got := DeterministicSandboxID(nil, "owner-a", "   "); got != "" {
		t.Fatalf("blank key id = %q, want empty", got)
	}
	if got := DeterministicSandboxID(nil, "owner-a", ""); got != "" {
		t.Fatalf("empty key id = %q, want empty", got)
	}

	// Stable: same owner + key resolves to the same id across calls, which is
	// what lets a retry replay instead of placing a second sandbox.
	first := DeterministicSandboxID(nil, "owner-a", "key-1")
	if first != DeterministicSandboxID(nil, "owner-a", "key-1") {
		t.Fatalf("id not stable for the same owner+key")
	}

	// Owner-namespaced: a key reused by another tenant never collides, so one
	// tenant can never resolve to another's id (CreateSandboxWithID owner check).
	if DeterministicSandboxID(nil, "owner-b", "key-1") == first {
		t.Fatalf("different owners produced the same id for the same key")
	}
	// Different key, same owner → different id.
	if DeterministicSandboxID(nil, "owner-a", "key-2") == first {
		t.Fatalf("different keys produced the same id")
	}

	// Shape matches a generated id (sb-<16 hex>) and is a valid container name.
	if len(first) != len("sb-")+16 {
		t.Fatalf("id %q length = %d, want %d", first, len(first), len("sb-")+16)
	}
	if err := models.ValidateSandboxID(first); err != nil {
		t.Fatalf("derived id %q invalid: %v", first, err)
	}
	// Leading/trailing whitespace on the key must not change the id.
	if DeterministicSandboxID(nil, "owner-a", "  key-1  ") != first {
		t.Fatalf("key whitespace changed the id")
	}
}

// In a federation the derived id carries the cell's byte (Service.IDInCell)
// and is still the same on every retry of the same key.
func TestDeterministicSandboxIDInACell(t *testing.T) {
	cfg := config.Config{CellID: 2, CellIDKey: bytes.Repeat([]byte{7}, 32)}
	svc := service.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	plain := DeterministicSandboxID(nil, "owner-a", "key-1")
	first := DeterministicSandboxID(svc, "owner-a", "key-1")
	if first != DeterministicSandboxID(svc, "owner-a", "key-1") || first != svc.IDInCell(plain) {
		t.Fatalf("derived id %q is not stable, or is not the digest %q in the cell", first, plain)
	}
	if first[5:] != plain[5:] || !models.IsGeneratedSandboxID(first) {
		t.Fatalf("derived id %q, want %q with only its first byte changed", first, plain)
	}
}
