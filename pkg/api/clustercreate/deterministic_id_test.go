package clustercreate

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDeterministicSandboxID(t *testing.T) {
	// A blank key keeps the create non-idempotent (the opt-in contract): the
	// caller mints a fresh random id when this returns "".
	if got := DeterministicSandboxID("owner-a", "   "); got != "" {
		t.Fatalf("blank key id = %q, want empty", got)
	}
	if got := DeterministicSandboxID("owner-a", ""); got != "" {
		t.Fatalf("empty key id = %q, want empty", got)
	}

	// Stable: same owner + key resolves to the same id across calls, which is
	// what lets a retry replay instead of placing a second sandbox.
	first := DeterministicSandboxID("owner-a", "key-1")
	if first != DeterministicSandboxID("owner-a", "key-1") {
		t.Fatalf("id not stable for the same owner+key")
	}

	// Owner-namespaced: a key reused by another tenant never collides, so one
	// tenant can never resolve to another's id (CreateSandboxWithID owner check).
	if DeterministicSandboxID("owner-b", "key-1") == first {
		t.Fatalf("different owners produced the same id for the same key")
	}
	// Different key, same owner → different id.
	if DeterministicSandboxID("owner-a", "key-2") == first {
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
	if DeterministicSandboxID("owner-a", "  key-1  ") != first {
		t.Fatalf("key whitespace changed the id")
	}
}
