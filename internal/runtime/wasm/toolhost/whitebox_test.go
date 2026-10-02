package toolhost

import (
	"testing"
)

// ─── exec_stream helpers ──────────────────────────────────────────────────────

// ─── coderun helpers ──────────────────────────────────────────────────────────

// ─── files helper ─────────────────────────────────────────────────────────────

func TestStrconvQuote(t *testing.T) {
	if got := strconvQuote(""); got != `""` {
		t.Fatalf("empty = %q", got)
	}
	if got := strconvQuote("file.txt"); got != `"file.txt"` {
		t.Fatalf("simple = %q", got)
	}
	if got := strconvQuote(`file"with"quotes`); got != `"file\"with\"quotes"` {
		t.Fatalf("with quotes = %q", got)
	}
}

// ─── host.go New with sessions ────────────────────────────────────────────────

func TestNewHostWithSessions(t *testing.T) {
	// When sessions is nil, daytona should also be nil
	h := New(Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	if h == nil {
		t.Fatal("New returned nil")
	}
	// no panic accessing the handler
	_ = h.Handler()
}
