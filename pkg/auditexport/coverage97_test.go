package auditexport

import (
	"strings"
	"testing"
	"time"
)

func TestCoverage97BackoffClampAndStdoutWriter(t *testing.T) {
	b := &Backoff{Base: 2 * time.Second, Max: time.Second, rand: func() float64 { return 0 }}
	if got := b.Next(); got != time.Second {
		// Base is above Max, so the ceiling is pulled back to Max. Jitter
		// of 0 is then floored at Base/2, which equals Max here.
		t.Fatalf("delay = %s", got)
	}
	backend, err := newFileBackend(BackendStdout, "-", nil)
	if err != nil || backend.w == nil {
		t.Fatalf("stdout backend = %v %v", backend, err)
	}
	if _, err := Open(Config{Backend: "not-a-backend"}); err == nil || !strings.Contains(err.Error(), "not-a-backend") {
		t.Fatalf("unknown backend err = %v", err)
	}
}
