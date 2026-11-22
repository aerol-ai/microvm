package daemon

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

func TestLogWasmWorkerConfinement(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop bool
		c    worker.Confinement
		want string
	}{
		{"dropped", true, worker.Confinement{UID: 61000, GID: 61000}, "wasm workers drop privileges before running a module"},
		{"escape hatch", false, worker.Confinement{}, "SB_WASM_WORKER_DROP_PRIVS=false"},
		{"not root", true, worker.Confinement{}, "sandboxd is not root on Linux"},
	} {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logWasmWorkerConfinement(logger, config.Config{WasmWorkerDropPrivs: tc.drop}, tc.c)
		if !strings.Contains(buf.String(), tc.want) {
			t.Fatalf("%s: log = %q", tc.name, buf.String())
		}
	}
}
