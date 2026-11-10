package wasm

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// execCapsClient records the capabilities each exec carries.
type execCapsClient struct {
	recordingWorkerClient
	execCaps []wasmengine.Capabilities
}

func (c *execCapsClient) Exec(_ string, caps wasmengine.Capabilities, _ string) (wasmengine.RunResult, error) {
	c.execCaps = append(c.execCaps, caps)
	return wasmengine.RunResult{Stdout: "ok"}, nil
}

// TestExecNeverOpensAGuestListener is the regression test for the Python
// "error evaluating path" bug (T14): an exec on a per-sandbox worker must not
// ask the worker for a wasip1 listener, on either kind of worker.
func TestExecNeverOpensAGuestListener(t *testing.T) {
	for _, resident := range []bool{false, true} {
		client := &execCapsClient{}
		d := New(Config{RunDir: t.TempDir()}, nil)
		d.SetWorkerClientFactory(func(string) WorkerClient { return client })
		d.byID["sb-exec"] = &sandboxInstance{
			sandboxID:        "sb-exec",
			socketPath:       "/tmp/w.sock",
			workDir:          t.TempDir(),
			fromResidentHost: resident,
			status:           models.SandboxStatusStarted,
			entryExport:      "_start",
		}
		res, err := d.execSandbox(context.Background(), "sb-exec", models.ExecRequest{Command: "python /work/x.py"})
		if err != nil || res.Stdout != "ok" {
			t.Fatalf("resident=%v exec = %+v, %v", resident, res, err)
		}
		if len(client.execCaps) != 1 {
			t.Fatalf("resident=%v exec calls = %d", resident, len(client.execCaps))
		}
		caps := client.execCaps[0]
		if caps.ListenEnabled() {
			t.Fatalf("resident=%v exec caps enable a listener (port %d)", resident, caps.WASIListenPort)
		}
		if len(caps.Preopens) != 1 || caps.Preopens[0].GuestPath != "/work" {
			t.Fatalf("resident=%v exec preopens = %+v", resident, caps.Preopens)
		}
	}
}
