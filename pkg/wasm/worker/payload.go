package worker

import (
	"encoding/json"
	"fmt"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type loadModulePayload struct {
	Path     string `json:"path"`
	MemoryMB int    `json:"memory_mb,omitempty"`
}

type instantiatePayload struct {
	Caps wasmengine.Capabilities `json:"caps"`
}

type invokePayload struct {
	Export string `json:"export"`
}

type execPayload struct {
	Caps   wasmengine.Capabilities `json:"caps"`
	Export string                  `json:"export"`
}

type execResultPayload struct {
	ExitCode int                   `json:"exit_code"`
	Stdout   string                `json:"stdout,omitempty"`
	Stderr   string                `json:"stderr,omitempty"`
	Usage    wasmengine.UsageStats `json:"usage,omitempty"`
}

type errorPayload struct {
	Message string `json:"message"`
	// Code lets a client tell refusals apart without matching message text.
	// Workers older than streaming exec never set it.
	Code string `json:"code,omitempty"`
}

// Error codes carried by errorPayload.Code.
const (
	errCodeStreamingUnsupported = "streaming_unsupported"
	errCodeStreamLimit          = "stream_limit"
)

// ExecStartPayload starts a streaming run (MsgExecStart). The run is a new
// instance next to the sandbox's own, so it never replaces the serving guest.
type ExecStartPayload struct {
	// Caps are the run's args, env, preopens, memory and wall timeout, plus
	// the sandbox's network blocks and egress policy, exactly as for MsgExec.
	Caps wasmengine.Capabilities `json:"caps"`
	// Export defaults to _start.
	Export string `json:"export,omitempty"`
	// ModulePath runs another module (a language runtime for code-run);
	// empty runs the sandbox's own module.
	ModulePath string `json:"module_path,omitempty"`
	// NoDeadline drops the wall-clock budget; the run lasts until it exits
	// or is killed. Caps.WallTimeoutNs is ignored then.
	NoDeadline bool `json:"no_deadline,omitempty"`
	// MaxOutputBytes keeps only the first N bytes of each of stdout and
	// stderr and drops the rest (the guest never blocks on it). 0 = no cap.
	MaxOutputBytes int64 `json:"max_output_bytes,omitempty"`
	// Stdin opens the guest's stdin to exec_stdin frames. Without it the
	// guest reads EOF at once.
	Stdin bool `json:"stdin,omitempty"`
}

// execStartedPayload answers MsgExecStart with the run's id, which an
// out-of-band exec_kill names.
type execStartedPayload struct {
	ID string `json:"id"`
}

// execKillPayload names the run an out-of-band exec_kill stops.
type execKillPayload struct {
	ID string `json:"id"`
}

// ExecExit ends a streaming run (MsgExecExit).
type ExecExit struct {
	// ExitCode is the guest's exit code; -1 when the run was killed or
	// timed out.
	ExitCode int  `json:"exit_code"`
	Killed   bool `json:"killed,omitempty"`
	TimedOut bool `json:"timed_out,omitempty"`
	// Truncated is set when MaxOutputBytes dropped output.
	Truncated bool `json:"truncated,omitempty"`
	// Error is set when the guest trapped or could not run.
	Error string                `json:"error,omitempty"`
	Usage wasmengine.UsageStats `json:"usage,omitempty"`
}

type okPayload struct {
	OK bool `json:"ok"`
}

// loadModuleResultPayload rides the MsgLoadModule OK reply so the host create
// path can emit the wasm_load sub-stage breakdown (Server-Timing). Old clients
// that decode only okPayload keep working — expectOK ignores the payload.
type loadModuleResultPayload struct {
	Timings wasmengine.LoadTimings `json:"timings"`
}

// instanceStatusPayload is the MsgInstanceStatus reply. Workers outlive
// sandboxd, so a restarted sandboxd also reads replies from workers that
// predate the identity fields: they leave both out, and Checked is how the
// reader tells "holds no instance" from "cannot say whose it holds".
type instanceStatusPayload struct {
	Loaded bool `json:"loaded"`
	// SandboxID is the sandbox whose instance the worker holds, "" for
	// none.
	SandboxID string `json:"sandbox_id,omitempty"`
	// Checked is set by every worker that tracks SandboxID.
	Checked bool `json:"checked,omitempty"`
}

type checkpointPayload struct {
	OutDir string                    `json:"out_dir"`
	Meta   wasmengine.SnapshotConfig `json:"meta"`
}

type checkpointResultPayload struct {
	CloneGeneration string `json:"clone_generation"`
}

type restorePayload struct {
	Dir  string                  `json:"dir"`
	Caps wasmengine.Capabilities `json:"caps"`
}

type setCapabilityPayload struct {
	Caps wasmengine.Capabilities `json:"caps"`
}

type netstatsResultPayload struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// setEgressPolicyPayload replaces a sandbox's mediator egress policy (live
// update, plans/egress-domain-filtering.md P2-1). Empty lists remove it.
type setEgressPolicyPayload struct {
	AllowOut []string `json:"allow_out,omitempty"`
	DenyOut  []string `json:"deny_out,omitempty"`
	// Learn selects learn mode (P2-7); the lists are then empty.
	Learn bool `json:"learn,omitempty"`
}

type setNetworkBlocksPayload struct {
	BlockIngress bool `json:"block_ingress"`
	BlockEgress  bool `json:"block_egress"`
}

type setListenPortPayload struct {
	Port int    `json:"port"`
	Host string `json:"host,omitempty"`
}

type listenPortResultPayload struct {
	Port int `json:"port"`
}

type proxyHTTPPayload struct {
	GuestPort  int                 `json:"guest_port"`
	Method     string              `json:"method"`
	RequestURI string              `json:"request_uri"`
	Header     map[string][]string `json:"header,omitempty"`
	Body       []byte              `json:"body,omitempty"`
}

type proxyHTTPResultPayload struct {
	StatusCode int                 `json:"status_code"`
	Header     map[string][]string `json:"header,omitempty"`
	Body       []byte              `json:"body,omitempty"`
}

var encodePayload = func(v any) ([]byte, error) {
	return json.Marshal(v)
}

var decodePayload = func(data []byte, v any) error {
	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}
	return json.Unmarshal(data, v)
}
