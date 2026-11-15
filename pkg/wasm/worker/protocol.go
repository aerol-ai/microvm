// Package worker implements the WASM worker-subprocess pool (plans/wasm-runtime.md §2.1).
// Phase 1 lands length-prefixed JSON framing; CBOR encoding can replace the codec
// without changing the message types.
package worker

// MessageType identifies a worker control-plane message.
type MessageType string

const (
	MsgHealthPing       MessageType = "health_ping"
	MsgPong             MessageType = "pong"
	MsgInstanceStatus   MessageType = "instance_status"
	MsgTriggerPanic     MessageType = "trigger_panic" // test-only: verifies crash isolation (D10)
	MsgLoadModule       MessageType = "load_module"
	MsgInstantiate      MessageType = "instantiate"
	MsgInvoke           MessageType = "invoke"
	MsgExec             MessageType = "exec"
	MsgStopInstance     MessageType = "stop_instance"
	MsgOK               MessageType = "ok"
	MsgError            MessageType = "error"
	MsgInvokeResult     MessageType = "invoke_result"
	MsgCheckpoint       MessageType = "checkpoint"
	MsgRestore          MessageType = "restore"
	MsgSetCapability    MessageType = "set_capability"
	MsgNetstatsTick     MessageType = "netstats_tick"
	MsgSetNetworkBlocks MessageType = "set_network_blocks"
	MsgSetEgressPolicy  MessageType = "set_egress_policy"
	MsgEgressLearned    MessageType = "egress_learned"
	MsgSetListenPort    MessageType = "set_listen_port"
	MsgListenPort       MessageType = "listen_port"
	MsgProxyHTTP        MessageType = "proxy_http"
	MsgProxyHTTPResult  MessageType = "proxy_http_result"

	// Streaming exec (issue #535). One connection carries one run: the
	// client sends exec_start and gets exec_started (or an error); then the
	// worker streams exec_chunk frames and ends with exec_exit, while the
	// client may send exec_stdin, exec_stdin_close and exec_kill. exec_kill
	// is also accepted on a fresh connection with the run's id, so a client
	// can stop a run whose connection is stalled on stdin backpressure.
	MsgExecStart      MessageType = "exec_start"
	MsgExecStarted    MessageType = "exec_started"
	MsgExecChunk      MessageType = "exec_chunk"
	MsgExecStdin      MessageType = "exec_stdin"
	MsgExecStdinClose MessageType = "exec_stdin_close"
	MsgExecKill       MessageType = "exec_kill"
	MsgExecExit       MessageType = "exec_exit"

	// MsgEntrypointLogs reads the serving guest's kept output (issue #178,
	// entrypoint.go). With follow, the connection then carries exec_chunk
	// frames until an exec_exit when the entrypoint ends.
	MsgEntrypointLogs MessageType = "entrypoint_logs"

	// MsgSetListenPorts / MsgListenPorts: one guest listener per exposed
	// port (listen_ports.go).
	MsgSetListenPorts MessageType = "set_listen_ports"
	MsgListenPorts    MessageType = "listen_ports"
)

// Stream ids on exec_chunk frames.
const (
	StreamStdout uint8 = 1
	StreamStderr uint8 = 2
)

// Envelope is the on-wire message body (after the length prefix).
type Envelope struct {
	Type      MessageType `json:"type"`
	SandboxID string      `json:"sandbox_id,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
	// Stream marks an exec_chunk as stdout (1) or stderr (2). Chunk and
	// stdin frames carry the bytes themselves as Payload, not a JSON
	// document, so output that is not UTF-8 arrives unchanged.
	Stream uint8 `json:"stream,omitempty"`
}
