// Package worker implements the WASM worker-subprocess pool (plans/wasm-runtime.md §2.1).
// Phase 1 lands length-prefixed JSON framing; CBOR encoding can replace the codec
// without changing the message types.
package worker

// MessageType identifies a worker control-plane message.
type MessageType string

const (
	MsgHealthPing       MessageType = "health_ping"
	MsgPong             MessageType = "pong"
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
	MsgSetListenPort    MessageType = "set_listen_port"
	MsgProxyHTTP        MessageType = "proxy_http"
	MsgProxyHTTPResult  MessageType = "proxy_http_result"
)

// Envelope is the on-wire message body (after the length prefix).
type Envelope struct {
	Type      MessageType `json:"type"`
	SandboxID string      `json:"sandbox_id,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
}
