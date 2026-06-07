// Package worker implements the WASM worker-subprocess pool (plans/wasm-runtime.md §2.1).
// Phase 1 lands length-prefixed JSON framing; CBOR encoding can replace the codec
// without changing the message types.
package worker

// MessageType identifies a worker control-plane message.
type MessageType string

const (
	MsgHealthPing    MessageType = "health_ping"
	MsgPong          MessageType = "pong"
	MsgTriggerPanic  MessageType = "trigger_panic" // test-only: verifies crash isolation (D10)
	MsgInvoke        MessageType = "invoke"
	MsgInvokeResult  MessageType = "invoke_result"
	MsgCheckpoint    MessageType = "checkpoint"
	MsgRestore       MessageType = "restore"
	MsgSetCapability MessageType = "set_capability"
	MsgNetstatsTick  MessageType = "netstats_tick"
)

// Envelope is the on-wire message body (after the length prefix).
type Envelope struct {
	Type      MessageType `json:"type"`
	SandboxID string      `json:"sandbox_id,omitempty"`
	Payload   []byte      `json:"payload,omitempty"`
}
