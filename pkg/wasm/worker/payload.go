package worker

import (
	"encoding/json"
	"fmt"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type loadModulePayload struct {
	Path string `json:"path"`
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
}

type okPayload struct {
	OK bool `json:"ok"`
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

func encodePayload(v any) ([]byte, error) {
	return json.Marshal(v)
}

func decodePayload(data []byte, v any) error {
	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}
	return json.Unmarshal(data, v)
}
