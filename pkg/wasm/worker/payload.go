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
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

type errorPayload struct {
	Message string `json:"message"`
}

type okPayload struct {
	OK bool `json:"ok"`
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
