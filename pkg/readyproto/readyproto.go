// Package readyproto defines the newline-delimited JSON handshake toolboxd
// sends to sandboxd when a Docker sandbox's agent is ready to serve.
package readyproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// EventReady is the only event type accepted on the readiness channel.
	EventReady = "ready"
	// MaxLineBytes caps attacker-controlled read size on the host listener.
	MaxLineBytes = 4 << 10
)

// ReadySignal is the guest→host readiness announcement.
type ReadySignal struct {
	Event        string `json:"event"`
	SandboxID    string `json:"sandbox_id"`
	Token        string `json:"token"`
	Nonce        string `json:"nonce"`
	AgentVersion string `json:"agent_version,omitempty"`
}

// Encode writes one newline-terminated JSON line.
func Encode(w io.Writer, sig ReadySignal) error {
	if strings.TrimSpace(sig.Event) == "" {
		sig.Event = EventReady
	}
	data, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	if len(data) > MaxLineBytes {
		return fmt.Errorf("readyproto: encoded line exceeds %d bytes", MaxLineBytes)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// Decode reads one bounded newline-delimited JSON line from r.
func Decode(r io.Reader) (ReadySignal, error) {
	limited := io.LimitReader(r, MaxLineBytes+1)
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(limited); err != nil {
		return ReadySignal{}, err
	}
	line := strings.TrimSpace(buf.String())
	if line == "" {
		return ReadySignal{}, errors.New("readyproto: empty line")
	}
	if len(line) > MaxLineBytes {
		return ReadySignal{}, fmt.Errorf("readyproto: line exceeds %d bytes", MaxLineBytes)
	}
	var sig ReadySignal
	if err := json.Unmarshal([]byte(line), &sig); err != nil {
		return ReadySignal{}, fmt.Errorf("readyproto: decode: %w", err)
	}
	if sig.Event != EventReady {
		return ReadySignal{}, fmt.Errorf("readyproto: unexpected event %q", sig.Event)
	}
	if strings.TrimSpace(sig.SandboxID) == "" {
		return ReadySignal{}, errors.New("readyproto: sandbox_id is required")
	}
	if strings.TrimSpace(sig.Token) == "" {
		return ReadySignal{}, errors.New("readyproto: token is required")
	}
	if strings.TrimSpace(sig.Nonce) == "" {
		return ReadySignal{}, errors.New("readyproto: nonce is required")
	}
	return sig, nil
}
