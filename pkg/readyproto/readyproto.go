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
	// EventReady is the guest→host readiness announcement after adopt or cold boot.
	EventReady = "ready"
	// EventParked is the guest→host hello from a warm-pool slot awaiting adopt.
	EventParked = "parked"
	// EventAdopt is the host→guest frame that binds real sandbox identity.
	EventAdopt = "adopt"
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

// ParkedSignal is the guest→host parked-slot hello.
type ParkedSignal struct {
	Event        string `json:"event"`
	Token        string `json:"token"`
	Nonce        string `json:"nonce"`
	AgentVersion string `json:"agent_version,omitempty"`
}

// AdoptFrame is the host→guest identity bind during warm-pool adoption.
type AdoptFrame struct {
	Event     string `json:"event"`
	SandboxID string `json:"sandbox_id"`
	Token     string `json:"token"`
	Nonce     string `json:"nonce"`
}

// Encode writes one newline-terminated JSON line.
func Encode(w io.Writer, sig ReadySignal) error {
	if strings.TrimSpace(sig.Event) == "" {
		sig.Event = EventReady
	}
	return encodeLine(w, sig)
}

// EncodeParked writes a parked hello line.
func EncodeParked(w io.Writer, sig ParkedSignal) error {
	if strings.TrimSpace(sig.Event) == "" {
		sig.Event = EventParked
	}
	return encodeLine(w, sig)
}

// EncodeAdopt writes a host→guest adopt frame.
func EncodeAdopt(w io.Writer, frame AdoptFrame) error {
	if strings.TrimSpace(frame.Event) == "" {
		frame.Event = EventAdopt
	}
	return encodeLine(w, frame)
}

func encodeLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
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

// Decode reads one bounded newline-delimited ready line from r.
func Decode(r io.Reader) (ReadySignal, error) {
	line, err := readLine(r)
	if err != nil {
		return ReadySignal{}, err
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

// DecodeParked reads a guest→host parked hello.
func DecodeParked(r io.Reader) (ParkedSignal, error) {
	line, err := readLine(r)
	if err != nil {
		return ParkedSignal{}, err
	}
	var sig ParkedSignal
	if err := json.Unmarshal([]byte(line), &sig); err != nil {
		return ParkedSignal{}, fmt.Errorf("readyproto: decode parked: %w", err)
	}
	if sig.Event != EventParked {
		return ParkedSignal{}, fmt.Errorf("readyproto: unexpected event %q", sig.Event)
	}
	if strings.TrimSpace(sig.Token) == "" {
		return ParkedSignal{}, errors.New("readyproto: token is required")
	}
	if strings.TrimSpace(sig.Nonce) == "" {
		return ParkedSignal{}, errors.New("readyproto: nonce is required")
	}
	return sig, nil
}

// DecodeAdopt reads a host→guest adopt frame.
func DecodeAdopt(r io.Reader) (AdoptFrame, error) {
	line, err := readLine(r)
	if err != nil {
		return AdoptFrame{}, err
	}
	var frame AdoptFrame
	if err := json.Unmarshal([]byte(line), &frame); err != nil {
		return AdoptFrame{}, fmt.Errorf("readyproto: decode adopt: %w", err)
	}
	if frame.Event != EventAdopt {
		return AdoptFrame{}, fmt.Errorf("readyproto: unexpected event %q", frame.Event)
	}
	if strings.TrimSpace(frame.SandboxID) == "" {
		return AdoptFrame{}, errors.New("readyproto: sandbox_id is required")
	}
	if strings.TrimSpace(frame.Token) == "" {
		return AdoptFrame{}, errors.New("readyproto: token is required")
	}
	if strings.TrimSpace(frame.Nonce) == "" {
		return AdoptFrame{}, errors.New("readyproto: nonce is required")
	}
	return frame, nil
}

func readLine(r io.Reader) (string, error) {
	limited := io.LimitReader(r, MaxLineBytes+1)
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(limited); err != nil {
		return "", err
	}
	line := strings.TrimSpace(buf.String())
	if line == "" {
		return "", errors.New("readyproto: empty line")
	}
	if len(line) > MaxLineBytes {
		return "", fmt.Errorf("readyproto: line exceeds %d bytes", MaxLineBytes)
	}
	return line, nil
}
