// Package readyproto defines the newline-delimited JSON handshake toolboxd
// sends to sandboxd when a Docker sandbox's agent is ready to serve.
package readyproto

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
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
	// MaxAdoptLineBytes caps an adopt frame. It is far above MaxLineBytes
	// because the frame carries the sandbox's env (plans/cluster-phase-2.md
	// §2), and it is the only line the larger cap applies to: the adopt
	// frame is host→guest, written by sandboxd and read by toolboxd, so the
	// host listener, which reads the lines a guest controls (parked hello,
	// ready ack), keeps the 4 KiB cap on attacker-sized reads.
	MaxAdoptLineBytes = 256 << 10
	// MaxAdoptEnvBytes is the largest JSON-encoded env an adopt frame may
	// carry. The rest of the frame (event, sandbox id, token, nonce) is what
	// every other line already fits in MaxLineBytes, so an env within this
	// bound always leaves a frame within MaxAdoptLineBytes, and a create
	// whose env is bigger is refused from the warm pool up front rather
	// than failing an adopt and burning a parked slot.
	MaxAdoptEnvBytes = MaxAdoptLineBytes - MaxLineBytes
)

// ErrEnvInvalid is returned for an env an adopt frame cannot carry: an empty
// key, a key containing '=', a NUL byte anywhere, or bytes that are not
// UTF-8 (encoding/json would replace them, so the guest would get a
// different value). The message names neither the key nor the value, since
// either could be a secret pasted into the wrong field.
var ErrEnvInvalid = errors.New("readyproto: env has an empty key, a key containing '=', a NUL byte, or bytes that are not UTF-8")

// ErrEnvTooLarge is returned for an env whose encoding exceeds
// MaxAdoptEnvBytes.
var ErrEnvTooLarge = fmt.Errorf("readyproto: env exceeds %d encoded bytes", MaxAdoptEnvBytes)

// ReadySignal is the guest→host readiness announcement.
type ReadySignal struct {
	Event        string `json:"event"`
	SandboxID    string `json:"sandbox_id"`
	Token        string `json:"token"`
	Nonce        string `json:"nonce"`
	AgentVersion string `json:"agent_version,omitempty"`
	// EnvDigest is set only in the ack of an adopt: EnvDigest(Nonce, env)
	// over the env the guest applied. An agent built before adopt frames
	// carried env leaves it out (encoding/json drops the unknown "env"
	// field without a word), which is how the host tells an agent that
	// ignored the env from one that applied it.
	EnvDigest string `json:"env_digest,omitempty"`
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
	// Env is the sandbox's env. The guest loads it before it takes the
	// identity and starts the held-back image command, so that command,
	// exec and sessions all see it. Omitted when empty, so an env-less
	// adopt is the same bytes an older agent has always read.
	Env map[string]string `json:"env,omitempty"`
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
	if err := validateEnvEntries(frame.Env); err != nil {
		return err
	}
	return encodeLineLimit(w, frame, MaxAdoptLineBytes)
}

func encodeLine(w io.Writer, v any) error {
	return encodeLineLimit(w, v, MaxLineBytes)
}

func encodeLineLimit(w io.Writer, v any, limit int) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > limit {
		return fmt.Errorf("readyproto: encoded line exceeds %d bytes", limit)
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
	line, err := readLineLimit(r, MaxAdoptLineBytes)
	if err != nil {
		return AdoptFrame{}, err
	}
	var frame AdoptFrame
	if err := json.Unmarshal([]byte(line), &frame); err != nil {
		// Not wrapped: the frame carries the sandbox's env, and a
		// json.SyntaxError quotes the byte it choked on, which may be one
		// of a secret's. The caller logs this error.
		return AdoptFrame{}, errors.New("readyproto: decode adopt: malformed JSON")
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
	if err := validateEnvEntries(frame.Env); err != nil {
		return AdoptFrame{}, err
	}
	return frame, nil
}

// ValidateAdoptEnv reports whether env can ride an adopt frame: every entry
// is one a process environment can carry, and the encoding fits within
// MaxAdoptEnvBytes. The host checks it before it takes a parked slot for a
// create, so an env the frame cannot carry sends the create cold instead of
// failing the adopt after the slot is spent. Errors are ErrEnvInvalid or
// ErrEnvTooLarge, which quote nothing from env.
func ValidateAdoptEnv(env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	if err := validateEnvEntries(env); err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return ErrEnvInvalid
	}
	if len(data) > MaxAdoptEnvBytes {
		return ErrEnvTooLarge
	}
	return nil
}

// validateEnvEntries is cmd/toolboxd/sandboxenv.Validate's rule (keys may
// not be empty or hold '=', the environ separator; nothing may hold NUL,
// the environ terminator) plus UTF-8, which JSON needs to carry a value
// unchanged. Checked on both ends: the host before it sends, the guest
// before it applies anything.
func validateEnvEntries(env map[string]string) error {
	for k, v := range env {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, 0) ||
			!utf8.ValidString(k) || !utf8.ValidString(v) {
			return ErrEnvInvalid
		}
	}
	return nil
}

// EnvDigest is the proof a guest's ready ack carries that it applied exactly
// the env an adopt frame held: hex HMAC-SHA256 keyed with the adopt nonce
// over the env in canonical form (entries sorted by key, each "key=value"
// then a NUL; keys hold neither '=' nor NUL and values hold no NUL, so the
// form is unambiguous). Keyed with the per-adopt nonce rather than a bare
// hash so the ack never holds a stable fingerprint of the env: a bare hash
// of a low-entropy secret could be matched by hashing guesses.
func EnvDigest(nonce string, env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	mac := hmac.New(sha256.New, []byte(nonce))
	for _, k := range keys {
		_, _ = io.WriteString(mac, k)
		_, _ = mac.Write([]byte{'='})
		_, _ = io.WriteString(mac, env[k])
		_, _ = mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// EnvDigestMatches reports, in constant time, whether digest is
// EnvDigest(nonce, env). An empty digest never matches.
func EnvDigestMatches(nonce string, env map[string]string, digest string) bool {
	if digest == "" {
		return false
	}
	return hmac.Equal([]byte(digest), []byte(EnvDigest(nonce, env)))
}

func readLine(r io.Reader) (string, error) {
	return readLineLimit(r, MaxLineBytes)
}

// readLineLimit reads one line of at most limit bytes (plus its newline).
// It stops reading once the line is over the limit, so a peer that never
// sends a newline costs at most limit bytes of memory, not whatever it
// cares to send.
func readLineLimit(r io.Reader, limit int) (string, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	var raw []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(raw)+len(chunk) > limit+1 {
			return "", fmt.Errorf("readyproto: line exceeds %d bytes", limit)
		}
		raw = append(raw, chunk...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(raw) > 0 {
			// Tolerate a final line without a trailing newline (tests, short reads).
			break
		}
		return "", err
	}
	line := bytes.TrimSpace(raw)
	if len(line) == 0 {
		return "", errors.New("readyproto: empty line")
	}
	if len(line) > limit {
		return "", fmt.Errorf("readyproto: line exceeds %d bytes", limit)
	}
	return string(line), nil
}
