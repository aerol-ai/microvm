package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	pathpkg "path"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The operator's exec output limits (plan E1, eng review ER5). sandboxd, not
// toolboxd, fills in SB_EXEC_OUTPUT_DEFAULT_BYTES and lowers a cap above
// SB_EXEC_OUTPUT_MAX_BYTES, in the exec request itself, before it forwards
// it. toolboxd has no channel for operator settings (the env a host pushes
// reaches the user's processes, not the agent), and a rule kept here holds on
// every runtime, after warm-pool adoption, on Firecracker templates and on
// agents already running. Both toolbox chokepoints call it, so it covers
// every surface that reaches buffered exec: v1's toolbox pass-through and
// Daytona's process routes (ServeToolboxReverseProxy), and Daytona
// executeCommand and Runloop one-shot commands (RoundTripToolbox). There is
// no /version round trip: an older agent ignores a cap sandboxd adds, which
// is how it treats every request today, while a cap the caller asked for is
// refused by the SDKs instead (ER4).

// ErrExecRequestTooLarge refuses a buffered exec body sandboxd will not read
// whole to apply the operator's maximum. It maps to 413.
var ErrExecRequestTooLarge = errors.New("exec request body is too large")

// maxExecPolicyBodyBytes bounds how much of an exec body sandboxd reads to
// rewrite it. Everything in the body ends up in one execve (the command, its
// env, later its argv), which Linux caps at a quarter of the stack limit:
// 2 MiB by default, 6 MiB at most. 8 MiB leaves room for JSON escaping, so
// no body that could run is refused. A variable for tests.
var maxExecPolicyBodyBytes int64 = 8 << 20

// isBufferedExecPath reports whether a toolbox request is a buffered exec.
// toolboxd strips one leading segment in front of a path it knows
// (normalizeSandboxPath: "/<anything>/process/execute" runs the exec), so a
// suffix match, not an exact one, is what keeps that form from slipping past
// the maximum. Matching a request toolboxd would not run as an exec costs
// only the rewrite.
func isBufferedExecPath(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	const exec = "/process/execute"
	clean := pathpkg.Clean("/" + path)
	return strings.HasSuffix(clean, exec) || strings.HasSuffix(path, exec)
}

func (s *Service) execOutputPolicyOn() bool {
	return s.cfg.ExecOutputDefaultBytes > 0 || s.cfg.ExecOutputMaxBytes > 0
}

// applyExecOutputPolicy returns the body to forward for a toolbox request:
// unchanged unless it is a buffered exec and the operator set a limit. It
// reads at most maxExecPolicyBodyBytes; a larger body is refused when a
// maximum is set (forwarding it unread would skip the maximum) and passed
// through untouched when only a default is.
func (s *Service) applyExecOutputPolicy(method, path string, body io.Reader) (io.Reader, error) {
	if body == nil || !s.execOutputPolicyOn() || !isBufferedExecPath(method, path) {
		return body, nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxExecPolicyBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxExecPolicyBodyBytes {
		if s.cfg.ExecOutputMaxBytes > 0 {
			return nil, fmt.Errorf("%w: over %d bytes", ErrExecRequestTooLarge, maxExecPolicyBodyBytes)
		}
		return io.MultiReader(bytes.NewReader(raw), body), nil
	}
	out, err := clampExecOutputBody(raw, s.cfg.ExecOutputDefaultBytes, s.cfg.ExecOutputMaxBytes)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(out), nil
}

// applyExecOutputPolicyToRequest is applyExecOutputPolicy for a request the
// reverse proxy forwards: it swaps the body and its length.
func (s *Service) applyExecOutputPolicyToRequest(r *http.Request, path string) error {
	if r.Body == nil || r.Body == http.NoBody || !s.execOutputPolicyOn() || !isBufferedExecPath(r.Method, path) {
		return nil
	}
	body, err := s.applyExecOutputPolicy(r.Method, path, r.Body)
	if err != nil {
		return err
	}
	// Only the length field: the transport writes Content-Length from it and
	// never from the header, and r.Header is shared with the caller's
	// request (r is a WithContext copy). A body passed through unread past
	// the bound keeps its length.
	if br, ok := body.(*bytes.Reader); ok {
		r.ContentLength = int64(br.Len())
		r.TransferEncoding = nil
	}
	r.Body = io.NopCloser(body)
	return nil
}

// clampExecOutputBody applies the default and the maximum to the two cap
// fields of an exec body and returns it, or raw itself when nothing changes.
//
// It reads the body the way toolboxd does (json.Decoder into ExecRequest:
// the first JSON value, field names matched case-insensitively, the last
// duplicate winning), so the caps it judges are the ones toolboxd would
// apply. Every other field is carried over as sent, including ones this
// sandboxd does not know. A body toolboxd cannot decode either goes through
// unchanged and toolboxd answers 400; a negative cap likewise.
func clampExecOutputBody(raw []byte, def, max int64) ([]byte, error) {
	var view models.ExecRequest
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&view); err != nil {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&fields); err != nil {
		return raw, nil
	}
	stdout, stdoutOK := clampOutputCap(view.MaxStdoutBytes, def, max)
	stderr, stderrOK := clampOutputCap(view.MaxStderrBytes, def, max)
	if !stdoutOK || !stderrOK {
		return raw, nil
	}
	if stdout == view.MaxStdoutBytes && stderr == view.MaxStderrBytes {
		return raw, nil
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	setCapField(fields, "max_stdout_bytes", stdout)
	setCapField(fields, "max_stderr_bytes", stderr)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return nil, err
	}
	// Fail closed: the rewritten body must say to toolboxd what was decided.
	var check models.ExecRequest
	if err := json.Unmarshal(buf.Bytes(), &check); err != nil || check.MaxStdoutBytes != stdout || check.MaxStderrBytes != stderr {
		return nil, fmt.Errorf("exec output policy: rewritten body does not carry the caps")
	}
	return buf.Bytes(), nil
}

// clampOutputCap is the operator's rule for one stream: no cap of the
// caller's own takes the default, and anything above the maximum (or no cap
// at all, with a maximum set) becomes the maximum. ok is false for a
// negative cap, which toolboxd refuses on its own.
func clampOutputCap(requested, def, max int64) (int64, bool) {
	if requested < 0 {
		return requested, false
	}
	if requested == 0 {
		requested = def
	}
	if max > 0 && (requested == 0 || requested > max) {
		requested = max
	}
	return requested, true
}

// setCapField replaces every spelling of name toolboxd would read with the
// one canonical key. encoding/json matches field names case-insensitively,
// so "MAX_STDOUT_BYTES" left beside the canonical key could override it.
func setCapField(fields map[string]json.RawMessage, name string, value int64) {
	for key := range fields {
		if strings.EqualFold(key, name) {
			delete(fields, key)
		}
	}
	if value > 0 {
		fields[name] = json.RawMessage(strconv.FormatInt(value, 10))
	}
}
