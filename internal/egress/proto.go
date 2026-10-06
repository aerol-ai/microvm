package egress

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// ProtocolVersion is the UDS protocol version this build speaks. Each side
// accepts N and N-1, so sandboxd and the gateway upgrade independently; only
// a gap of two is a mismatch (D9).
const ProtocolVersion = 1

// maxFrame bounds one JSON line. A full Sync of ~1k sandboxes with 64 entries
// each fits comfortably.
const maxFrame = 32 << 20

// Ops on the wire.
const (
	opHello      = "hello"
	opAttach     = "attach"
	opUpdate     = "update"
	opDetach     = "detach"
	opSetBlocked = "set_blocked"
	opSync       = "sync"
	opReady      = "ready"
	opBridges    = "bridges"
	opProbe      = "probe"
	opSubscribe  = "subscribe"
	opLearned    = "learned"
)

// request is one client frame.
type request struct {
	ID       uint64          `json:"id"`
	Op       string          `json:"op"`
	Versions []int           `json:"versions,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	// Trace carries W3C trace context so gateway spans join the caller's
	// trace (CEO D24 operability).
	Trace string `json:"trace,omitempty"`
}

// response is one server frame. Events on a subscribed connection reuse it
// with Event set and ID zero.
type response struct {
	ID      uint64          `json:"id"`
	Error   string          `json:"error,omitempty"`
	Code    string          `json:"code,omitempty"`
	Version int             `json:"version,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Event   *Event          `json:"event,omitempty"`
}

// Error codes carried in responses, mapped back to sentinels by the client.
const (
	codeUnavailable = "unavailable"
	codeNotAttached = "not_attached"
	codeLearnedCap  = "learned_cap"
	codeInvalid     = "invalid"
	codeVersion     = "version"
)

type detachPayload struct {
	ID string     `json:"id"`
	IP netip.Addr `json:"ip"`
}

type setBlockedPayload struct {
	ID     string      `json:"id"`
	Reason BlockReason `json:"reason"`
	On     bool        `json:"on"`
}

// Bridge is one sandbox bridge the gateway binds its listeners on (eng
// re-review S5: sandboxd discovers bridges; the gateway has no docker
// socket access).
type Bridge struct {
	Name      string     `json:"name"`
	GatewayIP netip.Addr `json:"gateway_ip"`
}

// ProbeRequest asks the gateway to treat a probe source as gateway-mode for
// the self-test (T41): sandboxd runs the probe client from a link-local /32
// in a test netns; the gateway reports whether the probe reached its
// listeners.
type ProbeRequest struct {
	Bridge string        `json:"bridge"`
	Source netip.Addr    `json:"source"`
	Begin  bool          `json:"begin"`
	Wait   time.Duration `json:"wait,omitempty"`
}

// ProbeResult reports what the listeners saw during a probe window.
type ProbeResult struct {
	DNSSeen   bool `json:"dns_seen"`
	ProxySeen bool `json:"proxy_seen"`
}

// ReadyStatus is the gateway's health as seen over the UDS.
type ReadyStatus struct {
	Layout    bool     `json:"layout"`
	Listeners []string `json:"listeners,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// Event is pushed to subscribers: audit decisions and heartbeat state.
type Event struct {
	Kind        string    `json:"kind"` // "audit" | "heartbeat"
	SandboxID   string    `json:"sandbox_id,omitempty"`
	Result      string    `json:"result,omitempty"` // allowed | denied
	Reason      string    `json:"reason,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Rule        string    `json:"rule,omitempty"`
	Mode        string    `json:"mode,omitempty"`
	Time        time.Time `json:"time,omitempty"`
	// Heartbeat fields.
	LayoutOK       bool   `json:"layout_ok,omitempty"`
	AuditDropped   uint64 `json:"audit_dropped,omitempty"`
	AttachFailed   uint64 `json:"attach_failed,omitempty"`
	FQDNSandboxes  int    `json:"fqdn_sandboxes,omitempty"`
	ProxyConns     int    `json:"proxy_conns,omitempty"`
	LayoutLostSeen bool   `json:"layout_lost,omitempty"`
}

// ErrVersionMismatch means the peer speaks a protocol two or more versions
// away. sandboxd refuses gateway-mode creates (503) but keeps Detach working.
var ErrVersionMismatch = errors.New("egress: gateway protocol version mismatch")

// negotiate picks the highest version both sides accept.
func negotiate(offered []int) (int, bool) {
	best := 0
	for _, v := range offered {
		if (v == ProtocolVersion || v == ProtocolVersion-1) && v > best && v > 0 {
			best = v
		}
	}
	return best, best > 0
}

type frameReader struct{ r *bufio.Reader }

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{r: bufio.NewReaderSize(r, 64<<10)}
}

func (f *frameReader) read(v any) error {
	var buf []byte
	for {
		chunk, isPrefix, err := f.r.ReadLine()
		if err != nil {
			return err
		}
		buf = append(buf, chunk...)
		if len(buf) > maxFrame {
			return fmt.Errorf("egress: frame exceeds %d bytes", maxFrame)
		}
		if !isPrefix {
			break
		}
	}
	return json.Unmarshal(buf, v)
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func codeFor(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNotAttached):
		return codeNotAttached
	case errors.Is(err, ErrLearnedCap):
		return codeLearnedCap
	case errors.Is(err, ErrUnavailable):
		return codeUnavailable
	case errors.Is(err, ErrVersionMismatch):
		return codeVersion
	default:
		return codeInvalid
	}
}

func errFor(code, msg string) error {
	switch code {
	case "":
		return nil
	case codeNotAttached:
		return fmt.Errorf("%w: %s", ErrNotAttached, msg)
	case codeLearnedCap:
		return fmt.Errorf("%w: %s", ErrLearnedCap, msg)
	case codeUnavailable:
		return fmt.Errorf("%w: %s", ErrUnavailable, msg)
	case codeVersion:
		return fmt.Errorf("%w: %s", ErrVersionMismatch, msg)
	default:
		return errors.New(msg)
	}
}
