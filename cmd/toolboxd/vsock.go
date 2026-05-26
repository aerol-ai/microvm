package main

// vsock.go is the portable protocol layer for the toolbox-on-guest's
// virtio-vsock listener. The Linux socket binding lives in vsock_linux.go
// (and a stub in vsock_other.go for the darwin/CI build). This file
// contains the protocol shape and connection handler so the bulk of the
// logic is testable without AF_VSOCK on the host.
//
// Why vsock at all: when a Firecracker snapshot is taken and the VMM is
// later resumed (possibly as a clone, possibly minutes later), any
// host↔guest TCP connection tears — the TCP state on both sides
// disagrees about sequence numbers, source ports, even network paths.
// virtio-vsock is snapshot-safe: the virtio device is reset on resume
// and new connections work transparently. The toolbox in the guest
// listens on (CID 3, port 1024); the host's runtime driver dials
// (CID 2, port 1024) to deliver pre-snapshot and post-resume signals.
//
// What this channel does NOT carry: the regular HTTP toolbox API. That
// stays on TCP/eth0 — it's only used during the sandbox's running
// lifetime (no snapshots in flight), so the snapshot-tear problem
// doesn't apply. Vsock is reserved for control-plane signals tied to the
// snapshot lifecycle.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// defaultVsockPort is the in-guest port the toolbox listens on. The host
// runtime driver dials this. 1024 is the lowest non-privileged port on
// Linux and matches the value baked into the agent's snapshot
// boot-args; if you change it, update both ends together.
const defaultVsockPort uint32 = 1024

// VsockOp is the small set of ops the host can issue. Closed set on
// purpose — every op the host can trigger must be acknowledged here so
// a buggy host can't put the guest agent into an undefined state.
type VsockOp string

const (
	// OpPing is a liveness probe. Used by the runtime driver's
	// post-resume readiness check (it dials, sends Ping, expects an
	// ack within a few hundred ms — that's the canonical proof the
	// guest is up and the vsock channel survived the resume).
	OpPing VsockOp = "ping"
	// OpPreSnapshot tells the guest "host is about to take a snapshot.
	// Quiesce any state that would be stale on a clone." The agent flushes
	// session-manager buffers, closes TCP sockets it owns, and acks.
	// Failure to ack within the host's deadline still allows the snapshot
	// to proceed — quiesce is best-effort, not blocking.
	OpPreSnapshot VsockOp = "pre_snapshot"
	// OpPostResume is the inverse. The agent re-stamps log lines with a
	// "resumed at <ts>" marker (useful for triaging snapshot-related
	// bugs in production) and re-arms any wall-clock-sensitive watchers.
	OpPostResume VsockOp = "post_resume"
)

// VsockMessage is the request shape. Newline-delimited JSON, one
// message per line. Tiny and human-readable — useful when diagnosing
// with `socat - VSOCK-CONNECT:2:1024` from the host.
type VsockMessage struct {
	Op   VsockOp         `json:"op"`
	Data json.RawMessage `json:"data,omitempty"`
}

// VsockResponse is the ack shape. Either Ok=true or Error is set;
// callers never get both. Kept narrow so the wire shape can grow without
// breaking older hosts (json decode ignores unknown fields).
type VsockResponse struct {
	Ok    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}

// VsockHandler is what the toolbox-on-guest implements. Each callback
// gets a context with a deadline derived from the host's per-op timeout
// (the protocol layer enforces one read deadline per message). Returning
// an error sends VsockResponse{Error: err.Error()}; nil sends Ok.
//
// Handlers should be fast (single-digit ms): they run on the agent's
// vsock goroutine and the host blocks on the ack.
type VsockHandler interface {
	OnPing(ctx context.Context) error
	OnPreSnapshot(ctx context.Context, raw json.RawMessage) error
	OnPostResume(ctx context.Context, raw json.RawMessage) error
}

// vsockReadDeadline is the per-message read budget enforced by
// handleVsockConn. Generous — the host should send the op as soon as it
// dials and then wait for the ack. Tightening this risks aborting on a
// slow host but is otherwise harmless because the host retries.
const vsockReadDeadline = 5 * time.Second

// handleVsockConn drives one accepted connection through its message
// loop. Exported only via the linux serveVsock wrapper; broken out so
// vsock_test.go can drive it with an io.Pipe and skip the socket
// layer entirely.
//
// The loop reads newline-delimited JSON messages, dispatches each to
// the handler, writes the ack, and continues until the peer closes
// the connection or a decode error occurs. A decode error is fatal for
// the connection (we don't try to recover — the host should reconnect),
// because mid-line garbage could be the result of a snapshot
// race-condition we'd rather surface as "channel reset" than swallow.
func handleVsockConn(ctx context.Context, rw io.ReadWriter, handler VsockHandler, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	reader := bufio.NewReader(rw)
	encoder := json.NewEncoder(rw)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Debug("vsock read", "error", err)
			}
			return
		}
		var msg VsockMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			_ = encoder.Encode(VsockResponse{Error: fmt.Sprintf("decode: %v", err)})
			return
		}
		opCtx, cancel := context.WithTimeout(ctx, vsockReadDeadline)
		err = dispatchVsock(opCtx, msg, handler)
		cancel()
		if err != nil {
			_ = encoder.Encode(VsockResponse{Error: err.Error()})
			// Per-op errors do not close the connection — the host may
			// follow up with a different op (e.g. Ping after a failed
			// pre_snapshot). Closing on error would force a reconnect
			// loop that masks the underlying error.
			continue
		}
		if err := encoder.Encode(VsockResponse{Ok: true}); err != nil {
			logger.Debug("vsock write", "error", err)
			return
		}
	}
}

// dispatchVsock maps a decoded message to a handler call. Unknown ops
// return an error so a host with a newer protocol gets a clear "no such
// op" rather than silent success.
func dispatchVsock(ctx context.Context, msg VsockMessage, handler VsockHandler) error {
	switch msg.Op {
	case OpPing:
		return handler.OnPing(ctx)
	case OpPreSnapshot:
		return handler.OnPreSnapshot(ctx, msg.Data)
	case OpPostResume:
		return handler.OnPostResume(ctx, msg.Data)
	case "":
		return errors.New("missing op")
	default:
		return fmt.Errorf("unknown op %q", msg.Op)
	}
}

// quiesceOps is the host-kernel-state resync seam used by the
// post_resume handler. Linux gets a real implementation in
// quiesce_linux.go (RNDADDENTROPY ioctl + ClockSettime syscall);
// non-Linux build targets get the stub in quiesce_other.go that
// returns "linux-only" errors. Defined as an interface so tests can
// inject a recorder fake.
type quiesceOps interface {
	ReseedRandom() error
	SetWallclock(unixNs int64) error
}

// sessionFlusher is the subset of behaviour the quiesce handler needs
// from the sessions package. Returning just the session IDs (rather
// than the full models.Session) keeps the interface narrow enough
// that vsock_test.go's fake is a few lines, and avoids importing the
// sessions package from vsock.go. main.go wires the real adapter.
type sessionFlusher interface {
	ListIDs() []string
	FlushRecording(id string) error
}

// quiesceHandler is the production VsockHandler. PR-A's
// loggingVsockHandler logged and acked; PR-B does real work:
//   - OnPreSnapshot best-effort fsyncs every active session
//     recording so a clone resumed from the snapshot observes a
//     recording that ends cleanly at the freeze point. Template
//     captures have no sessions so this is a no-op there.
//   - OnPostResume reseeds the kernel RNG (every clone resumes with
//     the template's entropy pool — a real crypto bug otherwise) and
//     resyncs CLOCK_REALTIME from the host's wall clock carried in
//     the message payload. Quiesce errors are logged at Warn and the
//     ack is still Ok=true — the clone is already serving requests,
//     telling the host to retry won't unbreak anything.
type quiesceHandler struct {
	logger   *slog.Logger
	sessions sessionFlusher
	quiesce  quiesceOps
}

func newQuiesceHandler(logger *slog.Logger, sessions sessionFlusher) *quiesceHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &quiesceHandler{
		logger:   logger,
		sessions: sessions,
		quiesce:  newQuiesceOps(),
	}
}

func (h *quiesceHandler) OnPing(ctx context.Context) error {
	return nil
}

func (h *quiesceHandler) OnPreSnapshot(ctx context.Context, _ json.RawMessage) error {
	if h.sessions != nil {
		for _, id := range h.sessions.ListIDs() {
			if err := h.sessions.FlushRecording(id); err != nil {
				h.logger.Debug("vsock pre_snapshot: session flush failed",
					"session_id", id, "error", err)
			}
		}
	}
	h.logger.Info("vsock: pre_snapshot quiesce complete")
	return nil
}

func (h *quiesceHandler) OnPostResume(ctx context.Context, raw json.RawMessage) error {
	var data struct {
		WallclockUnixNs int64 `json:"wallclock_unix_ns"`
	}
	if len(raw) > 0 {
		// Tolerate a missing/malformed payload — the RNG reseed is
		// still worth doing even without a wallclock signal.
		_ = json.Unmarshal(raw, &data)
	}
	if data.WallclockUnixNs > 0 {
		if err := h.quiesce.SetWallclock(data.WallclockUnixNs); err != nil {
			h.logger.Warn("vsock post_resume: clock resync failed", "error", err)
		}
	}
	if err := h.quiesce.ReseedRandom(); err != nil {
		h.logger.Warn("vsock post_resume: rng reseed failed", "error", err)
	}
	h.logger.Info("vsock: post_resume complete",
		"wallclock_set", data.WallclockUnixNs > 0)
	return nil
}
