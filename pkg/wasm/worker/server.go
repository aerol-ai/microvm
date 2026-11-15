package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Server holds one wazero engine per worker process (D11: one module per worker).
type Server struct {
	mu            sync.Mutex
	eng           wasmengine.Engine
	lastCaps      wasmengine.Capabilities
	net           *NetMediator
	auditMu       sync.RWMutex
	auditBindings map[string]egressAuditBinding
	// workerNet accumulates guest-side IO proxy bytes until MsgNetstatsTick
	// drains them. netMu guards the map: connections are served
	// concurrently, and a stream adds bytes while other messages run.
	netMu     sync.Mutex
	workerNet map[string]*workerNetUsage
	// holder is the sandbox whose instance this worker holds, set by the
	// first Instantiate or Restore that names one and kept for the process's
	// life (refuseForeign). Atomic, not under mu: every message reads it,
	// and mu is held across module compiles and checkpoints.
	holder atomic.Pointer[string]
	// modulePath and moduleMemoryMB record the last MsgLoadModule, so a
	// stream that names no module runs the sandbox's own (guarded by mu).
	modulePath     string
	moduleMemoryMB int
	streams        streamRegistry
	entry          entrypointLog // the serving guest's output (entrypoint.go)
}

// errForeignSandbox refuses a message for another sandbox than the one
// whose instance the worker holds. It names neither sandbox: the error can
// reach the caller of the request that carried the wrong id.
var errForeignSandbox = errors.New("wasm worker holds another sandbox's instance")

// holderID is the sandbox this worker holds, "" before its first instance.
func (s *Server) holderID() string {
	if p := s.holder.Load(); p != nil {
		return *p
	}
	return ""
}

// bindHolder records sandboxID as the holder once an instance of it is up.
// The caller holds mu, which serializes Instantiate and Restore, and has
// checked (refuseForeign) that no other sandbox holds the worker.
func (s *Server) bindHolder(sandboxID string) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID != "" && s.holder.Load() == nil {
		s.holder.Store(&sandboxID)
	}
}

// refuseForeign keeps a per-sandbox worker to its one sandbox. sandboxd
// reaches a worker by its socket path, and a path can lead to the wrong
// worker: a pre-upgrade sandbox's socket sits in its own /work, where the
// guest can swap it for a link to another sandbox's socket. Once the worker
// holds an instance, a message for any other sandbox is refused, so such a
// swap breaks only the sandbox that made it. Ping and the status question
// are answered for anyone: they reveal nothing and change nothing. Ids
// are trimmed as MsgNetstatsTick trims them.
func (s *Server) refuseForeign(env Envelope) error {
	switch env.Type {
	case MsgHealthPing, MsgInstanceStatus:
		return nil
	}
	id := strings.TrimSpace(env.SandboxID)
	if holder := s.holderID(); holder != "" && id != "" && id != holder {
		return errForeignSandbox
	}
	return nil
}

type workerNetUsage struct {
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func (s *Server) netUsageFor(sandboxID string) *workerNetUsage {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.workerNet == nil {
		s.workerNet = make(map[string]*workerNetUsage)
	}
	if s.workerNet[sandboxID] == nil {
		s.workerNet[sandboxID] = &workerNetUsage{}
	}
	return s.workerNet[sandboxID]
}

func (s *Server) mediator() *NetMediator {
	if s.net == nil {
		s.net = newNetMediator()
		// Worker process: append egress destinations to the daemon's audit JSONL
		// (cannot import internal/service). Dial-path only; never create.
		installDefaultEgressObserver(s.net, s.auditBinding)
		installOperatorGuard(s.net)
	}
	return s.net
}

// close stops the mediator's operator-file poll and every stream with the worker.
func (s *Server) close() {
	s.streams.closeAll()
	s.mu.Lock()
	m := s.net
	s.mu.Unlock()
	m.stopOperatorWatch()
}

// serverStreamHost adapts Server to the shared stream code, taking s.mu for
// the lazily built mediator and the loaded module.
type serverStreamHost struct{ s *Server }

func (h serverStreamHost) mediator() *NetMediator {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	return h.s.mediator()
}

func (h serverStreamHost) streamUsage(sandboxID string) *workerNetUsage {
	return h.s.netUsageFor(sandboxID)
}

func (h serverStreamHost) ownModule() (string, int) {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	return h.s.modulePath, h.s.moduleMemoryMB
}

func (s *Server) setAuditBinding(sandboxID string, caps wasmengine.Capabilities) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if s.auditBindings == nil {
		s.auditBindings = make(map[string]egressAuditBinding)
	}
	s.auditBindings[sandboxID] = egressAuditBinding{capability: caps.AuditCapability, incarnationID: caps.AuditIncarnation}
}

func (s *Server) auditBinding(sandboxID string) (egressAuditBinding, bool) {
	s.auditMu.RLock()
	defer s.auditMu.RUnlock()
	b, ok := s.auditBindings[sandboxID]
	return b, ok
}

func (s *Server) clearAuditBinding(sandboxID string) {
	s.auditMu.Lock()
	delete(s.auditBindings, sandboxID)
	s.auditMu.Unlock()
}

// syncResolvedListenPort copies the host port for an ephemeral wasip1 listener into caps.
func (s *Server) syncResolvedListenPort(caps *wasmengine.Capabilities) {
	if caps == nil || !caps.ListenEnabled() || caps.WASIListenPort != 0 || s.eng == nil {
		return
	}
	if port, ok := s.eng.ResolvedListenPort(); ok && port > 0 {
		caps.WASIListenPort = port
	}
}

type mediatorDialer struct {
	m         *NetMediator
	sandboxID string
}

func (d mediatorDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.m.DialContext(ctx, d.sandboxID, network, address)
}

type workerByteMeter struct {
	u *workerNetUsage
}

func (m *workerByteMeter) AddIn(n int64) {
	if m != nil && m.u != nil {
		m.u.bytesIn.Add(n)
	}
}

func (m *workerByteMeter) AddOut(n int64) {
	if m != nil && m.u != nil {
		m.u.bytesOut.Add(n)
	}
}

func (s *Server) bindNetworkHook(sandboxID string) {
	if s.eng == nil {
		return
	}
	ne, ok := s.eng.(wasmengine.NetworkAwareEngine)
	if !ok {
		return
	}
	m := s.mediator()
	usage := s.netUsageFor(sandboxID)
	ne.SetNetworkHook(&wasmengine.NetworkHook{
		SandboxID: sandboxID,
		Dial:      mediatorDialer{m: m, sandboxID: sandboxID},
		Meter:     &workerByteMeter{u: usage},
	})
}

func (s *Server) clearNetworkHook() {
	if s.eng == nil {
		return
	}
	if ne, ok := s.eng.(wasmengine.NetworkAwareEngine); ok {
		ne.ClearNetworkHook()
	}
}

func workerEngineName() string {
	return strings.TrimSpace(os.Getenv("AEROL_WASM_ENGINE"))
}

// Serve accepts framed control messages on conn until EOF or an unrecoverable error.
func (s *Server) Serve(conn net.Conn) error {
	defer conn.Close()
	ctx := context.Background()

	replyOK := func(sandboxID string) error {
		body, err := encodePayload(okPayload{OK: true})
		if err != nil {
			return err
		}
		return writeFrame(conn, Envelope{Type: MsgOK, SandboxID: sandboxID, Payload: body})
	}
	replyErr := func(sandboxID string, err error) error {
		body, encErr := encodePayload(errorPayload{Message: err.Error()})
		if encErr != nil {
			return encErr
		}
		return writeFrame(conn, Envelope{Type: MsgError, SandboxID: sandboxID, Payload: body})
	}

	for {
		env, err := readFrame(conn)
		if err != nil {
			return err
		}
		// Instantiate and Restore check in their own cases, under mu, where
		// they bind the holder.
		if env.Type != MsgInstantiate && env.Type != MsgRestore {
			if refused := s.refuseForeign(env); refused != nil {
				if werr := replyErr(env.SandboxID, refused); werr != nil {
					return werr
				}
				continue
			}
		}
		switch env.Type {
		case MsgHealthPing:
			if err := writeFrame(conn, Envelope{Type: MsgPong, SandboxID: env.SandboxID}); err != nil {
				return err
			}
		case MsgInstanceStatus:
			s.mu.Lock()
			loaded := s.eng != nil
			s.mu.Unlock()
			holder := s.holderID()
			if asked := strings.TrimSpace(env.SandboxID); asked != "" && asked != holder {
				// Asked about one sandbox, the worker answers for the
				// instance it holds: a restarted sandboxd adopts a worker
				// only for the sandbox that worker says it serves.
				loaded = false
			}
			body, encErr := encodePayload(instanceStatusPayload{Loaded: loaded, SandboxID: holder, Checked: true})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgTriggerPanic:
			panic("wasm worker test panic")
		case MsgLoadModule:
			var p loadModulePayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			// A new module replaces the sandbox's code: its runs of the old
			// code end with it.
			s.streams.killSandbox(env.SandboxID)
			s.mu.Lock()
			if s.eng != nil {
				_ = s.eng.Close(ctx)
				s.eng = nil
			}
			s.modulePath = ""
			newEngStart := time.Now()
			s.eng, err = wasmengine.NewEngineFor(ctx, workerEngineName())
			newEngDur := time.Since(newEngStart)
			if err != nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			err = s.eng.LoadModule(ctx, p.Path, wasmengine.LoadOptions{MemoryMB: p.MemoryMB})
			// Read the engine's sub-stage breakdown before releasing the lock; the
			// worker owns the NewEngineFor cost, so we splice it in here.
			var timings wasmengine.LoadTimings
			if r, ok := s.eng.(wasmengine.LoadTimingReporter); ok {
				timings = r.LastLoadTimings()
			}
			timings.NewEngine = newEngDur
			if err == nil {
				s.modulePath, s.moduleMemoryMB = p.Path, p.MemoryMB
				s.entry.attach(s.eng)
			}
			s.mu.Unlock()
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			body, encErr := encodePayload(loadModuleResultPayload{Timings: timings})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgInstantiate:
			var p instantiatePayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mu.Lock()
			// Under mu, which serializes instantiations: of two first ones
			// for different sandboxes, the second must not replace the
			// instance the first one bound.
			if refused := s.refuseForeign(env); refused != nil {
				s.mu.Unlock()
				if werr := replyErr(env.SandboxID, refused); werr != nil {
					return werr
				}
				continue
			}
			s.setAuditBinding(env.SandboxID, p.Caps)
			if s.eng == nil {
				s.mu.Unlock()
				s.clearAuditBinding(env.SandboxID)
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.mediator().AddBlocks(env.SandboxID, p.Caps.NetworkBlockIngress, p.Caps.NetworkBlockEgress)
			s.mediator().ApplyCapsPolicy(env.SandboxID, p.Caps)
			s.bindNetworkHook(env.SandboxID)
			err = s.eng.Instantiate(ctx, p.Caps)
			if err == nil {
				s.lastCaps = p.Caps
				s.syncResolvedListenPort(&s.lastCaps)
				s.bindHolder(env.SandboxID)
			}
			s.mu.Unlock()
			if err != nil {
				s.clearAuditBinding(env.SandboxID)
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgExec:
			var p execPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if p.Export == "" {
				p.Export = "_start"
			}
			s.mu.Lock()
			if s.eng == nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.mediator().AddBlocks(env.SandboxID, p.Caps.NetworkBlockIngress, p.Caps.NetworkBlockEgress)
			s.mediator().ApplyCapsPolicy(env.SandboxID, p.Caps)
			s.bindNetworkHook(env.SandboxID)
			caps := p.Caps
			eng := s.eng
			s.mu.Unlock()
			result, err := eng.Run(ctx, caps, p.Export)
			// Guest→host WASI output bytes; socket bytes come from NetMediator (UC-43).
			if out := int64(len(result.Stdout) + len(result.Stderr)); out > 0 {
				s.netUsageFor(env.SandboxID).bytesOut.Add(out)
			}
			if err != nil && result.ExitCode == 0 && result.Stderr == "" {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			body, encErr := encodePayload(execResultPayload{
				ExitCode: result.ExitCode,
				Stdout:   result.Stdout,
				Stderr:   result.Stderr,
				Usage:    result.Usage,
			})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgInvokeResult, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgInvoke:
			var p invokePayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if p.Export == "" {
				p.Export = "_start"
			}
			s.mu.Lock()
			if s.eng == nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(env.SandboxID)
			invokeCtx, cancel := wasmengine.WithInvocationDeadline(ctx, s.lastCaps)
			eng := s.eng
			s.mu.Unlock()
			start := time.Now()
			gen := s.entry.begin(env.SandboxID)
			err = eng.InvokeExport(invokeCtx, p.Export)
			s.entry.end(gen, err)
			_ = time.Since(start) // wall time accounted on Exec path via RunResult
			cancel()
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgStopInstance:
			s.streams.killSandbox(env.SandboxID)
			s.mu.Lock()
			if s.eng != nil {
				err = s.eng.StopInstance(ctx)
				s.clearNetworkHook()
			}
			s.mu.Unlock()
			s.clearAuditBinding(env.SandboxID)
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgCheckpoint:
			var p checkpointPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mu.Lock()
			if s.eng == nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			capture, err := s.eng.CaptureSnapshot(ctx)
			s.mu.Unlock()
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			capture.Config = p.Meta
			if err := wasmengine.WriteSnapshotDir(p.OutDir, capture); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			body, encErr := encodePayload(checkpointResultPayload{
				CloneGeneration: p.Meta.CloneGeneration,
			})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgRestore:
			var p restorePayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			snap, err := wasmengine.ReadSnapshotDir(p.Dir, wasmengine.EngineNameWazero())
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mu.Lock()
			if refused := s.refuseForeign(env); refused != nil {
				s.mu.Unlock()
				if werr := replyErr(env.SandboxID, refused); werr != nil {
					return werr
				}
				continue
			}
			s.setAuditBinding(env.SandboxID, p.Caps)
			if s.eng == nil {
				s.mu.Unlock()
				s.clearAuditBinding(env.SandboxID)
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.mediator().AddBlocks(env.SandboxID, p.Caps.NetworkBlockIngress, p.Caps.NetworkBlockEgress)
			s.mediator().ApplyCapsPolicy(env.SandboxID, p.Caps)
			s.bindNetworkHook(env.SandboxID)
			err = s.eng.RestoreSnapshot(ctx, snap, p.Caps)
			if err == nil {
				s.lastCaps = p.Caps
				s.syncResolvedListenPort(&s.lastCaps)
				s.bindHolder(env.SandboxID)
			}
			s.mu.Unlock()
			if err != nil {
				s.clearAuditBinding(env.SandboxID)
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgSetCapability:
			var p setCapabilityPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mu.Lock()
			if s.eng == nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(env.SandboxID)
			next := s.lastCaps
			if p.Caps.MemoryMB > 0 {
				next.MemoryMB = p.Caps.MemoryMB
			}
			if p.Caps.WallTimeoutNs > 0 {
				next.WallTimeoutNs = p.Caps.WallTimeoutNs
			}
			err = s.eng.Instantiate(ctx, next)
			if err == nil {
				s.lastCaps = next
				s.syncResolvedListenPort(&s.lastCaps)
			}
			s.mu.Unlock()
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgSetEgressPolicy:
			var p setEgressPolicyPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mediator().SetPolicy(env.SandboxID, compileLists(p.AllowOut, p.DenyOut, p.Learn))
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgEgressLearned:
			body, encErr := encodePayload(s.mediator().Learned(env.SandboxID))
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgSetNetworkBlocks:
			var p setNetworkBlocksPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mediator().SetBlocks(env.SandboxID, p.BlockIngress, p.BlockEgress)
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgSetListenPort:
			var p setListenPortPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.mu.Lock()
			if s.eng == nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			if p.Port != wasmengine.WASIListenPortDisabled && !s.eng.SupportsListen() {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("HTTP ingress (expose_port) is not supported on the %q WASM engine; use SB_WASM_ENGINE=wazero", workerEngineName())) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(env.SandboxID)
			next := s.lastCaps
			next.WASIListenPort = p.Port
			if strings.TrimSpace(p.Host) != "" {
				next.WASIListenHost = p.Host
			}
			err = s.eng.Instantiate(ctx, next)
			if err == nil {
				s.lastCaps = next
				s.syncResolvedListenPort(&s.lastCaps)
			}
			s.mu.Unlock()
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgListenPort:
			s.mu.Lock()
			port := s.lastCaps.WASIListenPort
			s.mu.Unlock()
			body, encErr := encodePayload(listenPortResultPayload{Port: port})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgProxyHTTP:
			var p proxyHTTPPayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			result, err := s.proxyGuestHTTPFromPayload(ctx, env.SandboxID, p)
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			body, encErr := encodePayload(result)
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgProxyHTTPResult, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgNetstatsTick:
			sandboxID := strings.TrimSpace(env.SandboxID)
			u := s.netUsageFor(sandboxID)
			sockIn, sockOut := s.mediator().DrainUsage(sandboxID)
			body, encErr := encodePayload(netstatsResultPayload{
				BytesIn:  u.bytesIn.Swap(0) + sockIn,
				BytesOut: u.bytesOut.Swap(0) + sockOut,
			})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: sandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgExecStart:
			// The connection now belongs to the run; it closes when the run ends.
			return s.streams.serve(serverStreamHost{s: s}, conn, env)
		case MsgExecKill:
			if err := s.streams.serveExecKill(conn, env); err != nil {
				return err
			}
		case MsgEntrypointLogs:
			// The connection may become a follow; it closes when that ends.
			return s.entry.serve(conn, env)
		default:
			if err := writeFrame(conn, Envelope{
				Type:      MsgInvokeResult,
				SandboxID: env.SandboxID,
			}); err != nil {
				return err
			}
		}
	}
}

// ServeSocketPath listens on a Unix domain socket and serves each connection concurrently.
func ServeSocketPath(socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &Server{}
	defer srv.close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			_ = srv.Serve(c)
		}(conn)
	}
}
