package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// ResidentServer serves the worker protocol backed by a MultiInstanceEngine:
// one resident process compiles a module once and hosts many isolated sandbox
// instances (compile-once, instantiate-many). Spawned via `--wasm-resident-host`.
//
// Phase 2b PR-A: per-instance egress via MultiInstanceEngine.SetNetworkHook
// (name-keyed hooks + conn ownership) and a shared NetMediator. Listener
// (expose_port/HTTP) and checkpoint/restore remain rejected — those stay on the
// per-sandbox cold path (migrate-on-expose is PR-B).
type ResidentServer struct {
	mu            sync.Mutex
	eng           *wasmengine.MultiInstanceEngine
	loadedPath    string
	net           *NetMediator
	workerNet     map[string]*workerNetUsage
	lastCaps      map[string]wasmengine.Capabilities
	auditMu       sync.RWMutex
	auditBindings map[string]egressAuditBinding
}

func (s *ResidentServer) mediator() *NetMediator {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.net == nil {
		s.net = newNetMediator()
		installDefaultEgressObserver(s.net, s.auditBinding)
	}
	return s.net
}

func (s *ResidentServer) setAuditBinding(sandboxID string, caps wasmengine.Capabilities) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if s.auditBindings == nil {
		s.auditBindings = make(map[string]egressAuditBinding)
	}
	s.auditBindings[sandboxID] = egressAuditBinding{capability: caps.AuditCapability, incarnationID: caps.AuditIncarnation}
}

func (s *ResidentServer) auditBinding(sandboxID string) (egressAuditBinding, bool) {
	s.auditMu.RLock()
	defer s.auditMu.RUnlock()
	b, ok := s.auditBindings[sandboxID]
	return b, ok
}

func (s *ResidentServer) clearAuditBinding(sandboxID string) {
	s.auditMu.Lock()
	delete(s.auditBindings, sandboxID)
	s.auditMu.Unlock()
}

func (s *ResidentServer) netUsageFor(sandboxID string) *workerNetUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workerNet == nil {
		s.workerNet = make(map[string]*workerNetUsage)
	}
	if s.workerNet[sandboxID] == nil {
		s.workerNet[sandboxID] = &workerNetUsage{}
	}
	return s.workerNet[sandboxID]
}

func (s *ResidentServer) bindNetworkHook(eng *wasmengine.MultiInstanceEngine, sandboxID string) {
	if eng == nil || sandboxID == "" {
		return
	}
	m := s.mediator()
	usage := s.netUsageFor(sandboxID)
	eng.SetNetworkHook(sandboxID, &wasmengine.NetworkHook{
		SandboxID: sandboxID,
		Dial:      mediatorDialer{m: m, sandboxID: sandboxID},
		Meter:     &workerByteMeter{u: usage},
	})
}

func (s *ResidentServer) clearNetworkHook(eng *wasmengine.MultiInstanceEngine, sandboxID string) {
	if eng == nil {
		return
	}
	eng.ClearNetworkHook(sandboxID)
	s.mu.Lock()
	delete(s.workerNet, sandboxID)
	delete(s.lastCaps, sandboxID)
	s.mu.Unlock()
}

func (s *ResidentServer) storeCaps(sandboxID string, caps wasmengine.Capabilities) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastCaps == nil {
		s.lastCaps = make(map[string]wasmengine.Capabilities)
	}
	s.lastCaps[sandboxID] = caps
}

func (s *ResidentServer) capsFor(sandboxID string) wasmengine.Capabilities {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCaps[sandboxID]
}

func (s *ResidentServer) engine() *wasmengine.MultiInstanceEngine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng
}

// Serve accepts framed control messages on conn until EOF or an unrecoverable
// error. Multiple connections may be served concurrently; the MultiInstanceEngine
// is internally synchronized.
func (s *ResidentServer) Serve(conn net.Conn) error {
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
	// unsupported rejects a message type that resident-host mode does not serve
	// in this cut, so a misrouted request fails loudly instead of hanging.
	unsupported := func(sandboxID, op string) error {
		return replyErr(sandboxID, fmt.Errorf("%s not supported in resident-host mode (route to per-sandbox worker)", op))
	}

	for {
		env, err := readFrame(conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case MsgHealthPing:
			if err := writeFrame(conn, Envelope{Type: MsgPong, SandboxID: env.SandboxID}); err != nil {
				return err
			}
		case MsgInstanceStatus:
			eng := s.engine()
			loaded := eng != nil && eng.Loaded()
			if eng != nil && env.SandboxID != "" {
				// Prefer per-sandbox liveness when a sandboxID is supplied so
				// Inspect can detect a gone instance after host respawn.
				loaded = eng.HasInstance(env.SandboxID)
			}
			body, encErr := encodePayload(instanceStatusPayload{Loaded: loaded})
			if encErr != nil {
				return encErr
			}
			if err := writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body}); err != nil {
				return err
			}
		case MsgTriggerPanic:
			panic("wasm resident worker test panic")
		case MsgLoadModule:
			var p loadModulePayload
			if err := decodePayload(env.Payload, &p); err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			// Hold the server lock across check+load so two concurrent
			// different-path loads cannot both pass prev=="" (D8).
			s.mu.Lock()
			prev := s.loadedPath
			if prev != "" && prev != p.Path {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("resident host already bound to %q, refusing to load %q", prev, p.Path)) != nil {
					return err
				}
				continue
			}
			var eng *wasmengine.MultiInstanceEngine
			var ensureErr error
			if s.eng == nil {
				eng, ensureErr = wasmengine.NewMultiInstanceEngine(ctx, p.MemoryMB)
				if ensureErr != nil {
					s.mu.Unlock()
					if replyErr(env.SandboxID, ensureErr) != nil {
						return err
					}
					continue
				}
				s.eng = eng
			} else {
				eng = s.eng
			}
			var timings wasmengine.LoadTimings
			if prev != p.Path {
				if loadErr := eng.LoadModule(ctx, p.Path); loadErr != nil {
					s.mu.Unlock()
					if replyErr(env.SandboxID, loadErr) != nil {
						return err
					}
					continue
				}
				timings = eng.LastLoadTimings()
				s.loadedPath = p.Path
			}
			s.mu.Unlock()
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
			if p.Caps.ListenEnabled() {
				if unsupported(env.SandboxID, "wasip1 listener (expose_port/HTTP)") != nil {
					return err
				}
				continue
			}
			s.setAuditBinding(env.SandboxID, p.Caps)
			eng := s.engine()
			if eng == nil {
				s.clearAuditBinding(env.SandboxID)
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(eng, env.SandboxID)
			if err := eng.Instantiate(ctx, env.SandboxID, p.Caps); err != nil {
				s.clearAuditBinding(env.SandboxID)
				s.clearNetworkHook(eng, env.SandboxID)
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			s.storeCaps(env.SandboxID, p.Caps)
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
			eng := s.engine()
			if eng == nil {
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(eng, env.SandboxID)
			s.storeCaps(env.SandboxID, p.Caps)
			result, runErr := eng.Run(ctx, env.SandboxID, p.Caps, p.Export)
			if runErr != nil && result.ExitCode == 0 && result.Stderr == "" {
				if replyErr(env.SandboxID, runErr) != nil {
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
			eng := s.engine()
			if eng == nil {
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(eng, env.SandboxID)
			// Honor caps wall timeout (D8) — previously invoked with Background.
			invokeCtx, cancel := wasmengine.WithInvocationDeadline(ctx, s.capsFor(env.SandboxID))
			invokeErr := eng.InvokeExport(invokeCtx, env.SandboxID, p.Export)
			cancel()
			if invokeErr != nil {
				if replyErr(env.SandboxID, invokeErr) != nil {
					return err
				}
				continue
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		case MsgStopInstance:
			eng := s.engine()
			if eng != nil {
				if err := eng.StopInstance(ctx, env.SandboxID); err != nil {
					if replyErr(env.SandboxID, err) != nil {
						return err
					}
					continue
				}
				s.clearNetworkHook(eng, env.SandboxID)
				s.clearAuditBinding(env.SandboxID)
				_, _ = s.mediator().DrainUsage(env.SandboxID)
			}
			if err := replyOK(env.SandboxID); err != nil {
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
		default:
			// Checkpoint/Restore and listener ops are not served by a resident host.
			if unsupported(env.SandboxID, string(env.Type)) != nil {
				return err
			}
		}
	}
}

// ServeSocketPathResident listens on a Unix socket and serves each connection
// with a shared ResidentServer (one MultiInstanceEngine per process).
func ServeSocketPathResident(socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &ResidentServer{}
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

// RunCLIResident is the `--wasm-resident-host <socket>` entrypoint.
func RunCLIResident(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: --wasm-resident-host <socket-path>")
	}
	return ServeSocketPathResident(args[0])
}
