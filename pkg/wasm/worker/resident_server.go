package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// ResidentServer serves the worker protocol backed by a MultiInstanceEngine:
// one resident process compiles a module once and hosts many isolated sandbox
// instances (compile-once, instantiate-many). It is the Phase 2 host process
// for plans/wasm-resident-module-host.md, spawned via `--wasm-resident-host`.
//
// Scope (initial cut, default-off): non-listen, non-networking sandboxes —
// LoadModule (once, host-level), Instantiate/Exec/Invoke/StopInstance keyed by
// sandboxID. Listener (expose_port/HTTP), checkpoint/restore, and per-instance
// egress mediation are rejected here on purpose; the driver routes those to the
// per-sandbox cold path. Per-instance egress isolation on a shared runtime
// (name-keyed hooks + conn ownership) is the eng-review-gated Phase 2 remainder.
type ResidentServer struct {
	mu         sync.Mutex
	eng        *wasmengine.MultiInstanceEngine
	loadedPath string
}

// ensureEngine lazily builds the MultiInstanceEngine on the first LoadModule,
// fixing the runtime memory limit to the bucket's memoryMB.
func (s *ResidentServer) ensureEngine(ctx context.Context, memoryMB int) (*wasmengine.MultiInstanceEngine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eng == nil {
		eng, err := wasmengine.NewMultiInstanceEngine(ctx, memoryMB)
		if err != nil {
			return nil, err
		}
		s.eng = eng
	}
	return s.eng, nil
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
			eng, err := s.ensureEngine(ctx, p.MemoryMB)
			if err != nil {
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			// A resident host is one (module, memoryMB) bucket. Loading a second,
			// different module into it is a routing bug — reject rather than blow
			// away the compiled module other live instances depend on.
			s.mu.Lock()
			prev := s.loadedPath
			s.mu.Unlock()
			if prev != "" && prev != p.Path {
				if replyErr(env.SandboxID, fmt.Errorf("resident host already bound to %q, refusing to load %q", prev, p.Path)) != nil {
					return err
				}
				continue
			}
			var timings wasmengine.LoadTimings
			if prev != p.Path {
				if err := eng.LoadModule(ctx, p.Path); err != nil {
					if replyErr(env.SandboxID, err) != nil {
						return err
					}
					continue
				}
				timings = eng.LastLoadTimings()
				s.mu.Lock()
				s.loadedPath = p.Path
				s.mu.Unlock()
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
			if p.Caps.ListenEnabled() {
				if unsupported(env.SandboxID, "wasip1 listener (expose_port/HTTP)") != nil {
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
			if err := eng.Instantiate(ctx, env.SandboxID, p.Caps); err != nil {
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
			eng := s.engine()
			if eng == nil {
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
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
			eng := s.engine()
			if eng == nil {
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			if err := eng.InvokeExport(ctx, env.SandboxID, p.Export); err != nil {
				if replyErr(env.SandboxID, err) != nil {
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
			}
			if err := replyOK(env.SandboxID); err != nil {
				return err
			}
		default:
			// Checkpoint/Restore, listener, network, and netstats ops are not
			// served by a resident host in this cut.
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
