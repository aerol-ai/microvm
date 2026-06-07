package worker

import (
	"context"
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
	mu       sync.Mutex
	eng      wasmengine.Engine
	lastCaps wasmengine.Capabilities
	net      *NetMediator
	// workerNet accumulates guest-side IO proxy bytes until MsgNetstatsTick drains them.
	workerNet map[string]*workerNetUsage
}

type workerNetUsage struct {
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func (s *Server) netUsageFor(sandboxID string) *workerNetUsage {
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
	}
	return s.net
}

type mediatorDialer struct {
	m         *NetMediator
	sandboxID string
}

func (d mediatorDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.m.DialContext(ctx, d.sandboxID, network, address)
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
	ne.SetNetworkHook(&wasmengine.NetworkHook{
		SandboxID: sandboxID,
		Dial:      mediatorDialer{m: m, sandboxID: sandboxID},
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
		switch env.Type {
		case MsgHealthPing:
			if err := writeFrame(conn, Envelope{Type: MsgPong, SandboxID: env.SandboxID}); err != nil {
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
			s.mu.Lock()
			if s.eng != nil {
				_ = s.eng.Close(ctx)
				s.eng = nil
			}
			s.eng, err = wasmengine.NewEngineFor(ctx, workerEngineName())
			if err != nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, err) != nil {
					return err
				}
				continue
			}
			err = s.eng.LoadModule(ctx, p.Path)
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
		case MsgInstantiate:
			var p instantiatePayload
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
			err = s.eng.Instantiate(ctx, p.Caps)
			if err == nil {
				s.lastCaps = p.Caps
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
			s.bindNetworkHook(env.SandboxID)
			result, err := s.eng.Run(ctx, p.Caps, p.Export)
			s.mu.Unlock()
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
			start := time.Now()
			err = s.eng.InvokeExport(invokeCtx, p.Export)
			_ = time.Since(start) // wall time accounted on Exec path via RunResult
			cancel()
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
		case MsgStopInstance:
			s.mu.Lock()
			if s.eng != nil {
				err = s.eng.StopInstance(ctx)
				s.clearNetworkHook()
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
			if s.eng == nil {
				s.mu.Unlock()
				if replyErr(env.SandboxID, fmt.Errorf("engine not loaded")) != nil {
					return err
				}
				continue
			}
			s.bindNetworkHook(env.SandboxID)
			err = s.eng.RestoreSnapshot(ctx, snap, p.Caps)
			if err == nil {
				s.lastCaps = p.Caps
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
			s.bindNetworkHook(env.SandboxID)
			next := s.lastCaps
			next.WASIListenPort = p.Port
			if strings.TrimSpace(p.Host) != "" {
				next.WASIListenHost = p.Host
			}
			err = s.eng.Instantiate(ctx, next)
			if err == nil {
				s.lastCaps = next
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

// ServeSocketPath listens on a Unix domain socket and serves one connection at a time.
func ServeSocketPath(socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv := &Server{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := srv.Serve(conn); err != nil {
			return err
		}
	}
}
