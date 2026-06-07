package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Server holds one wazero engine per worker process (D11: one module per worker).
type Server struct {
	mu  sync.Mutex
	eng wasmengine.Engine
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
			s.eng, err = wasmengine.NewEngine(ctx)
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
			err = s.eng.Instantiate(ctx, p.Caps)
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
			err = s.eng.InvokeExport(ctx, p.Export)
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
