package worker

import (
	"errors"
	"net"
	"testing"
)

func TestServer_Serve_EncodeDecodeErrors(t *testing.T) {
	// Mock encodePayload
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		return nil, errors.New("mock encode error")
	}

	runServe := func(env Envelope) {
		s := &Server{eng: nil}
		c1, c2 := net.Pipe()
		go func() {
			_ = writeFrame(c1, env)
			c1.Close()
		}()
		_ = s.Serve(c2)
	}

	p1, _ := origEncode(loadModulePayload{})
	p2, _ := origEncode(instantiatePayload{})
	p3, _ := origEncode(execPayload{})
	p4, _ := origEncode(invokePayload{})
	p5, _ := origEncode(checkpointPayload{})
	p6, _ := origEncode(restorePayload{})
	p7, _ := origEncode(setCapabilityPayload{})
	p8, _ := origEncode(setNetworkBlocksPayload{})
	p9, _ := origEncode(setListenPortPayload{})
	p10, _ := origEncode(proxyHTTPPayload{Method: "GET"})

	// Since encodePayload fails, replyErr and replyOK will fail.
	runServe(Envelope{Type: MsgHealthPing})
	runServe(Envelope{Type: MsgInstanceStatus})
	runServe(Envelope{Type: MsgLoadModule, Payload: p1})
	runServe(Envelope{Type: MsgInstantiate, Payload: p2})
	runServe(Envelope{Type: MsgExec, Payload: p3})
	runServe(Envelope{Type: MsgInvoke, Payload: p4})
	runServe(Envelope{Type: MsgCheckpoint, Payload: p5})
	runServe(Envelope{Type: MsgRestore, Payload: p6})
	runServe(Envelope{Type: MsgSetCapability, Payload: p7})
	runServe(Envelope{Type: MsgSetNetworkBlocks, Payload: p8})
	runServe(Envelope{Type: MsgSetListenPort, Payload: p9})
	runServe(Envelope{Type: MsgListenPort})
	runServe(Envelope{Type: MsgStopInstance})
	runServe(Envelope{Type: MsgProxyHTTP, Payload: p10})

	// Mock decodePayload
	encodePayload = origEncode
	origDecode := decodePayload
	defer func() { decodePayload = origDecode }()
	decodePayload = func(b []byte, v any) error {
		return errors.New("mock decode error")
	}

	runServe(Envelope{Type: MsgLoadModule, Payload: p1})
	runServe(Envelope{Type: MsgInstantiate, Payload: p2})
	runServe(Envelope{Type: MsgExec, Payload: p3})
	runServe(Envelope{Type: MsgInvoke, Payload: p4})
	runServe(Envelope{Type: MsgCheckpoint, Payload: p5})
	runServe(Envelope{Type: MsgRestore, Payload: p6})
	runServe(Envelope{Type: MsgSetCapability, Payload: p7})
	runServe(Envelope{Type: MsgSetNetworkBlocks, Payload: p8})
	runServe(Envelope{Type: MsgSetListenPort, Payload: p9})
	runServe(Envelope{Type: MsgProxyHTTP, Payload: p10})
}

func TestServer_Serve_BothFailing(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	origDecode := decodePayload
	defer func() { decodePayload = origDecode }()

	encodePayload = func(v any) ([]byte, error) {
		return nil, errors.New("encode error")
	}
	decodePayload = func(b []byte, v any) error {
		return errors.New("decode error")
	}

	runServe := func(msgType MessageType) {
		s := &Server{eng: nil}
		c1, c2 := net.Pipe()
		go func() {
			_ = writeFrame(c1, Envelope{Type: msgType, Payload: []byte("foo")})
			c1.Close()
		}()
		_ = s.Serve(c2)
	}

	msgs := []MessageType{
		MsgLoadModule, MsgInstantiate, MsgExec, MsgInvoke, MsgCheckpoint,
		MsgRestore, MsgSetCapability, MsgSetNetworkBlocks, MsgListenPort,
		MsgProxyHTTP, MsgSetListenPort, MsgStopInstance,
	}
	for _, m := range msgs {
		runServe(m)
	}
}
