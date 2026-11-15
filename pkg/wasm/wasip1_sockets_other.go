//go:build !linux && !darwin

package wasm

import "errors"

// The wasmtime engine serves guest sockets on Linux and macOS only (the
// poll and socket calls under wasip1_sockets.go). Elsewhere it serves none,
// says so through SupportsListen, and leaves every WASI call to wasmtime.

const wasip1SocketsSupported = false

const wasip1SocketFDBase int32 = 1 << 24

var errWasip1Stopped = errors.New("wasm instance stopped")

type wasip1Clock func(id uint32) (uint64, uint16)

type wasip1Sockets struct{ listen *instanceListen }

func newWasip1Sockets([]WASIListener, string, ByteMeter) (*wasip1Sockets, error) {
	return nil, errors.New("wasip1 sockets are not supported on this host")
}

func (*wasip1Sockets) listenerFDs() []int                         { return nil }
func (*wasip1Sockets) owns(int32) bool                            { return false }
func (*wasip1Sockets) stop()                                      {}
func (*wasip1Sockets) close()                                     {}
func (*wasip1Sockets) fdClose(int32) uint16                       { return wasiErrnoBadf }
func (*wasip1Sockets) fdRenumber(int32, int32) uint16             { return wasiErrnoBadf }
func (*wasip1Sockets) fdFdstatGet([]byte, int32, uint32) uint16   { return wasiErrnoBadf }
func (*wasip1Sockets) fdFdstatSetFlags(int32, uint32) uint16      { return wasiErrnoBadf }
func (*wasip1Sockets) fdFilestatGet([]byte, int32, uint32) uint16 { return wasiErrnoBadf }
func (*wasip1Sockets) sockShutdown(int32, uint32) uint16          { return wasiErrnoBadf }

func (*wasip1Sockets) sockAccept([]byte, int32, uint32, uint32) (uint16, error) {
	return wasiErrnoBadf, nil
}

func (*wasip1Sockets) fdRead([]byte, int32, uint32, uint32, uint32) (uint16, error) {
	return wasiErrnoBadf, nil
}

func (*wasip1Sockets) fdWrite([]byte, int32, uint32, uint32, uint32) (uint16, error) {
	return wasiErrnoBadf, nil
}

func (*wasip1Sockets) sockRecv([]byte, int32, uint32, uint32, uint32, uint32, uint32) (uint16, error) {
	return wasiErrnoBadf, nil
}

func (*wasip1Sockets) sockSend([]byte, int32, uint32, uint32, uint32, uint32) (uint16, error) {
	return wasiErrnoBadf, nil
}

func (*wasip1Sockets) pollOneoff([]byte, uint32, uint32, uint32, uint32, wasip1Clock) (uint16, bool, error) {
	return 0, false, nil
}
