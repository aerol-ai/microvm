package wasm

import "net"

// netConnRead performs a conn.Read, meters inbound bytes, and returns the
// guest-facing int32 result. Shared by the single-instance wazeroNetHost and
// the co-tenant multiNetHost so the socket body stays single-sourced (D5-A).
func netConnRead(conn net.Conn, meter ByteMeter, buf []byte) int32 {
	n, err := conn.Read(buf)
	if n > 0 && meter != nil {
		meter.AddIn(int64(n))
	}
	_ = err // guest sees short/EOF as a non-positive or short read; match prior host behavior
	return int32(n)
}

// netConnWrite performs a conn.Write, meters outbound bytes, and returns the
// guest-facing int32 result. Shared by both net hosts (D5-A).
func netConnWrite(conn net.Conn, meter ByteMeter, buf []byte) int32 {
	n, err := conn.Write(buf)
	if n > 0 && meter != nil {
		meter.AddOut(int64(n))
	}
	_ = err
	return int32(n)
}
