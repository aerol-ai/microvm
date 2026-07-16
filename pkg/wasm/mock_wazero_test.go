package wasm

import (
	"github.com/tetratelabs/wazero/api"
)

type mockMemory struct {
	api.Memory
	buf []byte
}

func (m *mockMemory) Read(offset, byteCount uint32) ([]byte, bool) {
	if offset+byteCount > uint32(len(m.buf)) {
		return nil, false
	}
	return m.buf[offset : offset+byteCount], true
}

func (m *mockMemory) ReadUint32Le(offset uint32) (uint32, bool) {
	if offset+4 > uint32(len(m.buf)) {
		return 0, false
	}
	return uint32(m.buf[offset]) | uint32(m.buf[offset+1])<<8 | uint32(m.buf[offset+2])<<16 | uint32(m.buf[offset+3])<<24, true
}

func (m *mockMemory) Write(offset uint32, v []byte) bool {
	if offset+uint32(len(v)) > uint32(len(m.buf)) {
		return false
	}
	copy(m.buf[offset:], v)
	return true
}

type mockModule struct {
	api.Module
	mem  *mockMemory
	name string
}

func (m *mockModule) Memory() api.Memory { return m.mem }
func (m *mockModule) Name() string       { return m.name }
