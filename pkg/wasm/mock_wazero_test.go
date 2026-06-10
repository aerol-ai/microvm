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

func (m *mockMemory) Write(offset uint32, v []byte) bool {
	if offset+uint32(len(v)) > uint32(len(m.buf)) {
		return false
	}
	copy(m.buf[offset:], v)
	return true
}

type mockModule struct {
	api.Module
	mem *mockMemory
}

func (m *mockModule) Memory() api.Memory { return m.mem }
