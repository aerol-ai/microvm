package wasm

import (
	"net"
	"reflect"

	"github.com/tetratelabs/wazero/api"
)

const (
	fdStdin   int32 = 0
	fdStdout  int32 = 1
	fdStderr  int32 = 2
	fdPreopen int32 = 3
)

// ResolvedListenPort returns the host TCP port bound by a wasip1 pre-open listener.
func ResolvedListenPort(mod api.Module) (port int, ok bool) {
	if mod == nil {
		return 0, false
	}
	for fd := fdPreopen; fd < fdPreopen+8; fd++ {
		file, found := moduleLookupFile(mod, fd)
		if !found {
			continue
		}
		if port, ok := tcpListenPort(file); ok {
			return port, true
		}
	}
	return 0, false
}

func moduleLookupFile(mod api.Module, fd int32) (any, bool) {
	mi := reflect.ValueOf(mod)
	for mi.Kind() == reflect.Interface || mi.Kind() == reflect.Pointer {
		if mi.IsNil() {
			return nil, false
		}
		mi = mi.Elem()
	}
	sysField := mi.FieldByName("Sys")
	if !sysField.IsValid() || sysField.IsNil() {
		return nil, false
	}
	fsOut := sysField.MethodByName("FS").Call(nil)
	if len(fsOut) == 0 || fsOut[0].IsNil() {
		return nil, false
	}
	lookup := fsOut[0].MethodByName("LookupFile")
	if !lookup.IsValid() {
		return nil, false
	}
	out := lookup.Call([]reflect.Value{reflect.ValueOf(fd)})
	if len(out) < 2 || !out[1].Bool() {
		return nil, false
	}
	entry := out[0]
	for entry.Kind() == reflect.Pointer {
		if entry.IsNil() {
			return nil, false
		}
		entry = entry.Elem()
	}
	fileField := entry.FieldByName("File")
	if !fileField.IsValid() {
		return nil, false
	}
	return fileField.Interface(), true
}

func tcpListenPort(file any) (int, bool) {
	if file == nil {
		return 0, false
	}
	seen := map[uintptr]struct{}{}
	return tcpListenPortValue(reflect.ValueOf(file), seen)
}

func tcpListenPortValue(v reflect.Value, seen map[uintptr]struct{}) (int, bool) {
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, false
		}
		if v.Kind() == reflect.Pointer {
			ptr := v.Pointer()
			if _, dup := seen[ptr]; dup {
				return 0, false
			}
			seen[ptr] = struct{}{}
		}
		v = v.Elem()
	}
	if v.CanAddr() {
		if m := v.Addr().MethodByName("Addr"); m.IsValid() && m.Type().NumOut() == 1 {
			out := m.Call(nil)
			if addr, ok := out[0].Interface().(*net.TCPAddr); ok && addr != nil && addr.Port > 0 {
				return addr.Port, true
			}
		}
	}
	if v.Kind() == reflect.Struct {
		for i := 0; i < v.NumField(); i++ {
			if port, ok := tcpListenPortValue(v.Field(i), seen); ok {
				return port, true
			}
		}
	}
	return 0, false
}
