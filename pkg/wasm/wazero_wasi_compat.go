package wasm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tetratelabs/wazero/api"
)

// wasiSocketsHost implements a Preview-2-shaped TCP egress surface on top of
// the mediated NetDialer hook (wazero has no wasi:sockets component support).
type wasiSocketsHost struct {
	net *wazeroNetHost
}

func (e *wazeroEngine) ensureWasiSocketsHost(ctx context.Context) error {
	if e.netHost == nil {
		if err := e.ensureNetworkHost(ctx); err != nil {
			return err
		}
	}
	if e.runtime == nil {
		return nil
	}
	host := &wasiSocketsHost{net: e.netHost}
	builder := e.runtime.NewHostModuleBuilder("wasi:sockets")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.tcpConnect), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("addr_ptr", "addr_len").
		Export("tcp_connect")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.streamRead), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("stream_id", "buf_ptr", "buf_len").
		Export("stream_read")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.streamWrite), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("stream_id", "buf_ptr", "buf_len").
		Export("stream_write")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.streamClose), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("stream_id").
		Export("stream_close")
	if _, err := builder.Instantiate(ctx); err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "already been instantiated") {
			return nil
		}
		return err
	}
	return nil
}

func (h *wasiSocketsHost) tcpConnect(ctx context.Context, mod api.Module, stack []uint64) {
	h.net.tcpDial(ctx, mod, stack)
}

func (h *wasiSocketsHost) streamRead(ctx context.Context, mod api.Module, stack []uint64) {
	h.net.tcpRead(ctx, mod, stack)
}

func (h *wasiSocketsHost) streamWrite(ctx context.Context, mod api.Module, stack []uint64) {
	h.net.tcpWrite(ctx, mod, stack)
}

func (h *wasiSocketsHost) streamClose(ctx context.Context, mod api.Module, stack []uint64) {
	h.net.tcpClose(ctx, mod, stack)
}

// wasiHTTPHost implements a minimal outgoing HTTP helper for guests that cannot
// use native wasi-http components on wazero (P2 components are not supported).
type wasiHTTPHost struct {
	net *wazeroNetHost
}

func (e *wazeroEngine) ensureWasiHTTPHost(ctx context.Context) error {
	if e.netHost == nil {
		if err := e.ensureNetworkHost(ctx); err != nil {
			return err
		}
	}
	if e.runtime == nil {
		return nil
	}
	host := &wasiHTTPHost{net: e.netHost}
	builder := e.runtime.NewHostModuleBuilder("wasi:http")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.httpGet), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("url_ptr", "url_len", "body_ptr", "body_len").
		Export("http_get")
	if _, err := builder.Instantiate(ctx); err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "already been instantiated") {
			return nil
		}
		return err
	}
	return nil
}

func (h *wasiHTTPHost) httpGet(_ context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errBlocked = int32(2)
		errRequest = int32(3)
	)
	urlPtr := uint32(stack[0])
	urlLen := uint32(stack[1])
	bodyPtr := uint32(stack[2])
	bodyMax := uint32(stack[3])
	stack[0] = uint64(errInvalid)

	h.net.mu.Lock()
	hook := h.net.hook
	h.net.mu.Unlock()
	if hook == nil || hook.Dial == nil {
		stack[0] = uint64(errBlocked)
		return
	}
	raw, ok := mod.Memory().Read(urlPtr, urlLen)
	if !ok {
		return
	}
	url := string(raw)
	if !strings.HasPrefix(url, "http://") {
		stack[0] = uint64(errRequest)
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: hook.Dial.DialContext,
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		if errors.Is(err, ErrNetworkEgressBlocked) {
			stack[0] = uint64(errBlocked)
			return
		}
		stack[0] = uint64(errRequest)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(bodyMax)))
	if err != nil {
		stack[0] = uint64(errRequest)
		return
	}
	if hook.Meter != nil {
		hook.Meter.AddIn(int64(len(body)))
	}
	if !mod.Memory().Write(bodyPtr, body) {
		stack[0] = uint64(errInvalid)
		return
	}
	stack[0] = uint64(int32(len(body)))
}
