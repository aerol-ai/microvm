package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
)

const maxProxyHTTPBody = 32 << 20

func (s *Server) guestHTTPTarget(guestPort int) (string, error) {
	s.mu.Lock()
	host := s.lastCaps.WASIListenHost
	port := s.lastCaps.WASIListenPort
	s.mu.Unlock()
	if guestPort > 0 {
		port = guestPort
	}
	if port < 0 {
		return "", fmt.Errorf("guest listen port disabled")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (s *Server) proxyGuestHTTP(ctx context.Context, sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	addr, err := s.guestHTTPTarget(guestPort)
	if err != nil {
		return err
	}
	target, err := url.Parse("http://" + addr)
	if err != nil {
		return err
	}

	usage := s.netUsageFor(sandboxID)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		http.Error(rw, proxyErr.Error(), http.StatusBadGateway)
	}
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Body != nil {
			resp.Body = &countReadCloser{ReadCloser: resp.Body, counter: &usage.bytesOut}
		}
		return nil
	}
	proxy.Transport = &http.Transport{
		DialContext: func(dctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			conn, dialErr := d.DialContext(dctx, network, address)
			if dialErr != nil {
				return nil, dialErr
			}
			return &countConn{Conn: conn, in: &usage.bytesIn, out: &usage.bytesOut}, nil
		},
		DisableKeepAlives: true,
	}

	if r.Body != nil {
		r.Body = &countReadCloser{ReadCloser: r.Body, counter: &usage.bytesIn}
	}
	proxy.ServeHTTP(w, r.WithContext(ctx))
	return nil
}

func (s *Server) proxyGuestHTTPFromPayload(ctx context.Context, sandboxID string, p proxyHTTPPayload) (proxyHTTPResultPayload, error) {
	req, err := http.NewRequestWithContext(ctx, p.Method, "http://guest"+p.RequestURI, bytes.NewReader(p.Body))
	if err != nil {
		return proxyHTTPResultPayload{}, err
	}
	req.Header = p.Header
	rec := httptest.NewRecorder()
	if err := s.proxyGuestHTTP(ctx, sandboxID, p.GuestPort, rec, req); err != nil {
		return proxyHTTPResultPayload{}, err
	}
	return proxyHTTPResultPayload{
		StatusCode: rec.Code,
		Header:     rec.Header(),
		Body:       rec.Body.Bytes(),
	}, nil
}

type countReadCloser struct {
	io.ReadCloser
	counter *atomic.Int64
}

func (c *countReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.counter.Add(int64(n))
	}
	return n, err
}

type countConn struct {
	net.Conn
	in  *atomic.Int64
	out *atomic.Int64
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.in.Add(int64(n))
	}
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.out.Add(int64(n))
	}
	return n, err
}

func buildProxyHTTPPayload(guestPort int, r *http.Request) (proxyHTTPPayload, error) {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxProxyHTTPBody))
		if err != nil {
			return proxyHTTPPayload{}, err
		}
	}
	return proxyHTTPPayload{
		GuestPort:  guestPort,
		Method:     r.Method,
		RequestURI: r.URL.RequestURI(),
		Header:     r.Header.Clone(),
		Body:       body,
	}, nil
}

func writeProxyHTTPResult(w http.ResponseWriter, p proxyHTTPResultPayload) {
	for k, vs := range p.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if p.StatusCode == 0 {
		p.StatusCode = http.StatusOK
	}
	w.WriteHeader(p.StatusCode)
	if len(p.Body) > 0 {
		_, _ = w.Write(p.Body)
	}
}

// SetListenPort hot-updates the wasip1 listener port without touching memory caps.
func (c *Client) SetListenPort(sandboxID string, port int, host string) error {
	body, err := encodePayload(setListenPortPayload{Port: port, Host: host})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgSetListenPort, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// ResolvedListenPort returns the host port for the active wasip1 listener (after ephemeral bind).
func (c *Client) ResolvedListenPort(sandboxID string) (int, error) {
	reply, err := c.roundTrip(Envelope{Type: MsgListenPort, SandboxID: sandboxID})
	if err != nil {
		return 0, err
	}
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgOK {
		return 0, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var p listenPortResultPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return 0, err
	}
	return p.Port, nil
}

// ProxyHTTP forwards one HTTP request to the guest wasip1 listener inside the worker.
func (c *Client) ProxyHTTP(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	payload, err := buildProxyHTTPPayload(guestPort, r)
	if err != nil {
		return err
	}
	body, err := encodePayload(payload)
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgProxyHTTP, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return err
		}
		return fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgProxyHTTPResult {
		return fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var result proxyHTTPResultPayload
	if err := decodePayload(reply.Payload, &result); err != nil {
		return err
	}
	writeProxyHTTPResult(w, result)
	return nil
}
