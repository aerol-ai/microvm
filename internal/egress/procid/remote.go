package procid

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

// The gateway runs unprivileged (user aerolvm-egress, NET_ADMIN and
// NET_BIND_SERVICE only), and reading another user's /proc/<pid>/fd and
// /proc/<pid>/root takes ptrace access it doesn't have: every traced
// connection came back unknown and per-binary rules refused everything
// (review finding 16). Rather than make the network-facing process
// privileged, sandboxd (root) answers the lookup on a local socket only the
// gateway's user may connect to. A request names a sandbox; sandboxd uses
// its own record of that sandbox's init process and only the paths the
// sandbox's rules list, so the gateway can't turn it into a general process
// oracle.

// DefaultSocket is where sandboxd serves lookups.
const DefaultSocket = "/run/aerolvm/egress-procid.sock"

// maxRequest bounds a request: a sandbox id, two addresses and at most a
// few dozen paths.
const maxRequest = 64 << 10

// Request asks which of a sandbox's listed executables hold the connection
// local→remote, seen from inside the sandbox.
type Request struct {
	SandboxID string         `json:"sandbox_id"`
	Local     netip.AddrPort `json:"local"`
	Remote    netip.AddrPort `json:"remote"`
	Paths     []string       `json:"paths"`
}

// Response lists the paths that matched. NotFound means no process holds the
// connection (it closed, or the sandbox can't be traced).
type Response struct {
	Matched  []string `json:"matched,omitempty"`
	NotFound bool     `json:"not_found,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Client is the gateway's side of the lookup.
type Client struct {
	Path    string
	Timeout time.Duration
}

// Match asks sandboxd and returns is(path) over the matched paths.
func (c Client) Match(sandboxID string, local, remote netip.AddrPort, paths []string) (func(string) bool, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, fmt.Errorf("procid: sandboxd lookup: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(Request{SandboxID: sandboxID, Local: local, Remote: remote, Paths: paths}); err != nil {
		return nil, fmt.Errorf("procid: sandboxd lookup: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("procid: sandboxd lookup: %w", err)
	}
	switch {
	case resp.NotFound:
		return nil, ErrNotFound
	case resp.Error != "":
		return nil, fmt.Errorf("procid: sandboxd lookup: %s", resp.Error)
	}
	matched := resp.Matched
	return func(path string) bool { return slices.Contains(matched, path) }, nil
}

// Authorizer resolves a request's sandbox to its init pid and the paths its
// rules list; an error refuses the request.
type Authorizer func(sandboxID string) (pid int, allowed []string, err error)

// Server answers lookups for the gateway (sandboxd's side).
type Server struct {
	// Peer vets each connection (SO_PEERCRED: the gateway's uid).
	Peer func(net.Conn) error
	// Authorize maps a sandbox to what may be asked about it.
	Authorize Authorizer
	// Resolver reads procfs; the zero value is the host's.
	Resolver Resolver
}

// Serve answers one request per connection until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	enc := json.NewEncoder(conn)
	if s.Peer != nil {
		if err := s.Peer(conn); err != nil {
			_ = enc.Encode(Response{Error: "peer not allowed"})
			return
		}
	}
	var req Request
	if err := json.NewDecoder(&limitedReader{r: conn, n: maxRequest}).Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: "bad request"})
		return
	}
	_ = enc.Encode(s.answer(req))
}

func (s *Server) answer(req Request) Response {
	if s.Authorize == nil {
		return Response{Error: "no authorizer"}
	}
	pid, allowed, err := s.Authorize(req.SandboxID)
	if err != nil {
		return Response{Error: err.Error()}
	}
	is, err := s.Resolver.Matcher(pid, req.Local, req.Remote)
	if errors.Is(err, ErrNotFound) {
		return Response{NotFound: true}
	}
	if err != nil {
		return Response{Error: err.Error()}
	}
	var matched []string
	for _, p := range req.Paths {
		// Only what the sandbox's own rules list is ever looked up.
		if slices.Contains(allowed, p) && is(p) {
			matched = append(matched, p)
		}
	}
	return Response{Matched: matched}
}

type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("procid: request too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}
