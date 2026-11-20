package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Only root opens connections to a guest's listeners. All workers share one
// uid, so the worker fence (internal/network/workerfence) cannot tell a
// worker reaching its own guest from one reaching another tenant's guest:
// it lets the worker uid answer connections on loopback and open none.
// sandboxd therefore makes each exposed-port connection itself:
//
//  1. sandboxd sends guest_listener; the worker answers with the listening
//     socket the request goes to (listenerFor) attached.
//  2. sandboxd checks that socket (checkGuestListener) and connects to its
//     address as root while it holds it. A listening socket bound to that
//     exact address, with SO_REUSEPORT off, is the only one the kernel can
//     hand the connection to, and a worker can only attach a socket it
//     holds: so the connection lands on that worker's own listener, never
//     on another tenant's or on a service of the node, whatever port the
//     worker named.
//  3. sandboxd sends proxy_http with the connected socket attached; the
//     worker checks, under its lock, that it leads to the listener of the
//     instance it runs now, and proxies the request over it.
//
// A worker from an older release answers guest_listener as a message it
// does not know; sandboxd then sends a plain proxy_http and that worker
// dials its listener itself, as it always did (it runs as root, and the
// fence does not apply to root).

// guestListenerPayload asks for the listener of an exposed port (0: the
// primary).
type guestListenerPayload struct {
	GuestPort int `json:"guest_port,omitempty"`
}

// guestListenerResult names the listener the worker attached.
type guestListenerResult struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// FD names of the sockets these messages carry (Envelope.FDPaths). They
// are never paths: readGrantedFrame keeps sockets out of the grants.
const (
	guestListenerFDName = "guest-listener"
	guestConnFDName     = "guest-conn"
)

// ErrHostDialUnsupported: the worker predates host-dialed guest
// connections. The caller sends a plain ProxyHTTP instead.
var ErrHostDialUnsupported = errors.New("wasm worker does not take guest connections from sandboxd")

// errGuestConnRequired refuses a proxy_http without a connection in a
// worker that dropped its privileges: it may not open one itself.
var errGuestConnRequired = errors.New("wasm guest HTTP: this worker takes its guest connections from sandboxd and opens none itself")

// guestDialTimeout bounds sandboxd's connect to a guest listener. It is on
// loopback, so it either completes at once or the listener's backlog is
// full.
var guestDialTimeout = 2 * time.Second

// fdDir lists this process's open descriptors.
var fdDir = "/proc/self/fd"

// hostDialSupported: the worker can find its listening sockets and
// sandboxd can check one (SO_ACCEPTCONN) on Linux, the only place workers
// drop their privileges. Elsewhere the worker says it does not take guest
// connections, and dials its listener itself.
var hostDialSupported = runtime.GOOS == "linux"

// fdNames lists the descriptor numbers in fdDir, names only: a stat of
// each would also stat the descriptor reading the folder.
func fdNames() ([]string, error) {
	d, err := os.Open(fdDir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.Readdirnames(-1)
}

// guestListenerFor is the listener a request on guestPort goes to: its
// address, and a duplicate of the socket, which the caller closes. The
// socket is found under mu, so the instance cannot change (and close it)
// while it is looked up.
func (s *Server) guestListenerFor(guestPort int) (guestListenerResult, *os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	port := listenerFor(s.eng, guestPort)
	if port <= 0 {
		return guestListenerResult{}, nil, errGuestNotListening
	}
	host := s.lastCaps.WASIListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	f, err := findListener(host, port)
	if err != nil {
		return guestListenerResult{}, nil, err
	}
	return guestListenerResult{Host: host, Port: port}, f, nil
}

// findListener returns a duplicate of this process's TCP listening socket
// bound to host:port. The engine binds the listeners itself (wazero keeps
// them to itself), so they are found among the process's descriptors by
// what they are bound to.
func findListener(host string, port int) (*os.File, error) {
	want, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("guest listen host %q: %w", host, err)
	}
	names, err := fdNames()
	if err != nil {
		return nil, fmt.Errorf("list descriptors: %w", err)
	}
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		if ap, ok := listeningAddr(fd); ok && ap.Addr() == want.Unmap() && int(ap.Port()) == port {
			dup, err := unix.Dup(fd)
			if err != nil {
				return nil, fmt.Errorf("dup guest listener: %w", err)
			}
			unix.CloseOnExec(dup)
			return os.NewFile(uintptr(dup), guestListenerFDName), nil
		}
	}
	return nil, fmt.Errorf("%w: no listening socket on %s", errGuestNotListening, net.JoinHostPort(host, strconv.Itoa(port)))
}

// listeningAddr is the address fd listens on, when it is a TCP socket in
// the listening state.
func listeningAddr(fd int) (netip.AddrPort, bool) {
	if v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || v == 0 {
		return netip.AddrPort{}, false
	}
	if v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || v != unix.SOCK_STREAM {
		return netip.AddrPort{}, false
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return netip.AddrPort{}, false
	}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), uint16(sa.Port)), true
	}
	return netip.AddrPort{}, false
}

// serveGuestListener answers guest_listener on conn. It returns only a
// write error, like the cases of Serve.
func (s *Server) serveGuestListener(conn net.Conn, env Envelope) error {
	var p guestListenerPayload
	err := decodePayload(env.Payload, &p)
	var (
		res guestListenerResult
		f   *os.File
	)
	switch {
	case err != nil:
	case !hostDialSupported:
		err = ErrHostDialUnsupported
	default:
		res, f, err = s.guestListenerFor(p.GuestPort)
	}
	if err != nil {
		body, encErr := encodePayload(errorPayload{Message: err.Error()})
		if encErr != nil {
			return encErr
		}
		return writeFrame(conn, Envelope{Type: MsgError, SandboxID: env.SandboxID, Payload: body})
	}
	defer f.Close()
	body, err := encodePayload(res)
	if err != nil {
		return err
	}
	return writeFrameFiles(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body, FDPaths: []string{guestListenerFDName}}, []*os.File{f})
}

// proxyGuestHTTPOn serves one proxied request over the connection sandboxd
// opened (f). It is used only when it leads to the listener the request
// would go to now: the instance may have been replaced since sandboxd asked
// for it, and that listener's port may then be another sandbox's.
func (s *Server) proxyGuestHTTPOn(ctx context.Context, sandboxID string, p proxyHTTPPayload, f *os.File) (proxyHTTPResultPayload, error) {
	nc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return proxyHTTPResultPayload{}, fmt.Errorf("guest connection: %w", err)
	}
	addr, err := s.guestHTTPTarget(p.GuestPort)
	if err == nil {
		err = sameTCPAddr(nc.RemoteAddr(), addr)
	}
	if err != nil {
		_ = nc.Close()
		return proxyHTTPResultPayload{}, err
	}
	// The transport closes it once the response is read; a request that
	// fails before it dials leaves it to this.
	defer nc.Close()
	return s.proxyGuestHTTPPayloadVia(ctx, sandboxID, p, addr, oneConnDialer(nc))
}

// sameTCPAddr checks that a connection's peer is want ("host:port").
func sameTCPAddr(got net.Addr, want string) error {
	tcp, ok := got.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("guest connection is not TCP (%v)", got)
	}
	wantAP, err := netip.ParseAddrPort(want)
	if err != nil {
		return err
	}
	if tcp.AddrPort().Addr().Unmap() != wantAP.Addr().Unmap() || tcp.AddrPort().Port() != wantAP.Port() {
		return fmt.Errorf("%w: the connection leads to %s, the instance listens on %s", errGuestNotListening, tcp, want)
	}
	return nil
}

// oneConnDialer hands out conn once: the reverse proxy's only connection
// (keep-alives are off), so nothing can make it dial anything else.
func oneConnDialer(conn net.Conn) func(context.Context) (net.Conn, error) {
	var used bool
	return func(context.Context) (net.Conn, error) {
		if used {
			return nil, errors.New("guest connection already used")
		}
		used = true
		return conn, nil
	}
}

// ProxyHTTPDialed forwards one HTTP request to the guest, connecting to
// its listener from this process (see the top of this file). host is where
// the driver had the worker bind its listeners; ports are the listener
// ports the driver knows for this sandbox: a listener anywhere else is
// refused. ErrHostDialUnsupported means the worker is from an older
// release, and nothing was sent to the guest.
func (c *Client) ProxyHTTPDialed(sandboxID string, guestPort int, host string, ports []int, w http.ResponseWriter, r *http.Request) error {
	conn, err := c.dial(c.socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	body, err := encodePayload(guestListenerPayload{GuestPort: guestPort})
	if err != nil {
		return err
	}
	if err := writeFrame(conn, Envelope{Type: MsgGuestListener, SandboxID: sandboxID, Payload: body}); err != nil {
		return err
	}
	reply, files, err := readFrameFiles(conn)
	if err != nil {
		return err
	}
	guest, err := connectGuest(reply, files, host, ports)
	closeFiles(files)
	if err != nil {
		// ErrHostDialUnsupported included: the request body is still
		// unread, for the caller's plain ProxyHTTP.
		return err
	}
	connFile, err := guest.File()
	_ = guest.Close()
	if err != nil {
		return fmt.Errorf("guest connection: %w", err)
	}
	defer connFile.Close()
	payload, err := buildProxyHTTPPayload(guestPort, r)
	if err != nil {
		return err
	}
	if body, err = encodePayload(payload); err != nil {
		return err
	}
	if err := writeFrameFiles(conn, Envelope{Type: MsgProxyHTTP, SandboxID: sandboxID, Payload: body, FDPaths: []string{guestConnFDName}}, []*os.File{connFile}); err != nil {
		return err
	}
	result, err := readFrame(conn)
	if err != nil {
		return err
	}
	return finishProxyHTTP(result, w)
}

// connectGuest checks the worker's guest_listener reply and connects to
// the listener it carries while holding it.
func connectGuest(reply Envelope, files []*os.File, host string, ports []int) (*net.TCPConn, error) {
	switch reply.Type {
	case MsgOK:
	case MsgInvokeResult:
		return nil, ErrHostDialUnsupported
	case MsgError:
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return nil, err
		}
		if strings.Contains(p.Message, "not supported in resident-host mode") || p.Message == ErrHostDialUnsupported.Error() {
			return nil, fmt.Errorf("%w: %s", ErrHostDialUnsupported, p.Message)
		}
		return nil, errors.New(p.Message)
	default:
		return nil, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	if len(files) != 1 || len(reply.FDPaths) != 1 || reply.FDPaths[0] != guestListenerFDName {
		return nil, errors.New("guest listener: the worker attached no listening socket")
	}
	addr, err := checkGuestListener(files[0], host, ports)
	if err != nil {
		return nil, err
	}
	nc, err := net.DialTimeout("tcp", addr.String(), guestDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to guest listener %s: %w", addr, err)
	}
	return nc.(*net.TCPConn), nil
}

// checkGuestListener checks the socket a worker attached before sandboxd
// connects to its address: a TCP socket in the listening state, bound to
// exactly host and one of ports, with SO_REUSEPORT off (so no other socket
// can share that address with it). While the caller holds it, it is the
// only socket a connection to that address can reach.
func checkGuestListener(f *os.File, host string, ports []int) (netip.AddrPort, error) {
	want, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("guest listen host %q: %w", host, err)
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("guest listener: %w", err)
	}
	var (
		ap       netip.AddrPort
		ok       bool
		reuse    int
		reuseErr error
	)
	// Control, not Fd: Fd would put the socket, which the worker's own
	// listener shares, into blocking mode.
	if err := rc.Control(func(fd uintptr) {
		ap, ok = listeningAddr(int(fd))
		reuse, reuseErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT)
	}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("guest listener: %w", err)
	}
	switch {
	case !ok:
		return netip.AddrPort{}, errors.New("guest listener: the attached socket is not a listening TCP socket")
	case reuseErr != nil || reuse != 0:
		return netip.AddrPort{}, errors.New("guest listener: the attached socket allows SO_REUSEPORT")
	case ap.Addr() != want.Unmap():
		return netip.AddrPort{}, fmt.Errorf("guest listener: bound to %s, not the guest listen host %s", ap, host)
	case !slices.Contains(ports, int(ap.Port())):
		return netip.AddrPort{}, fmt.Errorf("guest listener: port %d is not one of this sandbox's listeners", ap.Port())
	}
	return ap, nil
}

// finishProxyHTTP writes a proxy_http reply to w.
func finishProxyHTTP(reply Envelope, w http.ResponseWriter) error {
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

// rawFD is f's descriptor without Fd's side effect: Fd puts a non-blocking
// file into blocking mode, and a socket shares that mode with every copy
// of it (the worker's own listener, sandboxd's connection).
func rawFD(f *os.File) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	if err := rc.Control(func(u uintptr) { fd = int(u) }); err != nil {
		return -1, err
	}
	return fd, nil
}
