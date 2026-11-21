package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Only root opens connections to a guest's listeners, and the worker never
// holds one of them. All workers share one uid, so the worker fence
// (internal/network/workerfence) cannot tell a worker reaching its own
// guest from one reaching another tenant's guest: it lets the worker uid
// answer connections on the guest listen host and open none on loopback.
// sandboxd therefore serves each exposed-port request itself:
//
//  1. sandboxd sends guest_listener; the worker answers with the listening
//     socket the request goes to (listenerFor) attached.
//  2. sandboxd checks that socket (checkGuestListener) and connects to its
//     address as root while it holds it. A listening socket bound to that
//     exact address, with SO_REUSEPORT off, is the only one the kernel can
//     hand the connection to, and a worker can only attach a socket it
//     holds: so the connection lands on that worker's own listener, never
//     on another tenant's or on a service of the node, whatever port the
//     worker named. sandboxd closes the listening socket at once and never
//     accepts on it.
//  3. sandboxd sends the request over that connection and relays the
//     answer (proxyOverConn), counting the bytes as the worker counted
//     them. The connection stays sandboxd's: the fence matches packets by
//     the uid of the process that made the socket, so a root socket handed
//     to a worker would be root's to the fence wherever the worker pointed
//     it.
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

// guestListenerFDName names the listening socket a guest_listener reply
// carries (Envelope.FDPaths).
const guestListenerFDName = "guest-listener"

// ErrHostDialUnsupported: the worker predates host-dialed guest
// connections. The caller sends a plain ProxyHTTP instead.
var ErrHostDialUnsupported = errors.New("wasm worker does not take guest connections from sandboxd")

// errGuestConnRequired refuses a proxy_http in a worker that dropped its
// privileges: sandboxd serves its guest's HTTP itself (ProxyHTTPDialed),
// and the worker may not open a connection to its listener.
var errGuestConnRequired = errors.New("wasm guest HTTP: sandboxd connects to this worker's guest itself; the worker opens no connection to it")

// guestListenerTimeout bounds sandboxd's guest_listener exchange with a
// worker: one lookup under the worker's lock and one small reply.
var guestListenerTimeout = 5 * time.Second

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

// ProxyHTTPDialed serves one HTTP request to the guest from this process
// (see the top of this file): it asks the worker for the listener, checks
// it, connects to it and relays the request and the answer itself. host is
// where the driver had the worker bind its listeners; ports are the
// listener ports the driver knows for this sandbox: a listener anywhere
// else is refused. in and out take the bytes the worker would have counted
// for the request (proxyOverConn). ErrHostDialUnsupported means the worker
// is from an older release, and nothing was sent to the guest.
func (c *Client) ProxyHTTPDialed(sandboxID string, guestPort int, host string, ports []int, in, out *atomic.Int64, w http.ResponseWriter, r *http.Request) error {
	guest, addr, err := c.dialGuest(sandboxID, guestPort, host, ports)
	if err != nil {
		return err
	}
	defer guest.Close()
	return proxyOverConn(r.Context(), guest, addr, in, out, w, r)
}

// dialGuest runs the guest_listener exchange and returns sandboxd's own
// connection to the listener the worker named. The worker connection is
// done with by then, and every descriptor it sent is closed.
func (c *Client) dialGuest(sandboxID string, guestPort int, host string, ports []int) (net.Conn, string, error) {
	conn, err := c.dial(c.socketPath)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(guestListenerTimeout))
	body, err := encodePayload(guestListenerPayload{GuestPort: guestPort})
	if err != nil {
		return nil, "", err
	}
	if err := writeFrame(conn, Envelope{Type: MsgGuestListener, SandboxID: sandboxID, Payload: body}); err != nil {
		return nil, "", err
	}
	reply, files, err := readFrameFiles(conn)
	if err != nil {
		return nil, "", err
	}
	// connectGuest closes the listener right after it connects.
	return connectGuest(reply, files, host, ports)
}

// connectGuest checks the worker's guest_listener reply and connects to
// the listener it carries while holding it; then it closes every
// descriptor of the reply, the listener first among them, so sandboxd
// holds none of the worker's sockets beyond this call.
func connectGuest(reply Envelope, files []*os.File, host string, ports []int) (net.Conn, string, error) {
	defer closeFiles(files)
	switch reply.Type {
	case MsgOK:
	case MsgInvokeResult:
		return nil, "", ErrHostDialUnsupported
	case MsgError:
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return nil, "", err
		}
		if strings.Contains(p.Message, "not supported in resident-host mode") || p.Message == ErrHostDialUnsupported.Error() {
			return nil, "", fmt.Errorf("%w: %s", ErrHostDialUnsupported, p.Message)
		}
		return nil, "", errors.New(p.Message)
	default:
		return nil, "", fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	if len(files) != 1 || len(reply.FDPaths) != 1 || reply.FDPaths[0] != guestListenerFDName {
		return nil, "", errors.New("guest listener: the worker attached no listening socket")
	}
	addr, err := checkGuestListener(files[0], host, ports)
	if err != nil {
		return nil, "", err
	}
	nc, err := net.DialTimeout("tcp", addr.String(), guestDialTimeout)
	if err != nil {
		return nil, "", fmt.Errorf("connect to guest listener %s: %w", addr, err)
	}
	return nc, addr.String(), nil
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

// proxyOverConn relays r to the guest listener at addr over conn, its
// only connection, and the answer back to w. It counts what a worker
// counts for a proxied request, so a sandbox's usage is the same whichever
// side relays it: the request body and every byte read from the guest
// into in, every byte written to the guest and the response body into out.
func proxyOverConn(ctx context.Context, conn net.Conn, addr string, in, out *atomic.Int64, w http.ResponseWriter, r *http.Request) error {
	target, err := url.Parse("http://" + addr)
	if err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
		http.Error(rw, proxyErr.Error(), http.StatusBadGateway)
	}
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Body != nil {
			resp.Body = &countReadCloser{ReadCloser: resp.Body, counter: out}
		}
		return nil
	}
	dial := oneConnDialer(conn)
	proxy.Transport = &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			c, err := dial(dctx)
			if err != nil {
				return nil, err
			}
			return &countConn{Conn: c, in: in, out: out}, nil
		},
		DisableKeepAlives: true,
	}
	req := r.WithContext(ctx)
	// No X-Forwarded-For of sandboxd's own: the request reaches the guest
	// as it reached it through the worker.
	req.RemoteAddr = ""
	if req.Body != nil {
		req.Body = &countReadCloser{ReadCloser: req.Body, counter: in}
	}
	proxy.ServeHTTP(w, req)
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
