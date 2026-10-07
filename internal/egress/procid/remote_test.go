package procid

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// serve runs a Server on a temp UDS and returns its Client.
func serve(t *testing.T, s *Server) Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "pid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = s.Serve(ln) }()
	return Client{Path: path}
}

// TestRemoteLookup (review finding 16): the gateway asks sandboxd, which
// traces with its own record of the sandbox's process and answers only for
// the paths that sandbox's rules list.
func TestRemoteLookup(t *testing.T) {
	r, local, remote := fakeProc(t)
	var asked string
	srv := &Server{Resolver: r, Authorize: func(id string) (int, []string, error) {
		asked = id
		if id != "sb" {
			return 0, nil, errors.New("no per-binary rules")
		}
		return 100, []string{"/usr/bin/git", "/usr/bin/curl"}, nil
	}}
	c := serve(t, srv)

	// pip holds the connection too, but sb's rules don't list it: it is
	// never looked up, so it never matches.
	is, err := c.Match("sb", local, remote, []string{"/usr/bin/git", "/usr/local/bin/pip", "/usr/bin/curl"})
	if err != nil {
		t.Fatal(err)
	}
	if asked != "sb" || !is("/usr/bin/git") || is("/usr/local/bin/pip") || is("/usr/bin/curl") {
		t.Fatalf("matches: git=%v pip=%v curl=%v", is("/usr/bin/git"), is("/usr/local/bin/pip"), is("/usr/bin/curl"))
	}
	if _, err := c.Match("other", local, remote, []string{"/usr/bin/git"}); err == nil {
		t.Fatal("a sandbox the authorizer refuses must be an error")
	}
	if _, err := c.Match("sb", local, netip.MustParseAddrPort("1.2.3.4:5"), []string{"/usr/bin/git"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no owner = %v, want ErrNotFound", err)
	}

	// A peer the check refuses gets nothing.
	denied := serve(t, &Server{Resolver: r, Peer: func(net.Conn) error { return errors.New("uid 1000") },
		Authorize: func(string) (int, []string, error) { return 100, []string{"/usr/bin/git"}, nil }})
	if _, err := denied.Match("sb", local, remote, []string{"/usr/bin/git"}); err == nil {
		t.Fatal("a refused peer must get an error")
	}
	// No authorizer, no socket: errors, never a match.
	if _, err := serve(t, &Server{Resolver: r}).Match("sb", local, remote, nil); err == nil {
		t.Fatal("a server without an authorizer must refuse")
	}
	if _, err := (Client{Path: filepath.Join(t.TempDir(), "none.sock")}).Match("sb", local, remote, nil); err == nil {
		t.Fatal("no sandboxd must be an error")
	}
}

func TestRemoteBadRequest(t *testing.T) {
	r, _, _ := fakeProc(t)
	c := serve(t, &Server{Resolver: r, Authorize: func(string) (int, []string, error) { return 100, nil, nil }})
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	big := make([]byte, maxRequest+10)
	for i := range big {
		big[i] = 'x'
	}
	_, _ = conn.Write(big)
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if !slices.Contains([]string{`{"error":"bad request"}`}, string(buf[:n-1])) {
		t.Fatalf("response = %q", buf[:n])
	}
}
