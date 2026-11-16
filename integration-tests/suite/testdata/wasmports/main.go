//go:build wasip1

// Command wasmports is the guest UC-728 builds and pushes. It serves HTTP on
// every TCP listener the AerolVM wazero engine pre-opens and answers each
// request with "port=<P>", P being the exposed port that listener belongs
// to, so two exposed ports are told apart by their bodies alone.
//
// WASI has no getsockname, so the guest learns which descriptor is which
// port from AEROL_WASM_LISTEN_FDS ("8080=4,9090=5"; plans/code-interpreter.md
// section 6). An engine older than that sets only AEROL_WASM_LISTEN_FD, one
// listener for every port; the guest then answers "port=unknown", which the
// case reports as the missing feature.
package main

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type listener struct {
	port string
	fd   int
}

func listeners() []listener {
	var out []listener
	for _, pair := range strings.Split(os.Getenv("AEROL_WASM_LISTEN_FDS"), ",") {
		port, fd, ok := strings.Cut(strings.TrimSpace(pair), "=")
		n, err := strconv.Atoi(fd)
		if ok && err == nil && n >= 3 && port != "" {
			out = append(out, listener{port: port, fd: n})
		}
	}
	if len(out) > 0 {
		return out
	}
	fd := 3
	if n, err := strconv.Atoi(os.Getenv("AEROL_WASM_LISTEN_FD")); err == nil && n >= 3 {
		fd = n
	}
	return []listener{{port: "unknown", fd: fd}}
}

func serve(l listener) {
	// wazero runs the guest on one thread; non-blocking descriptors let the
	// Go runtime's poller park each accept loop while another serves.
	if err := syscall.SetNonblock(l.fd, true); err != nil {
		os.Stderr.WriteString("setnonblock " + strconv.Itoa(l.fd) + ": " + err.Error() + "\n")
		os.Exit(1)
	}
	ln, err := net.FileListener(os.NewFile(uintptr(l.fd), "listener-"+l.port))
	if err != nil {
		os.Stderr.WriteString("filelistener " + strconv.Itoa(l.fd) + ": " + err.Error() + "\n")
		os.Exit(1)
	}
	body := []byte("port=" + l.port + "\n")
	_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
}

func main() {
	all := listeners()
	for _, l := range all[1:] {
		go serve(l)
	}
	// The last accept loop runs on the main goroutine, so the guest lives as
	// long as its listeners do.
	serve(all[0])
}
