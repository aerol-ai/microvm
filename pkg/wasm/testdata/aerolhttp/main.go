//go:build wasip1

// Command aerolhttp is the AerolVM wasip1 HTTP test guest. It accepts on a
// pre-opened TCP listener and serves these behaviours:
//
//   - POST /            → echoes the request body followed by a newline
//     (back-compat with the bare-wasip1 echo guest the tests replaced).
//   - GET  /?workfile=N → returns the contents of /work/N, proving a guest can
//     hold a dir preopen and a listener at the same time.
//   - GET  /port        → in multi-port mode, the exposed port the request
//     came in on (the port its listener serves); otherwise "single".
//
// The listener fd defaults to 3 (the bare-wasip1 convention, used when no dir
// preopens are configured) and is overridden by AEROL_WASM_LISTEN_FD, which the
// AerolVM wazero engine injects as (3 + number of dir preopens). This is the
// "dynamic listener fd discovery" that lets /work and the listener coexist.
//
// Multi-port mode (an argument "multiport"): the guest serves every listener
// AEROL_WASM_LISTEN_FDS names ("8080=4,9090=5"), one per exposed port.
// Without that argument the guest is a single-listener guest even when the
// engine pre-opens several: it accepts on AEROL_WASM_LISTEN_FD only, which is
// how a guest written before per-port listeners behaves.
package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if multiPort() {
		serveListenFDs(os.Getenv("AEROL_WASM_LISTEN_FDS"))
		return
	}
	listenerFD := 3
	if s := os.Getenv("AEROL_WASM_LISTEN_FD"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 3 {
			listenerFD = v
		}
	}
	_ = http.Serve(fileListener(listenerFD), handler("single"))
}

func multiPort() bool {
	for _, a := range os.Args[1:] {
		if a == "multiport" {
			return true
		}
	}
	return false
}

// serveListenFDs serves each "port=fd" pair of spec on its own goroutine and
// blocks while they run.
func serveListenFDs(spec string) {
	done := make(chan struct{})
	n := 0
	for _, pair := range strings.Split(spec, ",") {
		port, fdText, ok := strings.Cut(pair, "=")
		fd, err := strconv.Atoi(fdText)
		if !ok || err != nil || fd < 3 {
			os.Stderr.WriteString("bad AEROL_WASM_LISTEN_FDS entry: " + pair + "\n")
			os.Exit(1)
		}
		ln := fileListener(fd)
		n++
		go func() {
			_ = http.Serve(ln, handler(port))
			done <- struct{}{}
		}()
	}
	for ; n > 0; n-- {
		<-done
	}
}

func fileListener(fd int) net.Listener {
	// wazero runs single-threaded; non-blocking lets the poller park the accept
	// goroutine while a request is served. The bare-wasip1 guest does the same.
	if err := syscall.SetNonblock(fd, true); err != nil {
		os.Stderr.WriteString("setnonblock: " + err.Error() + "\n")
		os.Exit(1)
	}
	ln, err := net.FileListener(os.NewFile(uintptr(fd), ""))
	if err != nil {
		os.Stderr.WriteString("filelistener: " + err.Error() + "\n")
		os.Exit(1)
	}
	return ln
}

func handler(port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/port" {
			_, _ = w.Write([]byte(port))
			return
		}
		if name := r.URL.Query().Get("workfile"); name != "" {
			// Only allow a bare filename inside /work — no traversal.
			data, err := os.ReadFile(filepath.Join("/work", filepath.Base(name)))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(data)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	})
}
