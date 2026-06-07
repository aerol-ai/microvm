//go:build wasip1

// Command aerolhttp is the AerolVM wasip1 HTTP test guest. It accepts on a
// pre-opened TCP listener and serves two behaviours:
//
//   - POST /            → echoes the request body followed by a newline
//     (back-compat with the bare-wasip1 echo guest the tests replaced).
//   - GET  /?workfile=N → returns the contents of /work/N, proving a guest can
//     hold a dir preopen and a listener at the same time.
//
// The listener fd defaults to 3 (the bare-wasip1 convention, used when no dir
// preopens are configured) and is overridden by AEROL_WASM_LISTEN_FD, which the
// AerolVM wazero engine injects as (3 + number of dir preopens). This is the
// "dynamic listener fd discovery" that lets /work and the listener coexist.
package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

func main() {
	listenerFD := 3
	if s := os.Getenv("AEROL_WASM_LISTEN_FD"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 3 {
			listenerFD = v
		}
	}

	// wazero runs single-threaded; non-blocking lets the poller park the accept
	// goroutine while a request is served. The bare-wasip1 guest does the same.
	if err := syscall.SetNonblock(listenerFD, true); err != nil {
		os.Stderr.WriteString("setnonblock: " + err.Error() + "\n")
		os.Exit(1)
	}
	f := os.NewFile(uintptr(listenerFD), "")
	ln, err := net.FileListener(f)
	if err != nil {
		os.Stderr.WriteString("filelistener: " + err.Error() + "\n")
		os.Exit(1)
	}

	_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
}
