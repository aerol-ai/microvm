//go:build wasip1

// Command aerolstdio is the AerolVM wasip1 stdio test guest for streaming
// exec (issue #535). Tests pick a behaviour with argv[1]:
//
//	echo              copy stdin to stdout until EOF, then exit 0
//	stderr TEXT       write TEXT to stderr, then exit 0
//	exit N            exit with code N
//	spin              loop forever without a host call
//	block             read stdin until it fails; exit 0 on EOF, 3 on an error
//	flood N           write N bytes of 'x' to stdout (N = 0: forever)
//	write-work F T    write T to /work/F
//	env [KEY]         print KEY's value, or every KEY=VALUE line
//	args              print each argument after the mode on its own line
//	dial ADDR         dial ADDR through aerol/vm/net and print "dial=<code>"
//	dial-read ADDR    dial ADDR, then block reading it; print "read=<n>"
//	pwd               print the working directory
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unsafe"
)

//go:wasmimport aerol/vm/net tcp_dial
func tcpDial(addrPtr, addrLen uint32) int32

//go:wasmimport aerol/vm/net tcp_read
func tcpRead(connID, bufPtr, bufLen uint32) int32

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: aerolstdio MODE [ARGS]")
		os.Exit(2)
	}
	mode, rest := os.Args[1], os.Args[2:]
	switch mode {
	case "echo":
		if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "echo:", err)
			os.Exit(3)
		}
	case "stderr":
		fmt.Fprint(os.Stderr, strings.Join(rest, " "))
	case "exit":
		code := 0
		if len(rest) > 0 {
			code, _ = strconv.Atoi(rest[0])
		}
		os.Exit(code)
	case "spin":
		spin()
	case "block":
		buf := make([]byte, 4096)
		for {
			_, err := os.Stdin.Read(buf)
			if err == io.EOF {
				return
			}
			if err != nil {
				os.Exit(3)
			}
		}
	case "flood":
		flood(rest)
	case "write-work":
		if len(rest) != 2 {
			os.Exit(2)
		}
		if err := os.WriteFile("/work/"+rest[0], []byte(rest[1]), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
	case "env":
		if len(rest) > 0 {
			fmt.Print(os.Getenv(rest[0]))
			return
		}
		env := os.Environ()
		sort.Strings(env)
		fmt.Print(strings.Join(env, "\n"))
	case "args":
		for _, a := range rest {
			fmt.Println(a)
		}
	case "dial":
		if len(rest) != 1 || rest[0] == "" {
			os.Exit(2)
		}
		addr := []byte(rest[0])
		code := tcpDial(uint32(uintptr(unsafe.Pointer(&addr[0]))), uint32(len(addr)))
		fmt.Printf("dial=%d", code)
	case "dial-read":
		if len(rest) != 1 || rest[0] == "" {
			os.Exit(2)
		}
		addr := []byte(rest[0])
		id := tcpDial(uint32(uintptr(unsafe.Pointer(&addr[0]))), uint32(len(addr)))
		buf := make([]byte, 64)
		fmt.Println("dialed")
		n := tcpRead(uint32(id), uint32(uintptr(unsafe.Pointer(&buf[0]))), uint32(len(buf)))
		fmt.Printf("read=%d", n)
	case "pwd":
		wd, err := os.Getwd()
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(wd)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", mode)
		os.Exit(2)
	}
}

// spin never makes a host call, so only the engine's context cancellation
// (wazero's CloseOnContextDone) can stop it.
func spin() {
	for {
		spinSink++
	}
}

var spinSink int

func flood(rest []string) {
	total := 0
	if len(rest) > 0 {
		total, _ = strconv.Atoi(rest[0])
	}
	w := bufio.NewWriterSize(os.Stdout, 64*1024)
	chunk := []byte(strings.Repeat("x", 4096))
	for written := 0; total == 0 || written < total; written += len(chunk) {
		if total > 0 && total-written < len(chunk) {
			chunk = chunk[:total-written]
		}
		if _, err := w.Write(chunk); err != nil {
			os.Exit(3)
		}
	}
	if err := w.Flush(); err != nil {
		os.Exit(3)
	}
}
