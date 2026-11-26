//go:build ignore

// nsm-attest asks a Nitro Sandbox's Nitro Secure Module (/dev/nsm, the
// Linux nsm driver's NSM_IOCTL_RAW) for an attestation document and prints
// the raw CBOR response base64-encoded on one line. With -vsock <port> it
// also sends that line to the parent (CID 2) over vsock, which Firecracker
// forwards to the host socket <vsock uds>_<port>; that is the only way out
// of a confidential sandbox started without debug_mode. Spike SP-B tool
// (plans/security-gaps-m1-m4.md §4.2 step 3); spb.py verifies the document.
//
// It is built inside the AerolVM module (spb-setup.sh, which drops the
// ignore tag) only to reuse its golang.org/x/sys; it is not part of AerolVM.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// From include/uapi/linux/nsm.h.
type nsmIovec struct {
	addr uint64
	len  uint64
}

type nsmRaw struct {
	request  nsmIovec
	response nsmIovec
}

// _IOWR(0x0A, 0, struct nsm_raw): read|write (3) << 30 | 32 << 16 | 0x0A << 8.
const nsmIoctlRaw = 0xC0200A00

func cborText(s string) []byte {
	if len(s) >= 24 {
		panic("long text")
	}
	return append([]byte{0x60 | byte(len(s))}, s...)
}

func cborBytes(b []byte) []byte {
	if len(b) < 24 {
		return append([]byte{0x40 | byte(len(b))}, b...)
	}
	return append([]byte{0x58, byte(len(b))}, b...)
}

// request is {"Attestation": {"user_data": null, "nonce": n, "public_key": null}}.
func request(nonce []byte) []byte {
	r := []byte{0xA1}
	r = append(r, cborText("Attestation")...)
	r = append(r, 0xA3)
	r = append(r, cborText("user_data")...)
	r = append(r, 0xF6)
	r = append(r, cborText("nonce")...)
	r = append(r, cborBytes(nonce)...)
	r = append(r, cborText("public_key")...)
	r = append(r, 0xF6)
	return r
}

func main() {
	port := flag.Uint("vsock", 0, "also send the line to the parent on this vsock port")
	nonce := flag.String("nonce", "spb-nonce", "nonce to bind into the document (at most 64 bytes)")
	flag.Parse()

	f, err := os.OpenFile("/dev/nsm", os.O_RDWR, 0)
	if err != nil {
		fmt.Println("NSM-ERROR open /dev/nsm:", err)
		send(*port, "NSM-ERROR open /dev/nsm: "+err.Error())
		os.Exit(1)
	}
	req := request([]byte(*nonce))
	resp := make([]byte, 0x3000)
	raw := nsmRaw{
		request:  nsmIovec{addr: uint64(uintptr(unsafe.Pointer(&req[0]))), len: uint64(len(req))},
		response: nsmIovec{addr: uint64(uintptr(unsafe.Pointer(&resp[0]))), len: uint64(len(resp))},
	}
	start := time.Now()
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), nsmIoctlRaw, uintptr(unsafe.Pointer(&raw))); errno != 0 {
		fmt.Println("NSM-ERROR ioctl:", errno)
		send(*port, "NSM-ERROR ioctl: "+errno.Error())
		os.Exit(1)
	}
	runtime.KeepAlive(req)
	runtime.KeepAlive(resp)
	line := fmt.Sprintf("NSM-DOC %d %s", time.Since(start).Microseconds(), base64.StdEncoding.EncodeToString(resp[:raw.response.len]))
	fmt.Println(line)
	send(*port, line)
}

func send(port uint, line string) {
	if port == 0 {
		return
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("NSM-ERROR vsock socket:", err)
		return
	}
	defer unix.Close(fd)
	for i := 0; i < 50; i++ {
		if err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: uint32(port)}); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Println("NSM-ERROR vsock connect:", err)
		return
	}
	b := []byte(line + "\n")
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err != nil {
			fmt.Println("NSM-ERROR vsock write:", err)
			return
		}
		b = b[n:]
	}
}
