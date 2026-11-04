// Command v6probe is PID 1 of a throwaway initramfs for
// TestKernelGuestIPv6BootArg: it reports what a guest kernel booted with a
// given command line does with IPv6, then powers the machine off. Every
// line it prints starts with "V6PROBE " and is a key=value pair.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func report(key, value string) { fmt.Printf("V6PROBE %s=%s\n", key, value) }

func linkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "absent"
	}
	return strings.TrimSpace(string(b))
}

func main() {
	_ = unix.Mount("proc", "/proc", "proc", 0, "")
	_ = unix.Mount("sysfs", "/sys", "sysfs", 0, "")
	report("cmdline", read("/proc/cmdline"))
	for _, l := range []string{"lo", "eth0"} {
		if err := linkUp(l); err != nil {
			report("link_up_"+l, "error: "+err.Error())
		}
	}
	// eth0 has carrier: give address autoconfiguration and DAD time.
	time.Sleep(3 * time.Second)
	for _, c := range []string{"all", "default", "lo", "eth0"} {
		report("disable_ipv6_"+c, read("/proc/sys/net/ipv6/conf/"+c+"/disable_ipv6"))
	}
	addrs := []string{}
	if f, err := os.Open("/proc/net/if_inet6"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if fields := strings.Fields(s.Text()); len(fields) == 6 {
				addrs = append(addrs, fields[5]+":"+fields[0])
			}
		}
		f.Close()
	}
	report("ipv6_addresses", fmt.Sprint(len(addrs)))
	report("ipv6_address_list", strings.Join(addrs, ","))

	// The raw syscall a workload makes for a listener on [::].
	if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0); err != nil {
		report("af_inet6_socket", "error: "+err.Error())
	} else {
		report("af_inet6_socket", "ok")
		sa := &unix.SockaddrInet6{Port: 18080}
		if err := unix.Bind(fd, sa); err != nil {
			report("af_inet6_bind_any", "error: "+err.Error())
		} else {
			report("af_inet6_bind_any", "ok")
		}
		unix.Close(fd)
	}
	// A dual-stack listener on [::] and an IPv4 client to it.
	ln, err := net.Listen("tcp", "[::]:18081")
	if err != nil {
		report("listen_any", "error: "+err.Error())
	} else {
		report("listen_any", ln.Addr().String())
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("hi\n"))
				c.Close()
			}
		}()
		if c, err := net.DialTimeout("tcp4", "127.0.0.1:18081", 2*time.Second); err != nil {
			report("ipv4_client_to_any", "error: "+err.Error())
		} else {
			line, _ := bufio.NewReader(c).ReadString('\n')
			report("ipv4_client_to_any", strings.TrimSpace(line))
			c.Close()
		}
	}
	report("done", "1")
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}
