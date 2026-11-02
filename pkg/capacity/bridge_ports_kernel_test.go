//go:build linux && kerneltest

package capacity

// Real-kernel proof of BridgeMaxPorts and of the "exchange full" marker, in a
// privileged Linux container:
//
//	go test -tags kerneltest -run KernelBridge ./pkg/capacity/
//
// The 2026-11-02 docker-engine density run stopped at exactly 1,023
// sandboxes. This attaches veths to one bridge until the kernel refuses and
// checks the refusal is the one the slot pools are sized for and the one
// IsNetworkExhaustion recognises.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestKernelBridgeHoldsBridgeMaxPorts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_NET_ADMIN)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}
	ip := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command("ip", args...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	br := fmt.Sprintf("brkt%d", os.Getpid()%100000)
	if out, err := ip("", "link", "add", br, "type", "bridge"); err != nil {
		t.Fatalf("add bridge: %v: %s", err, out)
	}
	var create, attach, cleanup strings.Builder
	for i := 1; i <= BridgeMaxPorts+1; i++ {
		fmt.Fprintf(&create, "link add bkv%d type veth peer name bkp%d\n", i, i)
		fmt.Fprintf(&cleanup, "link del bkv%d\n", i)
		if i <= BridgeMaxPorts {
			fmt.Fprintf(&attach, "link set bkv%d master %s\n", i, br)
		}
	}
	t.Cleanup(func() {
		_, _ = ip("", "link", "del", br)
		_, _ = ip(cleanup.String(), "-force", "-batch", "-")
	})
	if out, err := ip(create.String(), "-batch", "-"); err != nil {
		t.Fatalf("create veths: %v: %s", err, out)
	}
	if out, err := ip(attach.String(), "-batch", "-"); err != nil {
		t.Fatalf("attaching %d ports must succeed: %v: %s", BridgeMaxPorts, err, out)
	}
	out, err := ip("", "link", "set", fmt.Sprintf("bkv%d", BridgeMaxPorts+1), "master", br)
	if err == nil {
		t.Fatalf("the bridge took port %d", BridgeMaxPorts+1)
	}
	if !IsNetworkExhaustion(errors.New(out)) {
		t.Fatalf("the kernel refused port %d with %q, which IsNetworkExhaustion does not recognise", BridgeMaxPorts+1, out)
	}
	ports, err := os.ReadDir("/sys/class/net/" + br + "/brif")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != BridgeMaxPorts {
		t.Fatalf("bridge holds %d ports, want %d", len(ports), BridgeMaxPorts)
	}
	t.Logf("port %d refused: %s", BridgeMaxPorts+1, out)
}
