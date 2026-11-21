//go:build linux

package rootd

// The hostname gateway's host side on the real kernel, as root in a
// privileged container: the probe network on the helper's own bridge,
// and the sandbox-cgroup gate on executable lookups.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

func TestKernelBridgeProbe(t *testing.T) {
	k, _ := kernelRig(t)
	if err := hostnet.EnsureForwardingSysctls(); err != nil {
		t.Skipf("bridge netfilter: %v", err)
	}
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	// A sandbox on the bridge (with the real CNI plugins, its first ADD
	// makes the bridge), and the bridge up, as the plugin leaves it: a
	// route through a bridge that is down cannot be added.
	if _, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-probe"}); err != nil {
		t.Fatal(err)
	}
	br, err := netlink.LinkByName(k.bridge)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		t.Fatal(err)
	}
	setup, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP, Slot: 3})
	if err != nil || setup.GetBridgeAbsent() || setup.GetNotReady() != "" {
		t.Fatalf("set-up = %v, %v", setup, err)
	}
	host, err := netlink.LinkByName("egprobe3h")
	if err != nil {
		t.Fatalf("no probe veth: %v", err)
	}
	if host.Attrs().MasterIndex != br.Attrs().Index {
		t.Fatal("the probe veth is not on the helper's bridge")
	}
	// No gateway listens here, so the flows go nowhere; the send still
	// runs inside the probe's namespace and says what failed.
	if _, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND, Slot: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_CLOSE, Slot: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkByName("egprobe3h"); err == nil {
		t.Fatal("the probe veth outlived its close")
	}
	// A send with no probe network set up says so, and runs nothing.
	resp, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND, Slot: 3})
	if err != nil || resp.GetSendError() == "" {
		t.Fatalf("send without set-up = %v, %v", resp, err)
	}
	// A bridge that is not there yet is no failure.
	k.bridge = "aerolnone" + shortID(t)
	if resp, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP, Slot: 4}); err != nil || !resp.GetBridgeAbsent() {
		t.Fatalf("absent bridge = %v, %v", resp, err)
	}
}

func TestKernelMatchProcessGate(t *testing.T) {
	k, _ := kernelRig(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		c.Policy.Namespace = "aerolvm"
		c.Policy.CgroupParent = ""
		o.Network = k
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	req := func(pid int) *rootdpb.MatchProcessRequest {
		return &rootdpb.MatchProcessRequest{Pid: uint32(pid), Local: "10.77.0.5:40000", Remote: "192.0.2.1:443", Paths: []string{"/bin/sleep"}}
	}
	// The test's own process is no sandbox's.
	_, err := c.MatchProcess(ctx, req(os.Getpid()))
	wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleProcessMatch))

	// A process in a sandbox's cgroup passes the gate, and the lookup runs:
	// it holds no such connection.
	cg := filepath.Join("/sys/fs/cgroup/aerolvm", "sb-"+shortID(t))
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Skipf("no writable cgroup v2 here: %v", err)
	}
	sleep := exec.Command("sleep", "30")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleep.Process.Kill(); _ = sleep.Wait(); _ = os.Remove(cg) })
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(sleep.Process.Pid)), 0o644); err != nil {
		t.Skipf("cannot move a process into %s: %v", cg, err)
	}
	resp, err := c.MatchProcess(ctx, req(sleep.Process.Pid))
	if err != nil || !resp.GetNotFound() || len(resp.GetMatched()) != 0 {
		t.Fatalf("a sandbox's process = %v, %v", resp, err)
	}
	// Gone: nothing to say.
	_ = sleep.Process.Kill()
	_ = sleep.Wait()
	if resp, err := c.MatchProcess(ctx, req(sleep.Process.Pid)); err != nil || !resp.GetNotFound() {
		t.Fatalf("a gone process = %v, %v", resp, err)
	}
}
