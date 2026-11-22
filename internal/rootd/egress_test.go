package rootd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// fakeEgress is EgressHost in memory.
type fakeEgress struct {
	mu       sync.Mutex
	calls    []string
	absent   bool
	notReady error
	fail     error
	cgroups  map[int][]string // pid -> what each read of its cgroup says, in turn
	matched  []string
	// block, when set, holds every lookup until it is closed.
	block chan struct{}
}

func (f *fakeEgress) rec(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

func (f *fakeEgress) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeEgress) ProbeSetup(_ context.Context, slot int, bridge string, gw netip.Addr, subnet netip.Prefix) (bool, error, error) {
	f.rec("setup %d %s %s %s", slot, bridge, gw, subnet)
	return f.absent, f.notReady, f.fail
}

func (f *fakeEgress) ProbeSend(_ context.Context, slot int) error {
	f.rec("send %d", slot)
	return f.fail
}

func (f *fakeEgress) ProbeClose(slot int) error {
	f.rec("close %d", slot)
	return f.fail
}

func (f *fakeEgress) ProcCgroup(pid int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reads := f.cgroups[pid]
	if len(reads) == 0 {
		return "", errProcessGone
	}
	f.cgroups[pid] = reads[1:]
	if reads[0] == "error" {
		return "", errors.New("read failed")
	}
	return reads[0], nil
}

func (f *fakeEgress) Match(m rootpolicy.ProcessMatch) ([]string, bool, error) {
	f.rec("match %d %s %s %v", m.PID, m.Local, m.Remote, m.Paths)
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	if f.fail != nil {
		return nil, false, f.fail
	}
	return f.matched, f.matched == nil, nil
}

func egressRig(t *testing.T) (*rig, rootdpb.RootHelperClient, *fakeEgress) {
	t.Helper()
	fe := &fakeEgress{cgroups: map[int][]string{}}
	r := newRig(t, func(_ *Config, o *Options) { o.Network, o.Egress = newFakeNet(), fe })
	return r, rootdpb.NewRootHelperClient(r.conn), fe
}

// TestBridgeProbe: the probe is always the helper's own bridge, at the
// gateway and range of its own CNI config; the agent names only the step
// and the slot.
func TestBridgeProbe(t *testing.T) {
	r, c, fe := egressRig(t)
	ctx := callCtx(t)
	for _, op := range []rootdpb.BridgeProbeOp{rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP, rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND,
		rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_CLOSE} {
		resp, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: op, Slot: 2})
		if err != nil || resp.GetBridgeAbsent() || resp.GetNotReady() != "" || resp.GetSendError() != "" {
			t.Fatalf("%v = %v, %v", op, resp, err)
		}
	}
	if got := fe.recorded(); !slices.Equal(got, []string{"setup 2 aerolvm0 10.88.0.1 10.88.0.0/16", "send 2", "close 2"}) {
		t.Fatalf("calls %q", got)
	}
	fe.absent, fe.notReady = true, errors.New("bridge-nf-call-iptables is 0")
	resp, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP})
	if err != nil || !resp.GetBridgeAbsent() || resp.GetNotReady() == "" {
		t.Fatalf("absent = %v, %v", resp, err)
	}
	fe.fail = errors.New("netlink")
	if resp, err := c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND}); err != nil || resp.GetSendError() != "netlink" {
		t.Fatalf("send = %v, %v", resp, err)
	}
	_, err = c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP})
	wantCode(t, err, codes.Internal)
	_, err = c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_CLOSE})
	wantCode(t, err, codes.Internal)

	_, err = c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP, Slot: rootpolicy.MaxProbeSlots})
	wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleProbe))
	_, err = c.BridgeProbe(ctx, &rootdpb.BridgeProbeRequest{})
	wantRefusal(t, r, err, codes.InvalidArgument, ReasonBadRequest)
	newer := &rootdpb.BridgeProbeRequest{Op: rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND}
	newer.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	_, err = c.BridgeProbe(ctx, newer)
	wantCode(t, err, codes.Unimplemented)
}

// TestMatchProcess: only a process in a sandbox's cgroup, before and after
// the lookup, and only about the paths sent.
func TestMatchProcess(t *testing.T) {
	r, c, fe := egressRig(t)
	ctx := callCtx(t)
	req := func(pid uint32) *rootdpb.MatchProcessRequest {
		return &rootdpb.MatchProcessRequest{Pid: pid, Local: "10.88.0.5:40000", Remote: "1.2.3.4:443", Paths: []string{"/usr/bin/curl", "/bin/sh"}}
	}
	fe.cgroups[100] = []string{"0::/aerolvm/sb-1", "0::/aerolvm/sb-1"}
	fe.matched = []string{"/usr/bin/curl"}
	resp, err := c.MatchProcess(ctx, req(100))
	if err != nil || !slices.Equal(resp.GetMatched(), []string{"/usr/bin/curl"}) || resp.GetNotFound() {
		t.Fatalf("a sandbox's process = %v, %v", resp, err)
	}
	// Not a sandbox's: refused, and nothing is looked up.
	fe.cgroups[200] = []string{"0::/system.slice/containerd.service"}
	_, err = c.MatchProcess(ctx, req(200))
	wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleProcessMatch))
	// Gone before, or replaced during, the lookup: nothing to say.
	if resp, err := c.MatchProcess(ctx, req(300)); err != nil || !resp.GetNotFound() || len(resp.GetMatched()) != 0 {
		t.Fatalf("a gone process = %v, %v", resp, err)
	}
	fe.cgroups[400] = []string{"0::/aerolvm/sb-1"}
	if resp, err := c.MatchProcess(ctx, req(400)); err != nil || !resp.GetNotFound() || len(resp.GetMatched()) != 0 {
		t.Fatalf("a process gone during the lookup = %v, %v", resp, err)
	}
	fe.cgroups[500] = []string{"0::/aerolvm/sb-1", "0::/system.slice/sshd.service"}
	_, err = c.MatchProcess(ctx, req(500))
	wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleProcessMatch))
	if n := len(fe.recorded()); n != 3 {
		t.Fatalf("lookups %q", fe.recorded())
	}
	// Bad requests, and the kernel's failures.
	_, err = c.MatchProcess(ctx, &rootdpb.MatchProcessRequest{Pid: 1, Local: "10.88.0.5:1", Remote: "1.2.3.4:443", Paths: []string{"/a"}})
	wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleProcessMatch))
	fe.cgroups[600] = []string{"error"}
	_, err = c.MatchProcess(ctx, req(600))
	wantCode(t, err, codes.Internal)
	fe.cgroups[700] = []string{"0::/aerolvm/sb-1"}
	fe.fail = errors.New("procfs")
	_, err = c.MatchProcess(ctx, req(700))
	wantCode(t, err, codes.Internal)
	newer := req(100)
	newer.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	_, err = c.MatchProcess(ctx, newer)
	wantCode(t, err, codes.Unimplemented)
}

// TestMatchProcessIsBounded: a lookup the kernel makes slow (a sandbox with
// many processes and sockets) answers within matchTimeout, and the lookups
// running at once, given up on or not, and those waiting stay within their
// bounds; past them a call is answered at once. On the base a slow lookup
// held its call for as long as the agent waited, and nothing bounded how
// many ran.
func TestMatchProcessIsBounded(t *testing.T) {
	prevCalls, prevWait, prevTimeout := maxMatchCalls, maxMatchWaiting, matchTimeout
	maxMatchCalls, maxMatchWaiting, matchTimeout = 2, 1, 100*time.Millisecond
	t.Cleanup(func() { maxMatchCalls, maxMatchWaiting, matchTimeout = prevCalls, prevWait, prevTimeout })
	_, c, fe := egressRig(t)
	fe.block = make(chan struct{})
	t.Cleanup(func() { close(fe.block) })
	req := func(pid uint32) *rootdpb.MatchProcessRequest {
		fe.mu.Lock()
		fe.cgroups[int(pid)] = []string{"0::/aerolvm/sb-1", "0::/aerolvm/sb-1"}
		fe.mu.Unlock()
		return &rootdpb.MatchProcessRequest{Pid: pid, Local: "10.88.0.5:40000", Remote: "1.2.3.4:443", Paths: []string{"/bin/sh"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.MatchProcess(ctx, req(100))
	if took := time.Since(start); status.Code(err) != codes.Aborted || took > 2*time.Second {
		t.Fatalf("a slow lookup = %v after %v, want Aborted after about %v", err, took, matchTimeout)
	}
	// The given-up lookup still holds its turn: one more may run, one may
	// wait, and the next is turned away at once.
	errs := make(chan error, 2)
	for _, pid := range []uint32{101, 102} {
		go func() {
			_, err := c.MatchProcess(ctx, req(pid))
			errs <- err
		}()
	}
	waitFor(t, func() bool { return len(fe.recorded()) >= 2 })
	time.Sleep(20 * time.Millisecond) // the third is now waiting for a turn
	start = time.Now()
	_, err = c.MatchProcess(ctx, req(103))
	if status.Code(err) != codes.ResourceExhausted || time.Since(start) > time.Second || !strings.Contains(err.Error(), "executable lookups") {
		t.Fatalf("past the bound = %v after %v", err, time.Since(start))
	}
	for range 2 {
		if err := <-errs; status.Code(err) != codes.Aborted {
			t.Fatalf("a lookup within the bound = %v", err)
		}
	}
}

func TestEgressCallsWithoutANetwork(t *testing.T) {
	r := newRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	_, err := c.BridgeProbe(callCtx(t), &rootdpb.BridgeProbeRequest{})
	wantCode(t, err, codes.Unimplemented)
	_, err = c.MatchProcess(callCtx(t), &rootdpb.MatchProcessRequest{})
	wantCode(t, err, codes.Unimplemented)
}
