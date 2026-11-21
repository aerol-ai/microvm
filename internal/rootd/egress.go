package rootd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The hostname egress gateway's host side (plans/egress-domain-filtering.md;
// M1 PR 5b). The gateway is its own unprivileged process; two things it
// needs take root, which sandboxd did in single mode and the helper does in
// split:
//
//   - The self-test's probe network (BridgeProbe): a namespace joined to
//     the sandboxes' bridge, whose traffic must come back through the
//     gateway's redirect. The helper builds it on its own bridge, from its
//     own CNI config, at a source address it derives from the slot number;
//     the agent sends the step and the slot, nothing else.
//   - Executable lookups (MatchProcess): which of a sandbox's listed
//     executables holds a connection, for per-binary rules. The helper
//     answers only for a process that sits in a sandbox's cgroup (by the
//     kernel's word, before and after the lookup), and only about the
//     paths sent, so it is no oracle for the node's other processes.

// EgressHost is the kernel work behind those calls: the helper's own on
// Linux (egress_linux.go), a fake in tests.
type EgressHost interface {
	// ProbeSetup builds slot's probe network on bridge, whose sandboxes'
	// gateway is gateway; absent when the bridge has no link yet, notReady
	// when it cannot pass the redirect.
	ProbeSetup(ctx context.Context, slot int, bridge string, gateway netip.Addr, subnet netip.Prefix) (absent bool, notReady error, err error)
	// ProbeSend sends slot's probe flows.
	ProbeSend(ctx context.Context, slot int) error
	// ProbeClose removes slot's probe network; a slot with none is no error.
	ProbeClose(slot int) error
	// ProcCgroup reads /proc/<pid>/cgroup; a process that is gone is
	// errProcessGone.
	ProcCgroup(pid int) (string, error)
	// Match answers which of m.Paths m.PID's sandbox holds the connection
	// with; notFound when no process does.
	Match(m rootpolicy.ProcessMatch) (matched []string, notFound bool, err error)
}

// errProcessGone: the process asked about has exited.
var errProcessGone = errors.New("process gone")

// egressCalls serves the two calls; nil without a network configuration.
type egressCalls struct {
	net    *network
	policy rootpolicy.Policy
	host   EgressHost
	locks  *keyedLocks
}

func newEgressCalls(cfg Config, net *network, injected EgressHost, locks *keyedLocks) *egressCalls {
	if net == nil {
		return nil
	}
	h := injected
	if h == nil {
		h = newEgressHost()
	}
	return &egressCalls{net: net, policy: cfg.Policy, host: h, locks: locks}
}

var egressFeatures = []string{rootdpb.FeatureBridgeProbe, rootdpb.FeatureMatchProcess}

// probeKey is the per-object lock key of a probe slot (D11).
func probeKey(slot uint32) string { return "probe/" + strconv.FormatUint(uint64(slot), 10) }

func (e *egressCalls) bridgeProbe(ctx context.Context, req *rootdpb.BridgeProbeRequest) (*rootdpb.BridgeProbeResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	op := req.GetOp()
	if op != rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP && op != rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND &&
		op != rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_CLOSE {
		return nil, badRequest("root helper: probe op %v is not one the helper does", op)
	}
	if err := rootpolicy.CheckProbeSlot(req.GetSlot()); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	n, err := e.net.opened()
	if err != nil {
		return nil, err
	}
	unlock, err := e.locks.lock(ctx, probeKey(req.GetSlot()))
	if err != nil {
		return nil, err
	}
	defer unlock()
	slot := int(req.GetSlot())
	resp := &rootdpb.BridgeProbeResponse{}
	switch op {
	case rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP:
		subnet := n.Subnet().Masked()
		absent, notReady, err := e.host.ProbeSetup(ctx, slot, n.Bridge(), subnet.Addr().Next(), subnet)
		if err != nil {
			return nil, fmt.Errorf("root helper: probe network on %s: %w", n.Bridge(), err)
		}
		resp.BridgeAbsent = absent
		if notReady != nil {
			resp.NotReady = notReady.Error()
		}
	case rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND:
		if err := e.host.ProbeSend(ctx, slot); err != nil {
			resp.SendError = err.Error()
		}
	case rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_CLOSE:
		if err := e.host.ProbeClose(slot); err != nil {
			return nil, fmt.Errorf("root helper: remove the probe network: %w", err)
		}
	}
	return resp, nil
}

func (e *egressCalls) matchProcess(req *rootdpb.MatchProcessRequest) (*rootdpb.MatchProcessResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	m, err := rootpolicy.CheckProcessMatch(req.GetPid(), req.GetLocal(), req.GetRemote(), req.GetPaths())
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	// The process must be a sandbox's, by the kernel's word; and still be
	// after the lookup, so a process id the lookup raced (an exit and a
	// reuse by something else) answers nothing.
	sandboxed := func() (bool, error) {
		cg, err := e.host.ProcCgroup(m.PID)
		if errors.Is(err, errProcessGone) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("root helper: cgroup of process %d: %w", m.PID, err)
		}
		if err := rootpolicy.CheckSandboxCgroup(e.policy, cg); err != nil {
			return false, refusedRule(codes.PermissionDenied, err)
		}
		return true, nil
	}
	if ok, err := sandboxed(); err != nil || !ok {
		return &rootdpb.MatchProcessResponse{NotFound: true}, err
	}
	matched, notFound, err := e.host.Match(m)
	if err != nil {
		return nil, fmt.Errorf("root helper: executable lookup for process %d: %w", m.PID, err)
	}
	if ok, err := sandboxed(); err != nil || !ok {
		return &rootdpb.MatchProcessResponse{NotFound: true}, err
	}
	return &rootdpb.MatchProcessResponse{Matched: matched, NotFound: notFound}, nil
}
