package rootd

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// PrepareSandbox and ReleaseSandbox: a create's root work in one call, and
// its undo in one call (plans/security-gaps-m1-m4.md §3.7; M1 PR 5 design
// note "one helper call per create"). Each is made of parts, and each part
// keeps its own rules and refusal reasons: netns (network.go: the name
// rule, kernel ownership) and firewall (firewall.go: the address and lease
// rules, the CIDR rule).
//
// Version skew (agent N with helper N-1, eng review D5) must never drop a
// part without a word. Protobuf keeps a field it does not know and acts on
// nothing, so the helper checks: every listed part must be one it serves,
// and the request must hold no field it does not know. Either answers
// Unimplemented, which the agent reads as "the helper lacks this" (a
// version skew, not a refusal). The agent, for its part, sends a part only
// when the handshake listed it, and fails a create that needs one the
// helper lacks.
//
// D11: one call takes its slot's lock (netns/<name>) for the whole of it,
// then the address's lock (addr/<ip>) once the address is known. Every
// other call takes them in that order too.

// errSkew is a request this helper is too old for.
func errSkew(format string, args ...any) error {
	return &fileError{code: codes.Unimplemented, msg: fmt.Sprintf(format, args...)}
}

// noUnknownFields answers Unimplemented when m, or any message in it,
// holds a field this build does not know: a newer agent's part.
func noUnknownFields(m proto.Message) error {
	var walk func(protoreflect.Message) error
	walk = func(r protoreflect.Message) error {
		if len(r.GetUnknown()) > 0 {
			return errSkew("root helper: %s carries a field this helper does not know; it is older than the agent", r.Descriptor().FullName())
		}
		var err error
		r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			switch {
			case fd.IsList() && fd.Message() != nil:
				l := v.List()
				for i := range l.Len() {
					if err = walk(l.Get(i).Message()); err != nil {
						return false
					}
				}
			case fd.Message() != nil && !fd.IsMap():
				err = walk(v.Message())
			}
			return err == nil
		})
		return err
	}
	return walk(m.ProtoReflect())
}

// partsOf checks a request's parts: each once, each served.
func partsOf(list []string, served []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range list {
		if out[p] {
			return nil, badRequest("root helper: part %q listed twice", p)
		}
		if !slices.Contains(served, p) {
			return nil, errSkew("root helper: this helper does not serve part %q; it is older than the agent", p)
		}
		out[p] = true
	}
	if len(out) == 0 {
		return nil, badRequest("root helper: a request with no parts")
	}
	return out, nil
}

func (f *firewall) prepare(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	parts, err := partsOf(req.GetParts(), f.servedParts())
	if err != nil {
		return nil, err
	}
	if req.GetFirewall() != nil && !parts[rootdpb.PartFirewall] {
		return nil, badRequest("root helper: firewall rules sent without the firewall part")
	}
	name := req.GetNetnsName()
	path, err := f.net.path(name)
	if err != nil {
		return nil, err
	}
	var allow, deny []string
	fw := req.GetFirewall()
	if parts[rootdpb.PartFirewall] {
		if allow, deny, err = policyLists(fw.GetAllowCidrs(), fw.GetDenyCidrs()); err != nil {
			return nil, err
		}
	}
	if parts[rootdpb.PartNetns] == (req.GetContainerIp() != "") {
		return nil, badRequest("root helper: a request names its address only when it has no netns part")
	}
	h, n, err := f.opened()
	if err != nil {
		return nil, err
	}
	// A turn among the network calls (network.limit), for the whole call.
	done, err := f.net.limit.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	unlock, err := f.locks.lock(ctx, netnsKey(name))
	if err != nil {
		return nil, err
	}
	defer unlock()
	resp := &rootdpb.PrepareSandboxResponse{}
	var ip string
	if parts[rootdpb.PartNetns] {
		r, err := f.net.realizeLocked(ctx, n, name, path)
		if err != nil {
			return nil, err
		}
		resp.NetnsPath, resp.ContainerIp, ip = r.GetNetnsPath(), r.GetContainerIp(), r.GetContainerIp()
	} else {
		a, err := rootpolicy.CheckSandboxAddress(n.Subnet(), req.GetContainerIp())
		if err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
		ip = a.String()
	}
	if !parts[rootdpb.PartFirewall] {
		return resp, nil
	}
	unlock2, err := f.locks.lock(ctx, addrKey(ip))
	if err != nil {
		return nil, err
	}
	defer unlock2()
	if !parts[rootdpb.PartNetns] {
		// A warm slot: its address must be the one the helper's CNI
		// leased to it.
		if _, err := address(n, ip, true, name); err != nil {
			return nil, err
		}
	}
	inserted, err := f.applyCreateRules(ctx, h, ip, fw.GetBlockAllEgress(), allow, deny)
	if err != nil {
		// Leave nothing half done: the rules this call put in go, and so
		// does a namespace it realized; the agent's create rolls back.
		undo := h.ClearAddress(ip)
		if undo == nil {
			f.budget.release(ip)
		}
		// The namespace goes only once its address's rules have (PR 5
		// review): CNI DEL frees the address, and the next slot to get it
		// would get these rules with it. A slot whose clear failed stays,
		// and the agent's undo releases it again.
		if parts[rootdpb.PartNetns] && undo == nil {
			undo = n.Remove(ctx, name, path, ip)
		}
		return nil, errors.Join(fmt.Errorf("root helper: the create's rules on %s: %w", ip, err), undo)
	}
	resp.BlockInserted = inserted
	return resp, nil
}

// applyCreateRules puts a create's rules on ip: block-all, then the CIDR
// lists, as the agent's driver does in single mode.
func (f *firewall) applyCreateRules(ctx context.Context, h FirewallHost, ip string, blockAll bool, allow, deny []string) (bool, error) {
	var inserted bool
	if blockAll {
		var err error
		if inserted, err = h.Rules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, ip, nil, nil); err != nil {
			return false, err
		}
	}
	if len(allow) > 0 || len(deny) > 0 {
		if err := f.budget.reserve(ip, len(allow)+len(deny)+1); err != nil {
			return inserted, err
		}
		if _, err := h.Rules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, ip, allow, deny); err != nil {
			return inserted, err
		}
	}
	return inserted, nil
}

func (f *firewall) release(ctx context.Context, req *rootdpb.ReleaseSandboxRequest) (*rootdpb.ReleaseSandboxResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	parts, err := partsOf(req.GetParts(), f.servedParts())
	if err != nil {
		return nil, err
	}
	name := req.GetNetnsName()
	path, err := f.net.path(name)
	if err != nil {
		return nil, err
	}
	if parts[rootdpb.PartFirewall] && !parts[rootdpb.PartNetns] && req.GetContainerIp() == "" {
		return nil, badRequest("root helper: the firewall part alone needs the slot's address")
	}
	h, n, err := f.opened()
	if err != nil {
		return nil, err
	}
	done, err := f.net.limit.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	ip := ""
	if req.GetContainerIp() != "" {
		a, err := rootpolicy.CheckSandboxAddress(n.Subnet(), req.GetContainerIp())
		if err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
		ip = a.String()
	}
	unlock3, err := f.locks.lock(ctx, netnsKey(name))
	if err != nil {
		return nil, err
	}
	defer unlock3()
	var st NetnsState
	if parts[rootdpb.PartNetns] {
		if st, err = inspect(n, name, path); err != nil {
			return nil, err
		}
	}
	if parts[rootdpb.PartNetns] {
		// The slot's own address, not the one the agent names (PR 5
		// review): the namespace's, or for gVisor, which takes the address
		// out of the kernel's view, the one the helper's CNI leased to this
		// slot. CNI DEL frees that address, so its rules must go first,
		// whatever the agent sent. The agent's is used only when the slot
		// has none to show (a namespace already gone), and then only an
		// address no other slot holds (checked below).
		own := sandboxAddress(n.Subnet(), st.IPv4)
		if own == "" {
			a, ok, err := n.LeaseOf(name)
			if err != nil {
				return nil, fmt.Errorf("root helper: lease of %s: %w", name, err)
			}
			if ok {
				own = a.String()
			}
		}
		if own != "" {
			ip = own
		}
	}
	if ip != "" {
		unlock4, err := f.locks.lock(ctx, addrKey(ip))
		if err != nil {
			return nil, err
		}
		defer unlock4()
	}
	if parts[rootdpb.PartFirewall] && ip != "" {
		// Before CNI DEL frees the lease: the address's next holder can
		// never have its rules cleared by this call.
		if _, err := address(n, ip, false, name); err != nil {
			return nil, err
		}
		if err := h.ClearAddress(ip); err != nil {
			return nil, fmt.Errorf("root helper: clear the rules of %s: %w", ip, err)
		}
		f.budget.release(ip)
	}
	if parts[rootdpb.PartNetns] {
		if err := n.Remove(ctx, name, path, ip); err != nil {
			return nil, fmt.Errorf("root helper: remove network namespace %s: %w", name, err)
		}
	}
	return &rootdpb.ReleaseSandboxResponse{}, nil
}
