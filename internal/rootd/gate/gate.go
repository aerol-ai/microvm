// Package gate is the root helper's containerd gate: a gRPC handler that
// forwards containerd's own API from the unprivileged agent to the real
// containerd socket, which only root can open.
//
// The containerd socket is as good as root: whoever can write to it can
// start a privileged container that mounts /. So the gate passes only the
// methods the agent calls today (allowlist.go) and refuses every other one.
// Reads pass through. Every write is walked field by field (fields.go) and
// checked against internal/rootpolicy, the same rules the agent's spec
// builder takes its data from, before containerd sees it
// (plans/security-gaps-m1-m4.md §3.3, eng review D6).
//
// A refusal should never happen: the agent only sends what its own builder
// made, and the builder's output passes (the conformance test in
// internal/runtime/containerd). So a refusal means drift or a compromised
// agent (eng review D9). Each one goes to the OnRefusal callback, the
// helper's own record, and its answer carries the reason
// (rootdpb.HelperRefused), from which the agent's client writes the audit
// event and counts the metric the alert reads.
//
// Calls run in parallel (eng review D11). The gate's one piece of state is
// a bounded memo of spec checks a create has already paid for
// (specmemo.go), keyed on the exact bytes checked; it never decides a
// check that was not made in full for those bytes. Nothing here is wired
// into sandboxd or the helper yet.
package gate

import (
	"context"
	"errors"
	"fmt"
	"io"

	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// Reasons a refusal can give besides a rootpolicy rule. Each is a short,
// stable code, fit for a metric label.
const (
	ReasonMethod       = "method_not_allowed"
	ReasonNamespace    = string(rootpolicy.RuleNamespace)
	ReasonUnknownField = "unknown_field"
	ReasonField        = "field_not_allowed"
)

// Refusal is one refused call.
type Refusal struct {
	// Method is the full gRPC method, e.g.
	// /containerd.services.tasks.v1.Tasks/Exec.
	Method string
	// Reason is a rootpolicy.Rule or one of the Reason constants.
	Reason string
	// Detail says what about the request broke the rule.
	Detail string
}

// RefusalFunc hears every refusal. Calls arrive in parallel, on the
// refused call's goroutine, before the caller gets its error, so it must be
// quick and safe for concurrent use.
type RefusalFunc func(ctx context.Context, r Refusal)

// Config is what the gate needs.
type Config struct {
	// Policy is the helper's own policy, never the agent's.
	Policy rootpolicy.Policy
	// Upstream is a connection to the real containerd socket.
	Upstream grpc.ClientConnInterface
	// OnRefusal, when set, hears every refusal.
	OnRefusal RefusalFunc
	// Stdio checks each task stdio path on disk. Nil means the platform's
	// own: on Linux, a FIFO root made, reached with no link on the way;
	// elsewhere every path is refused.
	Stdio StdioChecker
	// Binds checks each spec bind source on disk. Nil means the platform's
	// own: on Linux, no link on the way and root's folders only; elsewhere
	// every bind is refused.
	Binds BindChecker
	// Reads checks each path a container makes root read (its runsc
	// config, a restore image) on disk. Nil means the platform's own: on
	// Linux, root's and reached through root's folders with no link on
	// the way; elsewhere every such path is refused.
	Reads ReadChecker
	// NetnsBinding, when set, must vouch for every named network namespace
	// a container joins. Nil checks the name's form only (see NetnsBinding).
	NetnsBinding NetnsBinding
}

// Gate forwards the allowed part of containerd's API.
type Gate struct {
	policy    rootpolicy.Policy
	upstream  grpc.ClientConnInterface
	onRefusal RefusalFunc
	stdio     StdioChecker
	binds     BindChecker
	reads     ReadChecker
	netns     NetnsBinding
	// specs remembers which spec bytes passed for which container.
	specs *specMemo
}

// New checks the policy and returns a gate.
func New(cfg Config) (*Gate, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("containerd gate: %w", err)
	}
	if cfg.Upstream == nil {
		return nil, errors.New("containerd gate: a connection to containerd is required")
	}
	// The gate's own copy: the memo's answers hold for the policy they
	// were made under, so no caller may change it after New.
	p := cfg.Policy.Clone()
	g := &Gate{policy: p, upstream: cfg.Upstream, onRefusal: cfg.OnRefusal,
		stdio: cfg.Stdio, binds: cfg.Binds, reads: cfg.Reads, netns: cfg.NetnsBinding,
		specs: newSpecMemo(p, memoEntries, memoEntryBytes)}
	if g.stdio == nil {
		g.stdio = defaultStdioChecker()
	}
	if g.binds == nil {
		g.binds = defaultBindChecker()
	}
	if g.reads == nil {
		g.reads = defaultReadChecker()
	}
	return g, nil
}

// ServerOptions makes a gRPC server hand the gate every method it does not
// serve itself (the helper's own typed calls share the server and its peer
// check, eng review D3), with containerd's message size limits.
func (g *Gate) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.UnknownServiceHandler(g.Handle),
		grpc.ForceServerCodecV2(frameCodec{}),
		grpc.MaxRecvMsgSize(defaults.DefaultMaxRecvMsgSize),
		grpc.MaxSendMsgSize(defaults.DefaultMaxSendMsgSize),
	}
}

var upstreamCallOptions = []grpc.CallOption{
	grpc.MaxCallRecvMsgSize(defaults.DefaultMaxRecvMsgSize),
	grpc.MaxCallSendMsgSize(defaults.DefaultMaxSendMsgSize),
	grpc.ForceCodecV2(frameCodec{}),
}

// Handle serves one call: it is a grpc.StreamHandler, for unary and
// streaming methods alike.
func (g *Gate) Handle(_ any, ss grpc.ServerStream) error {
	ctx := ss.Context()
	name, ok := grpc.MethodFromServerStream(ss)
	if !ok {
		return status.Error(codes.Internal, "containerd gate: the stream names no method")
	}
	m := methods[name]
	if m == nil {
		return g.refuse(ctx, name, ReasonMethod, "the method is not one the agent uses")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if ns := md.Get(namespaces.GRPCHeader); len(ns) != 1 || rootpolicy.CheckNamespace(g.policy, ns[0]) != nil {
		return g.refuse(ctx, name, ReasonNamespace, fmt.Sprintf("the call is in containerd namespace %q, not %q", ns, g.policy.Namespace))
	}
	// The first message is checked before containerd hears of the call.
	first := m.request()
	if err := ss.RecvMsg(first); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // a stream the client closed without a message
		}
		return err
	}
	if err := g.check(ctx, m, first); err != nil {
		return err
	}

	upCtx, cancel := context.WithCancel(metadata.NewOutgoingContext(ctx, forwarded(md)))
	defer cancel()
	cs, err := g.upstream.NewStream(upCtx, &grpc.StreamDesc{ServerStreams: m.serverStream, ClientStreams: m.clientStream}, name, upstreamCallOptions...)
	if err != nil {
		return err
	}
	// io.EOF means containerd ended the call; RecvMsg below has its status.
	if err := cs.SendMsg(first); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	refused := make(chan error, 1)
	if m.clientStream {
		go g.forwardRequests(ctx, cancel, ss, cs, m, refused)
	} else if err := cs.CloseSend(); err != nil {
		return err
	}
	if err := forwardResponses(ss, cs, m); err != nil {
		select {
		case r := <-refused:
			return r // the refusal, not the cancel it caused
		default:
			return err
		}
	}
	return nil
}

// forwardRequests checks and forwards a client stream's later messages. A
// refusal cancels the call upstream, so containerd never sees the message,
// and is handed back on refused.
func (g *Gate) forwardRequests(ctx context.Context, cancel context.CancelFunc, ss grpc.ServerStream, cs grpc.ClientStream, m *method, refused chan<- error) {
	for {
		r := m.request()
		if err := ss.RecvMsg(r); err != nil {
			if errors.Is(err, io.EOF) {
				_ = cs.CloseSend()
			} else {
				cancel()
			}
			return
		}
		if err := g.check(ctx, m, r); err != nil {
			refused <- err
			cancel()
			return
		}
		if err := cs.SendMsg(r); err != nil {
			return // containerd's status arrives through RecvMsg
		}
	}
}

func forwardResponses(ss grpc.ServerStream, cs grpc.ClientStream, m *method) error {
	defer func() { ss.SetTrailer(cs.Trailer()) }()
	for {
		resp := &frame{} // the gate reads no answer (frame.go)
		if err := cs.RecvMsg(resp); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := ss.SendMsg(resp); err != nil {
			return err
		}
		if !m.serverStream {
			return nil
		}
	}
}

// check runs the walk (writes) and the method's rootpolicy checks on one
// request message. Its error is the PermissionDenied the caller gets, or,
// when a check could not run (containerd did not answer), that error.
func (g *Gate) check(ctx context.Context, m *method, req any) error {
	if m.passThrough() {
		return nil // a read the policy passes unread (frame.go)
	}
	r, ok := req.(proto.Message)
	if !ok { // m.request decodes every message a check reads
		return status.Errorf(codes.Internal, "containerd gate: %s arrived undecoded", m.name)
	}
	if m.write {
		if err := walk(r.ProtoReflect()); err != nil {
			var fe *fieldError
			errors.As(err, &fe)
			return g.refuse(ctx, m.name, fe.reason, fe.detail)
		}
	}
	if m.check == nil {
		return nil
	}
	err := m.check(ctx, g, r)
	if err == nil {
		return nil
	}
	if rule := rootpolicy.RuleOf(err); rule != "" {
		return g.refuse(ctx, m.name, string(rule), err.Error())
	}
	return err
}

// refuse reports a refusal and answers it. The answer carries the reason
// as a rootdpb.HelperRefused detail, which is how the agent's client tells
// a refusal from containerd's own errors and records it (eng review D9).
func (g *Gate) refuse(ctx context.Context, method, reason, detail string) error {
	if g.onRefusal != nil {
		g.onRefusal(ctx, Refusal{Method: method, Reason: reason, Detail: detail})
	}
	return rootdpb.Refused(codes.PermissionDenied, reason, fmt.Sprintf("aerolvm root gate refused %s (%s): %s", method, reason, detail))
}

// forwarded is the metadata containerd reads: the namespace (already
// checked) and the lease a client's writes are held under. Anything else
// the agent sends stays at the gate.
func forwarded(in metadata.MD) metadata.MD {
	out := metadata.MD{}
	for _, k := range []string{namespaces.GRPCHeader, leases.GRPCHeader} {
		if v := in.Get(k); len(v) > 0 {
			out.Set(k, v...)
		}
	}
	return out
}

// upstreamContext is the context the gate's own calls to containerd use.
func (g *Gate) upstreamContext(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(namespaces.GRPCHeader, g.policy.Namespace))
}

// VerifyNamespace checks, from containerd, that the agent's namespace sets
// no default runtime, snapshotter or sandboxer: a default there changes
// what every create that names none runs. The helper calls it at start. A
// namespace containerd has not made yet has no labels.
func (g *Gate) VerifyNamespace(ctx context.Context) error {
	resp, err := namespacesapi.NewNamespacesClient(g.upstream).Get(g.upstreamContext(ctx), &namespacesapi.GetNamespaceRequest{Name: g.policy.Namespace})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("containerd gate: read namespace %s: %w", g.policy.Namespace, err)
	}
	return rootpolicy.CheckNamespaceLabels(resp.GetNamespace().GetLabels())
}
