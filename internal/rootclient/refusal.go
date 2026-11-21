package rootclient

import (
	"context"
	"expvar"
	"fmt"
	"regexp"
	"sync"

	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// A refusal is the helper or its containerd gate saying no to a call this
// agent made, because the request broke the helper's rules (eng review
// D9). The agent only sends what its own code built, and that passes the
// rules (the conformance test in internal/runtime/containerd), so a
// refusal is never the API caller's doing and a retry meets it again: it
// is drift between the agent and the helper, or someone who took over this
// agent asking for root. The client records every refusal it is answered
// with: it counts it in aerolvm_rootd_refusals_total, which the
// SandboxdRootHelperRefusal alert reads, and hands it to
// Config.OnRefusal, which writes the audit record. The API answers it 500
// (apihttp.Classify), not the 503 of a helper that is down.
//
// A refusal is told by the rootdpb.HelperRefused detail on the answer's
// status, which carries the reason. Only the helper's server adds it
// (containerd's own errors, passed on by the gate, never carry it), on an
// answer that also carries the helper's answered trailer; the client does
// not ask for the trailer too, which would only add a way to miss one.
//
// This record is the agent's own and only as good as the agent: an agent
// someone controls can skip it, and answer its caller as it likes. It
// cannot make the refusal pass, and it cannot touch the helper's own
// record, the line rootd.LogRefusal writes as root to the helper's log.

// ErrRefused: the helper or its containerd gate refused the call. The API
// maps it to 500.
var ErrRefused = rootdpb.ErrHelperRefused

// Refusal is one refused call. Both fields come from fixed sets, so they
// fit a metric label and an audit record; neither carries a sandbox ID, a
// path or anything else from a request.
type Refusal struct {
	// Call is the refused method's short name (rootdpb.CallName):
	// "Tasks.Create", "RootHelper.EnsureHostFiles".
	Call string
	// Reason is the helper's code for the rule the request broke: a
	// rootpolicy rule ("mount"), a gate reason ("method_not_allowed") or a
	// helper call's ("bad_request").
	Reason string
}

// RefusalFunc hears each refused call once, on the call's goroutine and
// with the call's context, before the caller gets the error. It must be
// quick and safe for concurrent use.
type RefusalFunc func(ctx context.Context, r Refusal)

// RefusedError is one of the helper's own calls that it refused. It
// matches ErrRefused and unwraps to the helper's status.
type RefusedError struct {
	Refusal
	Err error
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("root helper refused %s (%s): %s", e.Call, e.Reason, status.Convert(e.Err).Message())
}

func (e *RefusedError) Is(target error) bool { return target == ErrRefused }

func (e *RefusedError) Unwrap() error { return e.Err }

// reasonOther stands in for a reason that is not a plain code, so the
// label set stays fixed whatever a helper sends.
const reasonOther = "other"

var reasonRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// refusalsTotal is aerolvm_rootd_refusals_total{key=<call>,key2=<reason>}:
// a nested expvar map, so call and reason export as the positional key
// and key2 labels (pkg/api/prometheus.go). It is counted here, with or
// without OnRefusal, so the alert does not hang on how the hook is wired.
var (
	refusalsTotal   = expvar.NewMap("aerolvm_rootd_refusals_total")
	refusalsTotalMu sync.Mutex
)

// refused records one refusal of method, a full gRPC method name: the
// count, then the hook.
func (c *Client) refused(ctx context.Context, method, reason string) Refusal {
	r := Refusal{Call: rootdpb.CallName(method), Reason: reason}
	if !reasonRE.MatchString(r.Reason) {
		r.Reason = reasonOther
	}
	inner, ok := refusalsTotal.Get(r.Call).(*expvar.Map)
	if !ok {
		// Two first refusals of one call must not each Set a map and lose
		// the other's count.
		refusalsTotalMu.Lock()
		if inner, ok = refusalsTotal.Get(r.Call).(*expvar.Map); !ok {
			inner = new(expvar.Map)
			refusalsTotal.Set(r.Call, inner)
		}
		refusalsTotalMu.Unlock()
	}
	inner.Add(r.Reason, 1)
	if c.onRefusal != nil {
		c.onRefusal(ctx, r)
	}
	return r
}

// ownMethod is the full gRPC method of one of the helper's own calls, by
// its feature name, which is the call's name.
func ownMethod(feature string) string {
	return "/" + rootdpb.RootHelper_ServiceDesc.ServiceName + "/" + feature
}
