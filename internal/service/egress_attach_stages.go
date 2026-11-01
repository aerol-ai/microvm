package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Sub-stages of one gateway attach. svc_egress_attach is their sum; the
// split is what a live run needs to tell the gateway round trip apart from
// sandboxd's own store reads and the host firewall write that lifts the
// driver's block (the §8.2 budget is on the sum).
const (
	attachStageLookup  = "lookup"  // spec, hold record, injected secrets, pid
	attachStageReady   = "ready"   // the bootstrap latch (one atomic load when up)
	attachStageRPC     = "rpc"     // the gateway Attach over the UDS
	attachStageRelease = "release" // the gateway-hold release
	attachStageUnblock = "unblock" // ClearNetworkBlockEgress on the host firewall
)

// attachStages times an attach's sub-stages into its egress.attach span (as
// attributes) and into the create's Server-Timing (svc_egress_attach_<name>,
// only when the attach runs inside a create: createtiming.From is nil
// elsewhere and records nothing).
type attachStages struct {
	ctx  context.Context
	span oteltrace.Span
	last time.Time
	hook func(stage string, d time.Duration)
}

func (s *Service) newAttachStages(ctx context.Context, span oteltrace.Span) *attachStages {
	return &attachStages{ctx: ctx, span: span, last: time.Now(), hook: s.testAttachStage}
}

// mark closes the stage that ran since the previous mark.
func (a *attachStages) mark(stage string) {
	now := time.Now()
	d := now.Sub(a.last)
	a.last = now
	if a.span != nil {
		a.span.SetAttributes(attribute.Int64("egress.attach."+stage+"_us", d.Microseconds()))
	}
	createtiming.From(a.ctx).RecordStage("svc_egress_attach_"+stage, d)
	if a.hook != nil {
		a.hook(stage, d)
	}
}
