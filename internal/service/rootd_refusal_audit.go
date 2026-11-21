package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/internal/rootclient"
)

// auditKindRootdRefusal is the audit record for a call the node's root
// helper or its containerd gate refused (plans/security-gaps-m1-m4.md
// §3.3, eng review D9). Like failover_refused it uses only fields every
// build already hashes, so an older reader verifies it.
const auditKindRootdRefusal = "rootd_refusal"

// RecordRootRefusal writes the audit record of one refusal: the call, the
// reason and this node (rootclient.RefusalFunc; the daemon passes it as
// rootclient.Config.OnRefusal). The client calls it on the refused call's
// goroutine, before the caller gets its 500; Emit queues, so it never
// waits on the disk.
//
// The record holds the call and the reason, both from fixed sets, and no
// sandbox ID, path or other request content: what a refusal is about
// tells an auditor which rule held, while the request itself may be a
// tenant's input. The caller is the request's principal, or the
// subsystem's, as on every record: who led this node to make the call.
// The record is this agent's own, so an agent someone controls can skip
// it; the root helper's log keeps its own line (rootd.LogRefusal).
func (s *Service) RecordRootRefusal(ctx context.Context, r rootclient.Refusal) {
	if s == nil {
		return
	}
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	actor := s.auditActor()
	ev := SecretAuditEvent{
		Time:        time.Now().UTC(),
		Actor:       actor,
		NodeID:      actor,
		Result:      secretAuditResultFailure,
		Reason:      r.Reason,
		Kind:        auditKindRootdRefusal,
		Destination: "call=" + r.Call,
	}
	// The caller field is hash-covered and gated on every member reading
	// it (§5.8); without the gate the record still lands, unattributed.
	if s.auditCallerWritesAllowed() {
		ev.Caller = AuditCallerFromContext(ctx)
	}
	ensureSecretAuditEventID(&ev)
	sink.Emit(ev)
}
