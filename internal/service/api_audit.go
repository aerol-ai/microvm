package service

import (
	"context"
	"expvar"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// API action records (plans/identity-and-access.md §5.9). The API edge
// decides which calls to record and describes each one in an APICall; this
// file turns it into a kind "api" chain record that names the caller (from
// ctx, like every other record), stamps the sandbox's lifecycle and owner
// so the per-sandbox audit read finds it, and hands it to the buffered
// writer. The same writer funnel then merges or budgets floods
// (api_audit_flood.go).
//
// Cost on the request path: building one struct, one lookup in the audit
// identity cache, and a non-blocking channel send. No fsync (unless the
// call is one of the three SB_AUDIT_API_DURABLE covers), no network, and
// nothing on the CreateSandbox path itself: the record for a create is
// written by the edge after the handler returns.

// APICall is one call the API edge asks the service to record.
type APICall struct {
	// Method and Route are the HTTP method and the matched route pattern
	// without its method ("/v1/sandboxes/{id}/exec").
	Method string
	Route  string
	Status int
	// SandboxID is the sandbox the call acted on; "" for none.
	SandboxID string
	// IncarnationID and OwnerRef are the sandbox's lifecycle and owner when
	// the edge resolved them before the handler ran (a delete forgets them
	// once it succeeds). Empty means resolve now.
	IncarnationID string
	OwnerRef      string
	// Target, Digest, Argv and Surface fill the record's request (see
	// auditlog.Request).
	Target  string
	Digest  string
	Argv    []string
	Surface string
	// Grant is the role and team a token create handed out.
	Grant *auditlog.Grant
	// Denied is a refused call (403, or a 400/403 from authentication).
	Denied bool
	// Durable waits for the record to reach disk (SB_AUDIT_API_DURABLE).
	Durable bool
}

// APIAuditPolicy is what the API edge needs to decide which calls to
// record and how.
type APIAuditPolicy struct {
	// Enabled is false with SB_AUDIT_API_RECORDS=off, or while the cluster
	// audit gate is closed (an older member could not verify the records).
	Enabled bool
	// AllReads records plain GETs too (SB_AUDIT_API_RECORDS=all).
	AllReads bool
	// ExecArgv records the argv of exec calls (SB_AUDIT_EXEC_COMMAND=full).
	ExecArgv bool
	// Durable makes token create, token revoke and sandbox delete wait for
	// their record to reach disk (SB_AUDIT_API_DURABLE).
	Durable bool
}

// apiRecordsMode is SB_AUDIT_API_RECORDS, defaulted for a Service built
// without config.Load (tests).
func (s *Service) apiRecordsMode() string {
	switch m := strings.TrimSpace(s.cfg.AuditAPIRecords); m {
	case config.AuditAPIRecordsOff, config.AuditAPIRecordsAll:
		return m
	}
	return config.AuditAPIRecordsMutations
}

// APIAuditPolicy reports the api-record policy right now. The gate part can
// change at runtime (the last old member leaves), so the edge asks per call.
func (s *Service) APIAuditPolicy() APIAuditPolicy {
	if s == nil || s.apiRecordsMode() == config.AuditAPIRecordsOff {
		return APIAuditPolicy{}
	}
	return APIAuditPolicy{
		Enabled:  s.auditCallerWritesAllowed(),
		AllReads: s.apiRecordsMode() == config.AuditAPIRecordsAll,
		ExecArgv: strings.TrimSpace(s.cfg.AuditExecCommand) == config.AuditExecCommandFull,
		Durable:  s.cfg.AuditAPIDurable,
	}
}

// APIRecordsConfigured reports whether api records can ever be written on
// this node (SB_AUDIT_API_RECORDS is not off). The edge installs its hook
// only then, so "off" costs nothing per request.
func (s *Service) APIRecordsConfigured() bool {
	return s != nil && s.apiRecordsMode() != config.AuditAPIRecordsOff
}

// AuditIdentityForSandbox is the lifecycle id and owner a record about
// sandboxID is stamped with. The edge resolves it before a call that may
// end the lifecycle (a delete), so the record still finds the sandbox's
// history afterwards. A cache hit after the sandbox's first record.
func (s *Service) AuditIdentityForSandbox(sandboxID string) (incarnationID, ownerRef string) {
	if s == nil || strings.TrimSpace(sandboxID) == "" {
		return "", ""
	}
	return s.auditIdentityFor(strings.TrimSpace(sandboxID))
}

var auditAPIRecordsTotal = expvar.NewMap("aerolvm_audit_api_records_total")

// RecordAPICall writes one kind "api" record for call, attributed to the
// caller in ctx. It never blocks on disk unless call.Durable is set and
// durable records are configured.
func (s *Service) RecordAPICall(ctx context.Context, call APICall) {
	if s == nil || s.apiRecordsMode() == config.AuditAPIRecordsOff || !s.auditCallerWritesAllowed() {
		return
	}
	ev := s.apiEvent(ctx, call)
	ev.Caller = AuditCallerFromContext(ctx)
	s.emitAPIEvent(ev, call.Durable && s.cfg.AuditAPIDurable)
}

// apiEvent builds the record for call, without its caller.
func (s *Service) apiEvent(ctx context.Context, call APICall) SecretAuditEvent {
	actor := s.auditActor()
	route := strings.TrimSpace(call.Route)
	method := strings.ToUpper(strings.TrimSpace(call.Method))
	ref := route
	if method != "" {
		ref = method + " " + route
	}
	result := auditlog.APIResultForStatus(call.Status)
	if call.Denied {
		result = auditlog.APIResultDenied
	}
	ev := SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		NodeID:        actor,
		SandboxID:     strings.TrimSpace(call.SandboxID),
		Ref:           ref,
		Result:        result,
		CorrelationID: correlationIDFromContext(ctx),
		Kind:          auditlog.KindAPI,
		Request: &auditlog.Request{
			Method:  method,
			Route:   route,
			Status:  call.Status,
			Digest:  call.Digest,
			Surface: call.Surface,
			Argv:    call.Argv,
			Target:  strings.TrimSpace(call.Target),
			Grant:   call.Grant,
		},
	}
	if ev.CorrelationID == "" {
		ev.CorrelationID = newSecretAuditCorrelationID()
	}
	if ev.SandboxID != "" {
		ev.IncarnationID, ev.OwnerRef = strings.TrimSpace(call.IncarnationID), strings.TrimSpace(call.OwnerRef)
		if ev.IncarnationID == "" {
			ev.IncarnationID, ev.OwnerRef = s.auditIdentityFor(ev.SandboxID)
		}
	}
	return ev
}

// emitAPIEvent hands ev to the writer and counts it.
func (s *Service) emitAPIEvent(ev SecretAuditEvent, durable bool) {
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	auditAPIRecordsTotal.Add(ev.Result, 1)
	if durable {
		if d, ok := sink.(DurableSecretAuditSink); ok {
			if err := d.EmitDurable(ev); err != nil && s.logger != nil {
				// The call already happened; failing it now would not undo
				// it. The writer has counted the loss as a gap.
				s.logger.Warn("durable api audit record not persisted", "ref", ev.Ref, "sandbox_id", ev.SandboxID, "error", err)
			}
			return
		}
	}
	sink.Emit(ev)
}

// RecordAuthDenied writes one auth_denied record for a refused credential
// from source. The API edge rate-limits it to one per source address per
// minute and passes how many 401s that record stands for.
func (s *Service) RecordAuthDenied(ctx context.Context, method, route, reason, source string, count int64) {
	if s == nil || s.apiRecordsMode() == config.AuditAPIRecordsOff || !s.auditCallerWritesAllowed() {
		return
	}
	ev := s.apiEvent(ctx, APICall{Method: method, Route: route, Status: 401})
	ev.Kind = auditlog.KindAuthDenied
	ev.Reason = strings.TrimSpace(reason)
	ev.Request.Source = strings.TrimSpace(source)
	if count > 1 {
		ev.Dropped = count - 1
	}
	s.emitAPIEvent(ev, false)
}

// RecordSSHSession writes the record of an SSH session opened through the
// gateway (CEO review D3). The key that opened it belongs to the sandbox,
// not to a person, so the caller is the sandbox key; whoever created the
// sandbox is found through its create record. session is the toolbox
// session name it attached to ("" for a one-shot exec).
//
// The gateway calls it for a session on its own node. For a session it
// bridged to another node the owner calls it, under the request that opened
// the session there (pkg/api), and the caller names the gateway's node as
// Via, the way a forwarded call's does.
func (s *Service) RecordSSHSession(ctx context.Context, sandboxID, session string) {
	if s == nil || s.apiRecordsMode() == config.AuditAPIRecordsOff || !s.auditCallerWritesAllowed() {
		return
	}
	ev := s.apiEvent(ctx, APICall{Method: "SSH", Route: auditlog.RefSSH, SandboxID: sandboxID, Surface: auditlog.SurfaceSSH, Target: session})
	ev.Ref = auditlog.RefSSH
	ev.Caller = sandboxKeyCaller(ctx, sandboxID)
	s.emitAPIEvent(ev, false)
}

// SSHSessionsRecordedByOwner reports whether the SSH gateway may leave the
// record of a session it bridges to another node to that node, the owner
// (cluster.SSHSessionRecordGate). False on a single node, which bridges
// nothing, and in cluster mode until every live member runs a build that
// writes it; the gateway then records the session itself, as before.
func (s *Service) SSHSessionsRecordedByOwner() bool {
	if s == nil || !s.cfg.EnableCluster {
		return false
	}
	gate, ok := s.Cluster().(cluster.SSHSessionRecordGate)
	return ok && gate.SSHSessionOwnerRecordAllowed()
}

// System actions: destructive work the daemon does on its own. They used to
// be slog lines only; now "who deleted this sandbox" always has an answer,
// caller system:<subsystem> (§5.9, "System actions").
const (
	systemActionAutoStop    = "lifecycle.auto_stop"
	systemActionAutoDelete  = "lifecycle.auto_delete"
	systemActionReap        = "reconcile.reap"
	systemActionOrphanReap  = "reconcile.orphan_delete"
	systemActionMarkError   = "reconcile.mark_error"
	systemActionMethod      = "SYSTEM"
	auditSubsystemAuditMode = "audit"
)

// beginSystemAction resolves the sandbox's lifecycle and owner now, before
// the action can end the lifecycle, and returns the function that writes
// the record once the outcome is known. A no-op when records are off.
func (s *Service) beginSystemAction(ctx context.Context, sandboxID, action string) func(error) {
	if s == nil || s.apiRecordsMode() == config.AuditAPIRecordsOff {
		return func(error) {}
	}
	inc, owner := s.AuditIdentityForSandbox(sandboxID)
	return func(err error) {
		if !s.auditCallerWritesAllowed() {
			return
		}
		status := 200
		if err != nil {
			status = 500
		}
		ev := s.apiEvent(ctx, APICall{Method: systemActionMethod, Route: action, Status: status, SandboxID: sandboxID, IncarnationID: inc, OwnerRef: owner})
		ev.Caller = AuditCallerFromContext(ctx)
		s.emitAPIEvent(ev, false)
	}
}

// Flood mode (D14). The configured mode applies as is, except that a node
// hosting sandboxes of more than one owner always budgets: coalesce runs as
// both there. The node re-evaluates after every local create and delete
// (an async nudge, so the create path pays one non-blocking send) and on a
// slow ticker that catches any path without a nudge. Every change of the
// effective mode writes one chain record.

const apiFloodRecheckEvery = 30 * time.Second

var auditAPIFloodModeGauge = expvar.NewMap("aerolvm_audit_api_flood_mode")

type apiFloodState struct {
	control    *apiFloodControl
	configured apiFloodMode

	mu       sync.Mutex
	recorded apiFloodMode // the effective mode the chain last recorded
	exported string       // the configured/effective pair the gauge shows

	once sync.Once
	// nudge is read by every create and delete, possibly while the sink is
	// still opening on another goroutine, so it is published atomically.
	nudge   atomic.Pointer[chan struct{}]
	stop    chan struct{} // guarded by mu
	done    sync.WaitGroup
	stopped bool // guarded by mu
}

// newAPIFloodControlFor builds the writer's flood control from config. A
// coalesce node starts as both, the safe mode, until its first evaluation
// shows it hosts a single owner.
func (s *Service) newAPIFloodControlFor() *apiFloodControl {
	configured := parseAPIFloodMode(s.cfg.AuditAPIFloodControl)
	s.apiFlood.configured = configured
	start := configured
	if configured == apiFloodCoalesce {
		start = apiFloodBoth
	}
	c := newAPIFloodControl(start, s.cfg.AuditAPIRate, s.cfg.AuditAPIBurst, 0)
	s.apiFlood.control = c
	s.exportAPIFloodMode(start)
	return c
}

// NoteLocalOwnersChanged nudges the flood-mode evaluator after a local
// create or delete. Non-blocking: a nudge already pending covers this one.
func (s *Service) NoteLocalOwnersChanged() {
	if s == nil {
		return
	}
	nudge := s.apiFlood.nudge.Load()
	if nudge == nil {
		return
	}
	select {
	case *nudge <- struct{}{}:
	default:
	}
}

// startAPIFloodEvaluator runs the shared-node rule on a coalesce node. A
// budget or both node never changes mode, so it starts nothing.
func (s *Service) startAPIFloodEvaluator() {
	st := &s.apiFlood
	if st.control == nil || st.configured != apiFloodCoalesce {
		return
	}
	st.once.Do(func() {
		nudge := make(chan struct{}, 1)
		st.mu.Lock()
		if st.stopped {
			st.mu.Unlock()
			return
		}
		st.stop = make(chan struct{})
		stop := st.stop
		st.done.Add(1)
		st.mu.Unlock()
		st.nudge.Store(&nudge)
		go func() {
			defer st.done.Done()
			ticker := time.NewTicker(apiFloodRecheckEvery)
			defer ticker.Stop()
			s.reevaluateAPIFloodMode(context.Background())
			for {
				select {
				case <-stop:
					return
				case <-nudge:
				case <-ticker.C:
				}
				s.reevaluateAPIFloodMode(context.Background())
			}
		}()
	})
}

func (s *Service) stopAPIFloodEvaluator() {
	st := &s.apiFlood
	st.mu.Lock()
	if st.stopped {
		st.mu.Unlock()
		return
	}
	st.stopped = true
	if st.stop != nil {
		close(st.stop)
	}
	st.mu.Unlock()
	st.done.Wait()
}

// reevaluateAPIFloodMode counts the owners among this node's sandboxes
// (two are enough to decide) and applies the shared-node rule.
func (s *Service) reevaluateAPIFloodMode(ctx context.Context) {
	if s.store == nil {
		return
	}
	owners, err := s.store.CountDistinctSandboxOwners(ctx, 2)
	if err != nil {
		// Keep the current mode; the ticker retries. Failing toward budget
		// would be safe too, but flapping the mode on a transient error
		// would write a chain record each way.
		if s.logger != nil {
			s.logger.Warn("api audit flood mode: count owners failed", "error", err)
		}
		return
	}
	s.applyAPIFloodMode(ctx, effectiveAPIFloodMode(s.apiFlood.configured, owners), owners)
}

// applyAPIFloodMode switches the writer to mode and records the change in
// the chain. The record waits for the cluster gate like every new kind; a
// change made while it is closed is recorded on the first evaluation after
// it opens.
func (s *Service) applyAPIFloodMode(ctx context.Context, mode apiFloodMode, owners int) {
	st := &s.apiFlood
	if st.control == nil {
		return
	}
	st.control.setMode(mode)
	s.exportAPIFloodMode(mode)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.recorded == mode || !s.auditCallerWritesAllowed() {
		return
	}
	reason := "single_owner"
	if owners > 1 {
		reason = "shared_node"
	}
	actor := s.auditActor()
	ev := SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		NodeID:        actor,
		Ref:           st.configured.String() + ":" + mode.String(),
		Result:        auditlog.APIResultOK,
		Reason:        reason,
		CorrelationID: newSecretAuditCorrelationID(),
		Kind:          auditlog.KindAPIFloodMode,
		Caller:        AuditCallerFromContext(withAuditSubsystem(ctx, auditSubsystemAuditMode)),
	}
	if sink := s.secretAuditSink(); sink != nil {
		sink.Emit(ev)
	}
	st.recorded = mode
	if s.logger != nil {
		s.logger.Info("audit api flood mode changed", "configured", st.configured.String(), "effective", mode.String(), "owners_at_least", owners)
	}
}

// exportAPIFloodMode sets aerolvm_audit_api_flood_mode{key=configured,
// key2=effective} to 1 for the current pair and 0 for the one it replaces.
func (s *Service) exportAPIFloodMode(effective apiFloodMode) {
	st := &s.apiFlood
	configured := st.configured.String()
	pair := configured + "/" + effective.String()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.exported == pair {
		return
	}
	inner, ok := auditAPIFloodModeGauge.Get(configured).(*expvar.Map)
	if !ok {
		inner = new(expvar.Map)
		auditAPIFloodModeGauge.Set(configured, inner)
	}
	for _, m := range []apiFloodMode{apiFloodBudget, apiFloodCoalesce, apiFloodBoth} {
		v := new(expvar.Int)
		if m == effective {
			v.Set(1)
		}
		inner.Set(m.String(), v)
	}
	st.exported = pair
}
