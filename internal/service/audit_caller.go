package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The caller in audit records (plans/identity-and-access.md §5.8). Every
// record a request causes names the request's principal; every record
// background work causes names the daemon subsystem that did it. Emitters
// never take a caller argument: they read it from ctx, so a new emitter
// cannot forget to attribute, and a call path that never passed the auth
// edge cannot claim a request's caller.

// Daemon subsystems that act with no request behind them. They name the
// system:<subsystem> caller of the records that work writes; T5's system
// action records (lifecycle auto-stop and auto-delete, the reconcile reap,
// the orphan delete) use the same names.
const (
	auditSubsystemBootRestore = "boot-restore"
	auditSubsystemReconcile   = "reconcile"
	auditSubsystemLifecycle   = "lifecycle"
	auditSubsystemFailover    = "failover"
	auditSubsystemImageGC     = "image-gc"
	// auditSubsystemWake is a sandbox started by traffic to one of its
	// routes (HTTP or L4 wake), not by an API call.
	auditSubsystemWake = "wake"
	// auditSubsystemEgress is the egress gateway reading a sandbox's
	// environment to inject a credential into its outbound traffic.
	auditSubsystemEgress = "egress"
)

// withAuditSubsystem tags ctx as background work by subsystem. A request's
// caller still wins (AuditCallerFromContext reads Access first), so tagging
// a function an API handler also calls is safe.
func withAuditSubsystem(ctx context.Context, subsystem string) context.Context {
	return controlplane.ContextWithSystemCaller(ctx, subsystem)
}

// AuditCallerFromContext is the caller a record written under ctx names,
// before the rolling-upgrade gate:
//
//   - the request's principal, when the API edge attached an Access: kind
//     and id, the display name when it adds something, the team a
//     team-bound credential acted for, and Via, the edge node a forwarded
//     request came through (from the verified mTLS peer);
//   - except for a call the SSH gateway bridged for a sandbox key holder
//     (the edge attached an auditlog.SSHGatewayCall after checking where it
//     came from): the gateway sends the operator token because that is the
//     credential its loopback hop has, but the operator did nothing, so the
//     caller is sandbox_key:<id>, via the gateway's node;
//   - otherwise the system:<subsystem> principal background work tagged;
//   - otherwise system:daemon, for work reached through an untagged entry
//     point.
//
// Use (*Service).auditCaller to fill a record: it also applies the gate.
func AuditCallerFromContext(ctx context.Context) *auditlog.Caller {
	if ctx != nil {
		if access, ok := controlplane.AccessFromContext(ctx); ok {
			if call, bridged := auditlog.SSHGatewayCallFromContext(ctx); bridged {
				return &auditlog.Caller{Kind: string(controlplane.PrincipalSandboxKey), ID: call.SandboxID, Via: access.Via}
			}
			return callerFromAccess(access)
		}
	}
	p, ok := controlplane.SystemCallerFromContext(ctx)
	if !ok {
		p = controlplane.SystemPrincipal(controlplane.SystemDaemon)
	}
	return &auditlog.Caller{Kind: string(p.Kind), ID: p.ID}
}

// callerFromAccess maps a request's Access onto a record's caller. An Access
// with no principal (only hand-built ones in tests; every authenticator sets
// one) yields no caller rather than a guessed one.
func callerFromAccess(a controlplane.Access) *auditlog.Caller {
	p := a.Principal
	if p.ID == "" {
		return nil
	}
	c := &auditlog.Caller{Kind: string(p.Kind), ID: p.ID, Via: a.Via}
	// Names come from outside (token names, claims, provider identities);
	// the record is evidence, so control characters never reach it.
	if name := controlplane.SanitizeDisplayName(p.Name); name != "" && name != p.ID {
		c.Name = name
	}
	switch p.Kind {
	case controlplane.PrincipalToken, controlplane.PrincipalOIDC:
		// Only team-bound credentials select a team (§5.3); "*" records
		// that a fleet binding acted across teams.
		c.Team = a.Team()
	}
	return c
}

// sandboxKeyCaller is the caller of an SSH session record: the sandbox's
// key, via the edge node when a peer forwarded the request that opened the
// session (the gateway's own calls carry no Access, so no Via).
func sandboxKeyCaller(ctx context.Context, sandboxID string) *auditlog.Caller {
	c := &auditlog.Caller{Kind: string(controlplane.PrincipalSandboxKey), ID: strings.TrimSpace(sandboxID)}
	if ctx != nil {
		if access, ok := controlplane.AccessFromContext(ctx); ok {
			c.Via = access.Via
		}
	}
	return c
}

// auditCaller is the caller to write on a record under ctx, or nil while
// the cluster gate is closed.
func (s *Service) auditCaller(ctx context.Context) *auditlog.Caller {
	if !s.auditCallerWritesAllowed() {
		return nil
	}
	return AuditCallerFromContext(ctx)
}

// auditCallerWritesAllowed is the §5.8 write gate. A single node writes the
// caller at once: no other build reads its log. In cluster mode the field
// is written only once every live member advertises a build that reads it
// (cluster.AuditCallerGate); a client that cannot say, including the Noop a
// cluster-mode service holds before the real client is attached, keeps it
// closed, so the failure mode is "records as before", never "records an
// older peer cannot verify".
func (s *Service) auditCallerWritesAllowed() bool {
	if s == nil {
		return false
	}
	if !s.cfg.EnableCluster {
		return true
	}
	gate, ok := s.Cluster().(cluster.AuditCallerGate)
	return ok && gate.AuditCallerWritesAllowed()
}
