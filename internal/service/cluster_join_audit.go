package service

import (
	"context"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// auditKindClusterJoin is the audit record for one call on the join port
// (plans/kubectl-style-cluster-ops.md §4 "Limits", §8): cluster-info, join
// or preflight, success or failure. Like failover_refused it uses only
// fields every build already hashes, so an older reader verifies it.
const auditKindClusterJoin = "cluster_join"

// auditSubsystemJoin is the system caller of join records: the join port
// has no API principal, only a token id.
const auditSubsystemJoin = "join"

// RecordClusterJoin writes the record of one join call
// (cluster.JoinAuditRecorder). The join listener calls it on its request
// goroutine; Emit queues, so it never waits on the disk. The token's secret
// never reaches it, only the public id.
func (s *Service) RecordClusterJoin(ev cluster.JoinAuditEvent) {
	if s == nil {
		return
	}
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	actor := s.auditActor()
	result := secretAuditResultFailure
	if ev.Result == secretAuditResultSuccess {
		result = secretAuditResultSuccess
	}
	fields := []string{"route=" + ev.Route, "source=" + ev.Source}
	for _, kv := range [][2]string{{"token", ev.TokenID}, {"node", ev.NodeID}, {"role", ev.Role}} {
		if strings.TrimSpace(kv[1]) != "" {
			fields = append(fields, kv[0]+"="+strings.TrimSpace(kv[1]))
		}
	}
	rec := SecretAuditEvent{
		Time:        time.Now().UTC(),
		Actor:       actor,
		NodeID:      actor,
		Result:      result,
		Reason:      ev.Reason,
		Kind:        auditKindClusterJoin,
		Destination: strings.Join(fields, " "),
	}
	if s.auditCallerWritesAllowed() {
		rec.Caller = AuditCallerFromContext(controlplane.ContextWithSystemCaller(context.Background(), auditSubsystemJoin))
	}
	ensureSecretAuditEventID(&rec)
	sink.Emit(rec)
}
