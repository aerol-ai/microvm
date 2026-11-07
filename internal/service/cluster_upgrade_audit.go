package service

import (
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// auditKindClusterUpgrade is the record of one upgrade call
// (plans/kubectl-style-cluster-ops.md §6.3, §8, §10.1): a rollout command
// on the leader, an upload, a leadership hand-off, or one node's step.
// Like cluster_join it uses only fields every build already hashes, so an
// older reader verifies it.
const auditKindClusterUpgrade = "cluster_upgrade"

// RecordClusterUpgrade writes the record of one upgrade call
// (cluster.UpgradeAuditRecorder, and the API's rollout writes). The caller
// is the principal that ran apply, from the committed rollout record for a
// node step and from the request for a command, so every node's log points
// back to the person or token that started the rollout. Emit queues, so it
// never waits on the disk.
func (s *Service) RecordClusterUpgrade(ev cluster.UpgradeAuditEvent) {
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
	fields := []string{"route=" + ev.Route}
	for _, kv := range [][2]string{{"step", ev.Step}, {"rollout", ev.RolloutID}, {"node", ev.NodeID}, {"caller", ev.Caller}} {
		if v := strings.TrimSpace(kv[1]); v != "" {
			fields = append(fields, kv[0]+"="+v)
		}
	}
	rec := SecretAuditEvent{
		Time:        time.Now().UTC(),
		Actor:       actor,
		NodeID:      actor,
		Result:      result,
		Reason:      ev.Reason,
		Kind:        auditKindClusterUpgrade,
		Destination: strings.Join(fields, " "),
	}
	if s.auditCallerWritesAllowed() {
		rec.Caller = upgradeAuditCaller(ev.Caller)
	}
	ensureSecretAuditEventID(&rec)
	sink.Emit(rec)
}

// upgradeAuditCaller turns the "kind:id" the rollout record keeps back
// into a record caller. An empty or unknown caller is the system's.
func upgradeAuditCaller(caller string) *auditlog.Caller {
	kind, id, ok := strings.Cut(strings.TrimSpace(caller), ":")
	if !ok || kind == "" || id == "" {
		return &auditlog.Caller{Kind: "system", ID: "rollout"}
	}
	return &auditlog.Caller{Kind: kind, ID: id}
}
