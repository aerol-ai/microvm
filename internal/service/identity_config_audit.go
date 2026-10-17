package service

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// identity_config records (plans/identity-and-access.md §5.5, CEO review
// D20). Who holds which role is decided by the identity file on each node,
// so a change to it is the most sensitive change there is, and it must land
// in the tamper-evident chain: one record per node per change, naming the
// old and new file hash and what changed. The file cannot say who edited it;
// the hashes point at the exact versions, and the operator's config history
// names the author.

// auditSubsystemIdentityFile names the identity_config record's caller:
// system:identity-file.
const auditSubsystemIdentityFile = "identity-file"

// identityConfigStateName is the last recorded identity file's canonical
// lines, kept next to the audit log so a boot with a changed file records
// what changed, not just that something did.
const identityConfigStateName = "identity-config.last.json"

// identityConfigMu serialises recording: the watcher's change hook and the
// retry loop may both call in.
var identityConfigMu sync.Mutex

// RecordIdentityConfig writes one identity_config record when sum's hash
// differs from the last one this node recorded, then remembers sum. It
// reports whether there is nothing left to do: false means "not recorded
// yet, call again later", which happens while the cluster audit gate is
// closed (a member still runs a release that cannot verify the record,
// §5.8) or when the durable write failed. An unchanged file records nothing.
// A file changed twice while the gate was closed yields one record from the
// last recorded file to the current one.
func (s *Service) RecordIdentityConfig(sum identity.Summary) bool {
	if s == nil || sum.Hash == "" {
		return true
	}
	identityConfigMu.Lock()
	defer identityConfigMu.Unlock()
	if !s.auditCallerWritesAllowed() {
		return false
	}
	sink := s.secretAuditSink()
	path := s.identityConfigStatePath()
	if sink == nil || path == "" {
		// No audit log on this node (tests, no data dir): nothing to
		// compare against and nowhere to write.
		return true
	}
	prev, err := readIdentityConfigState(path)
	if err != nil {
		// An unreadable state file means the previous file is unknown: the
		// record then lists every line as added, which over-reports and
		// never hides a change.
		s.logger.Warn("identity_config: last recorded identity file unreadable; recording the whole file", "path", path, "error", err)
		prev = identity.Summary{}
	}
	if prev.Hash == sum.Hash {
		return true
	}
	actor := s.auditActor()
	ev := SecretAuditEvent{
		Time:           time.Now().UTC(),
		Actor:          actor,
		NodeID:         actor,
		Result:         secretAuditResultSuccess,
		Reason:         secretAuditReasonOK,
		Kind:           auditlog.KindIdentityConfig,
		Caller:         AuditCallerFromContext(controlplane.ContextWithSystemCaller(context.Background(), auditSubsystemIdentityFile)),
		IdentityConfig: identity.Diff(prev, sum),
	}
	ensureSecretAuditEventID(&ev)
	if durable, ok := sink.(DurableSecretAuditSink); ok {
		// Rare and important: wait for the bytes to reach disk before
		// remembering the file, so a crash cannot drop the record and also
		// mark it written.
		if err := durable.EmitDurable(ev); err != nil {
			s.logger.Warn("identity_config: record not written; retrying", "error", err)
			return false
		}
	} else {
		sink.Emit(ev)
	}
	if err := writeIdentityConfigState(path, sum); err != nil {
		// The record is in the chain; the next boot writes it once more.
		s.logger.Warn("identity_config: could not remember the recorded identity file", "path", path, "error", err)
	}
	s.logger.Info("identity_config record written", "old_hash", prev.Hash, "new_hash", sum.Hash,
		"bindings_added", len(ev.IdentityConfig.BindingsAdded), "bindings_removed", len(ev.IdentityConfig.BindingsRemoved))
	return true
}

func (s *Service) identityConfigStatePath() string {
	dataDir := secretAuditDataDir(s.cfg.DBPath)
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "audit", identityConfigStateName)
}

func readIdentityConfigState(path string) (identity.Summary, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return identity.Summary{}, nil
	}
	if err != nil {
		return identity.Summary{}, err
	}
	var sum identity.Summary
	if err := json.Unmarshal(raw, &sum); err != nil {
		return identity.Summary{}, err
	}
	return sum, nil
}

func writeIdentityConfigState(path string, sum identity.Summary) error {
	raw, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomicDurable(path, append(raw, '\n'), 0o600)
}
