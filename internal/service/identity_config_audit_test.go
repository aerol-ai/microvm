package service

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

const identityFileV1 = `version: 1
issuers:
  - {name: okta, url: "https://acme.okta.com", audiences: [cli]}
bindings:
  - {issuer: okta, group: platform-admins, role: admin}
  - {issuer: okta, group: payments-eng, role: runner, team: payments}
`

func identitySummary(t *testing.T, doc string) identity.Summary {
	t.Helper()
	c, err := identity.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return c.Summary()
}

func identityConfigService(t *testing.T, dataDir string) (*Service, *memSecretAuditSink) {
	t.Helper()
	audit := &memSecretAuditSink{}
	return &Service{
		cfg:         config.Config{DBPath: filepath.Join(dataDir, "sandboxd.db")},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster:     cluster.NewNoop("node-a", "", ""),
		secretAudit: audit,
	}, audit
}

func identityConfigRecords(sink *memSecretAuditSink) []SecretAuditEvent {
	var out []SecretAuditEvent
	for _, ev := range sink.Events() {
		if ev.Kind == auditlog.KindIdentityConfig {
			out = append(out, ev)
		}
	}
	return out
}

// TestRecordIdentityConfig is D20: the first file is one record listing it
// all; an unchanged reload writes none; a change writes one with the exact
// binding diff; and a reboot with a changed file writes one, diffed against
// what this node last recorded.
func TestRecordIdentityConfig(t *testing.T) {
	dir := t.TempDir()
	svc, audit := identityConfigService(t, dir)
	v1 := identitySummary(t, identityFileV1)

	if !svc.RecordIdentityConfig(v1) {
		t.Fatal("first record not done")
	}
	recs := identityConfigRecords(audit)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	first := recs[0]
	wantCaller := &auditlog.Caller{Kind: "system", ID: "system:identity-file"}
	if !reflect.DeepEqual(first.Caller, wantCaller) || first.Actor != "node-a" || first.NodeID != "node-a" || first.Result != "success" || first.EventID == "" {
		t.Fatalf("record = %+v", first)
	}
	ic := first.IdentityConfig
	if ic == nil || ic.OldHash != "" || ic.NewHash != v1.Hash || !reflect.DeepEqual(ic.BindingsAdded, v1.Bindings) || len(ic.BindingsRemoved) != 0 || len(ic.IssuersAdded) != 1 {
		t.Fatalf("first diff = %+v", ic)
	}

	// Unchanged: nothing.
	if !svc.RecordIdentityConfig(v1) || len(identityConfigRecords(audit)) != 1 {
		t.Fatal("an unchanged file wrote a record")
	}

	// Changed: payments-eng becomes a viewer, and a subject is denied.
	v2doc := `version: 1
issuers:
  - {name: okta, url: "https://acme.okta.com", audiences: [cli]}
bindings:
  - {issuer: okta, group: platform-admins, role: admin}
  - {issuer: okta, group: payments-eng, role: viewer, team: payments}
deny_subjects: ["okta:00u1"]
`
	v2 := identitySummary(t, v2doc)
	if !svc.RecordIdentityConfig(v2) {
		t.Fatal("change not recorded")
	}
	recs = identityConfigRecords(audit)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	ic = recs[1].IdentityConfig
	want := &auditlog.IdentityConfig{
		OldHash:         v1.Hash,
		NewHash:         v2.Hash,
		BindingsAdded:   []string{`okta group="payments-eng" -> viewer/payments`},
		BindingsRemoved: []string{`okta group="payments-eng" -> runner/payments`},
		DenyAdded:       []string{"okta:00u1"},
	}
	if !reflect.DeepEqual(ic, want) {
		t.Fatalf("change diff =\n %+v\nwant\n %+v", ic, want)
	}

	// Reboot (a new Service over the same data dir) with the same file:
	// nothing; with a changed file: one record from v2.
	rebooted, audit2 := identityConfigService(t, dir)
	if !rebooted.RecordIdentityConfig(v2) || len(identityConfigRecords(audit2)) != 0 {
		t.Fatal("a boot with an unchanged file wrote a record")
	}
	if !rebooted.RecordIdentityConfig(v1) {
		t.Fatal("boot change not recorded")
	}
	recs = identityConfigRecords(audit2)
	if len(recs) != 1 || recs[0].IdentityConfig.OldHash != v2.Hash || recs[0].IdentityConfig.NewHash != v1.Hash ||
		!reflect.DeepEqual(recs[0].IdentityConfig.DenyRemoved, []string{"okta:00u1"}) {
		t.Fatalf("boot-with-changed-file record = %+v", recs)
	}
	info, err := os.Stat(rebooted.identityConfigStatePath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", info, err)
	}
}

// TestRecordIdentityConfigGate: identity_config is a new record kind, so it
// rides the §5.8 audit caller gate. A cluster node records nothing (and
// reports "not done") while a member still runs an older release, and
// records once the gate opens.
func TestRecordIdentityConfigGate(t *testing.T) {
	svc, audit := identityConfigService(t, t.TempDir())
	gated := &gateCluster{Noop: cluster.NewNoop("n1", "", "")}
	svc.cfg.EnableCluster = true
	svc.cluster = gated
	v1 := identitySummary(t, identityFileV1)
	if svc.RecordIdentityConfig(v1) || len(identityConfigRecords(audit)) != 0 {
		t.Fatal("recorded while the gate was closed")
	}
	gated.open.Store(true)
	if !svc.RecordIdentityConfig(v1) || len(identityConfigRecords(audit)) != 1 {
		t.Fatal("not recorded once the gate opened")
	}
}

// TestRecordIdentityConfigDurable: with the real file sink the record is
// appended durably, chained, and still verifies with its identity_config
// field covered by the hash.
func TestRecordIdentityConfigDurable(t *testing.T) {
	dir := t.TempDir()
	sink, err := newFileAuditSink(filepath.Join(dir, "audit"), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	svc, _ := identityConfigService(t, dir)
	svc.secretAudit = sink
	if !svc.RecordIdentityConfig(identitySummary(t, identityFileV1)) {
		t.Fatal("durable record not done")
	}
	events := readAuditEvents(t, sink.path)
	if len(events) != 1 || events[0].Kind != auditlog.KindIdentityConfig || events[0].IdentityConfig == nil || events[0].EventHash == "" {
		t.Fatalf("file events = %+v", events)
	}
	v := auditlog.NewChainVerifier()
	if err := v.Add(events[0]); err != nil {
		t.Fatalf("chain: %v", err)
	}
	tampered := events[0]
	tampered.IdentityConfig = &auditlog.IdentityConfig{NewHash: "forged"}
	v = auditlog.NewChainVerifier()
	if err := v.Add(tampered); err == nil {
		t.Fatal("a rewritten identity_config still verified")
	}
}

type failingDurableSink struct{ memSecretAuditSink }

func (f *failingDurableSink) EmitDurable(SecretAuditEvent) error { return errors.New("disk full") }

func TestRecordIdentityConfigEdges(t *testing.T) {
	v1 := identitySummary(t, identityFileV1)
	var nilSvc *Service
	if !nilSvc.RecordIdentityConfig(v1) {
		t.Fatal("nil service has nothing to do")
	}

	svc, audit := identityConfigService(t, t.TempDir())
	if !svc.RecordIdentityConfig(identity.Summary{}) || len(audit.Events()) != 0 {
		t.Fatal("an empty summary records nothing")
	}

	noDir, noDirAudit := identityConfigService(t, t.TempDir())
	noDir.cfg.DBPath = ""
	if !noDir.RecordIdentityConfig(v1) || len(noDirAudit.Events()) != 0 {
		t.Fatal("no data dir: nothing to record against")
	}

	// A durable write that fails is retried later: not done, nothing kept.
	failing, _ := identityConfigService(t, t.TempDir())
	failing.secretAudit = &failingDurableSink{}
	if failing.RecordIdentityConfig(v1) {
		t.Fatal("a failed durable write must report not done")
	}
	if _, err := os.Stat(failing.identityConfigStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed write must not remember the file")
	}

	// An unreadable state file over-reports: the whole file as added.
	corrupt, corruptAudit := identityConfigService(t, t.TempDir())
	path := corrupt.identityConfigStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !corrupt.RecordIdentityConfig(v1) {
		t.Fatal("corrupt state: not done")
	}
	recs := identityConfigRecords(corruptAudit)
	if len(recs) != 1 || recs[0].IdentityConfig.OldHash != "" || len(recs[0].IdentityConfig.BindingsAdded) != 2 {
		t.Fatalf("corrupt state record = %+v", recs)
	}

	// A state path that cannot be written still leaves the record in the
	// chain (the next boot writes it once more).
	blocked, blockedAudit := identityConfigService(t, t.TempDir())
	statePath := blocked.identityConfigStatePath()
	if err := os.MkdirAll(statePath, 0o700); err != nil { // a directory where the file goes
		t.Fatal(err)
	}
	if !blocked.RecordIdentityConfig(v1) || len(identityConfigRecords(blockedAudit)) != 1 {
		t.Fatal("record must be written even when the state cannot be")
	}
	if _, err := readIdentityConfigState(statePath); err == nil {
		t.Fatal("reading a directory as state must fail")
	}
}
