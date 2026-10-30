package service

import (
	"bytes"
	"expvar"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestKeyStoreOptionsAndRef(t *testing.T) {
	cfg := config.Config{
		SecretProvider: "Vault", SecretAWSkmsKeyID: "alias/k", SecretVaultAddr: "https://v", SecretVaultMount: "/team/transit/",
		SecretVaultKeyName: "kek", SecretProviderMaxInFlight: 5, SecretPKCS11TokenLabel: "tok", SecretPKCS11KeyLabel: "kek-b",
	}
	helper := p11Stub{}
	o := KeyStoreOptions(cfg, "n1", helper)
	if o.Name != "vault" || o.AWSKMSKeyID != "alias/k" || o.Vault.NodeID != "n1" || o.Vault.Addr != "https://v" || o.MaxInFlight != 5 || o.PKCS11 != helper || o.Observer == nil {
		t.Fatalf("options = %+v", o)
	}
	for provider, want := range map[string]string{"awskms": "alias/k", "vault": "team/transit/kek", "pkcs11": "tok/kek-b", "local": ""} {
		cfg.SecretProvider = provider
		if got := KeyStoreRef(cfg); got != want {
			t.Fatalf("KeyStoreRef(%s) = %q, want %q", provider, got, want)
		}
	}
}

// §9: the report never overstates; out-of-scope keys are listed as they are.
func TestCustodyReport(t *testing.T) {
	find := func(rows []CustodyRow, class string) CustodyRow {
		for _, r := range rows {
			if r.Class == class {
				return r
			}
		}
		t.Fatalf("no %q row", class)
		return CustodyRow{}
	}
	wrapped := CustodyReport(config.Config{CredentialKeyCustody: "wrapped", SecretProvider: "pkcs11", PATToken: "p", ClusterTLSDir: "/tls"})
	if r := find(wrapped, "server key"); r.Custody != CustodyWrappedKeyStore || !r.InScope {
		t.Fatalf("server key = %+v", r)
	}
	if find(wrapped, "cluster-secret DEKs").Custody != "pkcs11" || find(wrapped, "egress-inspection CA key").Custody != CustodyWrappedKeyStore {
		t.Fatal("DEKs or CA key")
	}
	if r := find(wrapped, "PAT"); r.Custody != CustodyEnvVar || r.InScope {
		t.Fatalf("PAT = %+v", r)
	}
	if find(wrapped, "node TLS key").Custody != CustodyPlaintextFile || find(wrapped, "gossip key").Custody != CustodyNotConfigured {
		t.Fatal("TLS or gossip key")
	}
	env := CustodyReport(config.Config{CredentialEncryptionKey: "k", AuditIngestToken: "t", UpstreamWrapKeyPath: "/u", ClusterGossipSecretKey: "g"})
	if find(env, "server key").Custody != CustodyEnvVar || find(env, "cluster-secret DEKs").Custody != CustodyLocalServerKey {
		t.Fatal("env key or local DEKs")
	}
	if find(env, "upstream wrap key").Custody != CustodyPlaintextFile || find(env, "audit-ingest token").Custody != CustodyEnvVar {
		t.Fatal("upstream or audit-ingest")
	}
	if find(CustodyReport(config.Config{}), "server key").Custody != CustodyPlaintextFile {
		t.Fatal("default server key")
	}
}

func TestPublishKeyCustody(t *testing.T) {
	PublishKeyCustody(config.Config{CredentialKeyCustody: "wrapped", SecretProvider: "awskms", EnterpriseMode: true})
	byCustody, ok := keyCustodyGauge.Get("server key").(*expvar.Map)
	if !ok {
		t.Fatal("no server key entry")
	}
	byEnterprise, ok := byCustody.Get(CustodyWrappedKeyStore).(*expvar.Map)
	if !ok {
		t.Fatalf("server key custody = %s", byCustody.String())
	}
	if v, ok := byEnterprise.Get("true").(*expvar.Int); !ok || v.Value() != 1 {
		t.Fatalf("enterprise label = %s", byEnterprise.String())
	}
	// Republishing replaces, never accumulates, rows.
	PublishKeyCustody(config.Config{})
	byCustody = keyCustodyGauge.Get("server key").(*expvar.Map)
	if byCustody.Get(CustodyWrappedKeyStore) != nil || byCustody.Get(CustodyPlaintextFile) == nil {
		t.Fatalf("after republish = %s", byCustody.String())
	}
}

// S7: a custody change between boots is recorded once; the first boot and an
// unchanged boot record nothing.
func TestRecordKeyCustody(t *testing.T) {
	dir := t.TempDir()
	audit := &memSecretAuditSink{}
	var logs bytes.Buffer
	svc := &Service{
		cfg:         config.Config{DBPath: filepath.Join(dir, "state.db"), CredentialKeyCustody: "wrapped"},
		logger:      slog.New(slog.NewTextHandler(&logs, nil)),
		cluster:     cluster.NewNoop("node-a", "", ""),
		secretAudit: audit,
	}
	records := func() []SecretAuditEvent {
		var out []SecretAuditEvent
		for _, ev := range audit.Events() {
			if ev.Kind == KindKeyCustodyChanged {
				out = append(out, ev)
			}
		}
		return out
	}
	svc.RecordKeyCustody()
	svc.RecordKeyCustody()
	if n := len(records()); n != 0 {
		t.Fatalf("first and unchanged boots recorded %d", n)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("first boot warned: %s", logs.String())
	}
	svc.cfg.CredentialKeyCustody = ""
	svc.RecordKeyCustody()
	got := records()
	if len(got) != 1 || got[0].Reason != "from=wrapped to=file" || got[0].NodeID == "" {
		t.Fatalf("downgrade records = %+v", got)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit", keyCustodyStateName))
	if string(raw) != "file\n" {
		t.Fatalf("state = %q", raw)
	}
	svc.RecordKeyCustody()
	if len(records()) != 1 {
		t.Fatal("an unchanged boot recorded again")
	}
	// No data dir: nothing to compare, nothing written.
	(&Service{logger: svc.logger}).RecordKeyCustody()
	(*Service)(nil).RecordKeyCustody()
	svc.SetKeyStoreWrapper(p11Stub{})
	if svc.keyStoreWrapper == nil {
		t.Fatal("SetKeyStoreWrapper")
	}
	(*Service)(nil).SetKeyStoreWrapper(nil)
}

// With wrapped custody the daemon unwrapped the server key through the same
// client, so the synthetic canary is skipped and the gauge says ok.
func TestConfigureSecretProviderWrappedCustody(t *testing.T) {
	dir := t.TempDir()
	st := openSealTestStore(t)
	cipher, err := secrets.NewCipher("", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	denied := failingWrapper{err: secrets.ErrProviderDenied}
	svc := New(config.Config{SecretProvider: "awskms", SecretAWSkmsKeyID: "k", CredentialKeyCustody: "wrapped", SecretProviderStrictBoot: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, cipher, nil, nil)
	svc.SetKeyStoreWrapper(denied)
	if err := svc.ConfigureSecretProvider(t.Context()); err != nil {
		t.Fatalf("wrapped custody ran the canary: %v", err)
	}
	if secretProviderCanaryOK.Value() != 1 {
		t.Fatal("canary gauge not ok")
	}
}
