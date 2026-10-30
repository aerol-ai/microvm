package service

import (
	"context"
	"errors"
	"expvar"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Key custody (plans/customer-key-custody.md §3, §9). One key-store client
// per node serves the boot unwrap of the server key, the cluster-secret
// provider and (Phase 4.2) the re-check loop.

// KeyStoreOptions is the provider options every key-store client in sandboxd
// is built from: the daemon at boot, the service, and `sandboxd key`.
func KeyStoreOptions(cfg config.Config, nodeID string, pkcs11 secrets.DataKeyWrapper) secrets.ProviderOptions {
	vault := cfg.SecretVaultOptions()
	vault.NodeID = nodeID
	return secrets.ProviderOptions{
		Name:        secrets.NormalizeProviderName(cfg.SecretProvider),
		AWSKMSKeyID: cfg.SecretAWSkmsKeyID,
		Vault:       vault,
		PKCS11:      pkcs11,
		MaxInFlight: cfg.SecretProviderMaxInFlight,
		Observer:    recordKeyStoreLimiterWait,
	}
}

// KeyStoreRef names the key the provider wraps with, for the wrapped file
// and the custody report.
func KeyStoreRef(cfg config.Config) string {
	switch secrets.NormalizeProviderName(cfg.SecretProvider) {
	case secrets.ProviderAWSKMS:
		return cfg.SecretAWSkmsKeyID
	case secrets.ProviderVault:
		return strings.Trim(cfg.SecretVaultMount, "/") + "/" + cfg.SecretVaultKeyName
	case secrets.ProviderPKCS11:
		return cfg.SecretPKCS11TokenLabel + "/" + cfg.SecretPKCS11KeyLabel
	default:
		return ""
	}
}

// SetKeyStoreWrapper hands the service the key-store client the daemon built
// before the server key was opened, so one client serves every use.
func (s *Service) SetKeyStoreWrapper(w secrets.DataKeyWrapper) {
	if s != nil {
		s.keyStoreWrapper = w
	}
}

// Custody report answers (§9).
const (
	CustodyWrappedKeyStore = "customer key store (wrapped)"
	CustodyPlaintextFile   = "plaintext file"
	CustodyEnvVar          = "env var"
	CustodyLocalServerKey  = "local (server key)"
	CustodyNotConfigured   = "not configured"
)

// CustodyRow is one key class and where it lives.
type CustodyRow struct {
	Class   string
	Custody string
	// InScope is false for keys the plan does not move to the key store;
	// they are listed so the report never overstates (§9).
	InScope bool
}

// CustodyReport is where each key class lives on this node, from config
// alone: no key-store call, no database (§9).
func CustodyReport(cfg config.Config) []CustodyRow {
	server := CustodyPlaintextFile
	switch {
	case cfg.CredentialKeyCustody == secrets.CustodyWrapped:
		server = CustodyWrappedKeyStore
	case cfg.CredentialEncryptionKey != "":
		server = CustodyEnvVar
	}
	deks := secrets.NormalizeProviderName(cfg.SecretProvider)
	if deks == secrets.ProviderLocal {
		deks = CustodyLocalServerKey
	}
	plainOrNone := func(set bool, how string) string {
		if set {
			return how
		}
		return CustodyNotConfigured
	}
	return []CustodyRow{
		{Class: "server key", Custody: server, InScope: true},
		{Class: "cluster-secret DEKs", Custody: deks, InScope: true},
		{Class: "egress-inspection CA key", Custody: server, InScope: true},
		{Class: "node TLS key", Custody: plainOrNone(cfg.ClusterTLSDir != "", CustodyPlaintextFile)},
		{Class: "gossip key", Custody: plainOrNone(cfg.ClusterGossipSecretKey != "", CustodyEnvVar)},
		{Class: "PAT", Custody: plainOrNone(cfg.PATToken != "", CustodyEnvVar)},
		{Class: "audit-ingest token", Custody: plainOrNone(cfg.AuditIngestToken != "", CustodyEnvVar)},
		{Class: "upstream wrap key", Custody: plainOrNone(cfg.UpstreamWrapKeyPath != "", CustodyPlaintextFile)},
	}
}

// keyCustodyGauge is aerolvm_key_custody{key=class, key2=custody,
// key3=enterprise} = 1, published once at boot; the SandboxdServerKeyPlaintext
// alert fires on an enterprise node whose server key is not wrapped (§9).
var keyCustodyGauge = expvar.NewMap("aerolvm_key_custody")

// PublishKeyCustody publishes the custody report as the gauge.
func PublishKeyCustody(cfg config.Config) {
	keyCustodyGauge.Init()
	enterprise := strconv.FormatBool(cfg.EnterpriseMode)
	for _, row := range CustodyReport(cfg) {
		byCustody := new(expvar.Map).Init()
		byEnterprise := new(expvar.Map).Init()
		one := new(expvar.Int)
		one.Set(1)
		byEnterprise.Set(enterprise, one)
		byCustody.Set(row.Custody, byEnterprise)
		keyCustodyGauge.Set(row.Class, byCustody)
	}
}

// keyCustodyStateName remembers the custody this node last booted with, next
// to the audit log, so a change between boots is recorded (S7).
const keyCustodyStateName = "key-custody.last"

// KindKeyCustodyChanged is the secret-audit record of a custody change
// between boots (S7): a new Kind value, no new field, so older binaries
// re-marshal the record byte for byte (§8).
const KindKeyCustodyChanged = "key_custody_changed"

var keyCustodyMu sync.Mutex

// RecordKeyCustody writes a key_custody_changed record when this boot's
// server-key custody differs from the last boot's, then remembers it. It
// catches a downgrade to a plaintext key, by `sandboxd key unwrap` or by
// hand, that would otherwise go unnoticed. The first boot that records
// custody has nothing to compare with and records nothing.
func (s *Service) RecordKeyCustody() {
	if s == nil {
		return
	}
	keyCustodyMu.Lock()
	defer keyCustodyMu.Unlock()
	dataDir := secretAuditDataDir(s.cfg.DBPath)
	sink := s.secretAuditSink()
	if dataDir == "" || sink == nil {
		return
	}
	now := s.cfg.CredentialKeyCustody
	if now == "" {
		now = secrets.CustodyFile
	}
	path := filepath.Join(dataDir, "audit", keyCustodyStateName)
	raw, err := os.ReadFile(path)
	prev := strings.TrimSpace(string(raw))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.logger.Warn("key custody: last recorded custody unreadable", "path", path, "error", err)
	}
	if prev != "" && prev != now {
		actor := s.auditActor()
		ev := SecretAuditEvent{
			Time: time.Now().UTC(), Actor: actor, NodeID: actor,
			Result: secretAuditResultSuccess, Reason: "from=" + prev + " to=" + now,
			Kind: KindKeyCustodyChanged,
		}
		ensureSecretAuditEventID(&ev)
		if durable, ok := sink.(DurableSecretAuditSink); ok {
			if err := durable.EmitDurable(ev); err != nil {
				// Not remembered, so the next boot records it again.
				s.logger.Warn("key custody: change not recorded; the next boot retries", "error", err)
				return
			}
		} else {
			sink.Emit(ev)
		}
		s.logger.Warn("server-key custody changed since the last boot", "from", prev, "to", now)
	}
	if prev != now {
		werr := os.MkdirAll(filepath.Dir(path), 0o700)
		if werr == nil {
			werr = os.WriteFile(path, []byte(now+"\n"), 0o600)
		}
		if werr != nil {
			s.logger.Warn("key custody: could not remember this boot's custody", "path", path, "error", werr)
		}
	}
}

// bootContext marks boot-time key-store calls for the key store's audit log.
func bootContext(ctx context.Context) context.Context {
	return secrets.ContextWithBackgroundPurpose(ctx, "boot")
}
