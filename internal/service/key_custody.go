package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
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
		Calls:       recordKeyStoreCall,
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

// The answers for a PKCS#11 slot that is not hardware (SoftHSM2): the key
// sits in a file on this host, so the report does not claim an HSM (§2).
const (
	CustodyWrappedSoftwareToken = "customer key store (wrapped, software token)"
	CustodyPKCS11SoftwareToken  = "pkcs11 (software token)"
)

// CustodyRow is one key class and where it lives.
type CustodyRow struct {
	Class   string
	Custody string
	// InScope is false for keys the plan does not move to the key store;
	// they are listed so the report never overstates (§9).
	InScope bool
}

// CustodyFacts are what config cannot say: only the running PKCS#11 token
// knows whether its slot is hardware.
type CustodyFacts struct {
	SoftwareToken bool
}

// CustodyReport is where each key class lives on this node, from config and
// facts: no key-store call, no database (§9).
func CustodyReport(cfg config.Config, facts CustodyFacts) []CustodyRow {
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
	if facts.SoftwareToken && deks == secrets.ProviderPKCS11 {
		deks = CustodyPKCS11SoftwareToken
		if server == CustodyWrappedKeyStore {
			server = CustodyWrappedSoftwareToken
		}
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
func PublishKeyCustody(cfg config.Config, facts CustodyFacts) {
	keyCustodyGauge.Init()
	enterprise := strconv.FormatBool(cfg.EnterpriseMode)
	for _, row := range CustodyReport(cfg, facts) {
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

// Revocation (§10, CEO-E2, eng D2, D12, D18, D21, D4). With wrapped custody
// the node unwraps its server-key file again every
// SB_SECRET_PROVIDER_RECHECK_INTERVAL. After SB_SECRET_PROVIDER_REVOKE_AFTER
// consecutive revoked results it stops processing the customer's data; the
// first good re-check after that brings it back.

// Secret-audit kinds of a revoke and a recovery: new Kind values, no new
// field (§8).
const (
	KindKeyRevoked   = "key_revoked"
	KindKeyRecovered = "key_recovered"
)

// Re-check results, the key of aerolvm_key_recheck_total.
const (
	recheckOK          = "ok"
	recheckRevoked     = "revoked"
	recheckRetired     = "retired"
	recheckDenied      = "denied"
	recheckThrottled   = "throttled"
	recheckUnavailable = "unavailable"
	recheckMismatch    = "mismatch"
	recheckError       = "error"
)

// keyRecheckTimeout bounds one re-check, so a hung key store (a PKCS#11
// helper in a stuck vendor call) cannot stall the loop (eng D25).
const keyRecheckTimeout = 30 * time.Second

// egressGatewayUnit is restarted when the gateway is too old to know
// clear_inspect_ca: it comes back without the CA, which lives in memory
// only (eng D4).
const egressGatewayUnit = "aerolvm-egress-gateway.service"

var (
	keyRevokedGauge = expvar.NewInt("aerolvm_key_revoked")
	keyRecheckTotal = expvar.NewMap("aerolvm_key_recheck_total")
)

// keyCustodyState is the server key's lifecycle on this node.
type keyCustodyState struct {
	revoked atomic.Bool
	mu      sync.Mutex
	streak  int
	// stop is closed when the key is revoked; streams opened before end
	// with it.
	stop    chan struct{}
	closers []func() int
	// restartGateway replaces the systemctl restart in tests.
	restartGateway func(context.Context) error
}

// KeyRevoked reports whether the customer's key store revoked the server
// key and this node stopped processing their data.
func (s *Service) KeyRevoked() bool { return s != nil && s.keyCustody.revoked.Load() }

// OnKeyRevoked registers a closer run when the key is revoked: the SSH
// gateway's CloseAll. It returns how many sessions it closed.
func (s *Service) OnKeyRevoked(closeAll func() int) {
	s.keyCustody.mu.Lock()
	defer s.keyCustody.mu.Unlock()
	s.keyCustody.closers = append(s.keyCustody.closers, closeAll)
}

// SetEgressGatewayRestarter replaces the restart of a gateway that predates
// clear_inspect_ca (tests).
func (s *Service) SetEgressGatewayRestarter(fn func(context.Context) error) {
	s.keyCustody.mu.Lock()
	defer s.keyCustody.mu.Unlock()
	s.keyCustody.restartGateway = fn
}

func (s *Service) keyStop() chan struct{} {
	s.keyCustody.mu.Lock()
	defer s.keyCustody.mu.Unlock()
	if s.keyCustody.stop == nil {
		s.keyCustody.stop = make(chan struct{})
	}
	return s.keyCustody.stop
}

// RevocableContext is ctx, also cancelled when the key is revoked: a
// toolbox stream opened before the revoke holds a token opened before it,
// so it must end with it (§10). Already revoked, it is cancelled at once.
func (s *Service) RevocableContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	if s == nil {
		return ctx, cancel
	}
	stop := s.keyStop()
	if s.KeyRevoked() {
		cancel()
		return ctx, cancel
	}
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// StartKeyCustody runs the key-custody loop until ctx ends (eng D2: one
// owner of the server key's lifecycle). Every SB_SECRET_PROVIDER_RECHECK_INTERVAL
// it re-reads the server-key ring, so a `sandboxd key rotate` step reaches
// the node without a restart (§13): with wrapped custody as part of the
// re-check that unwraps the file again, with custody=file by reading the
// ring file. While a rotation is in progress the same tick reseals rows
// onto the current key. With any external provider it also runs the
// rewrap sweep now (the API is already serving) and then every hour after
// a random start delay of up to an hour, so a fleet restarted together
// does not sweep in lockstep (eng D19).
func (s *Service) StartKeyCustody(ctx context.Context) {
	if s == nil || s.cipher == nil {
		return
	}
	recheck := s.cfg.CredentialKeyCustody == secrets.CustodyWrapped && s.keyStoreWrapper != nil
	sweep := s.keyStoreWrapper != nil && secrets.IsExternalProvider(s.cfg.SecretProvider)
	interval := s.cfg.SecretProviderRecheckInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if entries, err := s.serverKeyRing(); err == nil {
		// Boot is a re-read too: a step taken while the daemon was down
		// is recorded now.
		s.noteServerKeyRing(entries)
	}
	go func() {
		var sweepC <-chan time.Time
		// ±10% jitter on the re-check, for the same reason.
		nextRecheck := func() <-chan time.Time {
			return time.After(interval + time.Duration((rand.Float64()*0.2-0.1)*float64(interval)))
		}
		recheckC := nextRecheck()
		if sweep {
			s.sweepPass(ctx)
			sweepC = time.After(time.Duration(rand.Int64N(int64(keySweepInterval))))
		}
		s.resealTick(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-recheckC:
				if recheck {
					s.RecheckServerKey(ctx)
				} else {
					s.reloadKeyRingFile()
				}
				s.resealTick(ctx)
				recheckC = nextRecheck()
			case <-sweepC:
				s.sweepPass(ctx)
				sweepC = time.After(keySweepInterval)
			}
		}
	}()
}

// RecheckServerKey runs one re-check and acts on its result, which it
// returns. Only a deliberate signal from the key store counts toward a
// revoke: a 403, an outage or a retired version never does (§10).
func (s *Service) RecheckServerKey(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(secrets.ContextForBackground(secrets.ContextWithBackgroundPurpose(ctx, "recheck")), keyRecheckTimeout)
	defer cancel()
	f, err := secrets.ReadWrappedKeyFile(s.cfg.CredentialKeyWrappedPath)
	if err == nil {
		_, err = secrets.UnwrapServerKey(cctx, s.keyStoreWrapper, f)
	}
	result := recheckResult(err)
	keyRecheckTotal.Add(result, 1)

	s.keyCustody.mu.Lock()
	switch result {
	case recheckRevoked:
		s.keyCustody.streak++
	default:
		s.keyCustody.streak = 0
	}
	streak := s.keyCustody.streak
	s.keyCustody.mu.Unlock()

	switch result {
	case recheckOK:
		recordSecretProviderCanary(true)
		if !s.KeyRevoked() {
			s.applyWrappedRing(cctx, f)
			break
		}
		// Recovery takes the whole ring back, not only the current key
		// (eng D12, §13).
		keys, rerr := secrets.UnwrapRing(cctx, s.keyStoreWrapper, f, nil)
		if rerr == nil {
			rerr = s.recoverKey(ctx, keys)
		}
		if rerr != nil {
			s.logger.Error("key custody: the key unwraps again but the node could not take it back", "error", rerr)
		} else {
			s.noteServerKeyRing(f.Entries())
		}
	case recheckRevoked:
		s.logger.Error("key custody: the key store reports the key revoked", "consecutive", streak, "revoke_after", s.cfg.SecretProviderRevokeAfter, "error", err)
		if !s.KeyRevoked() && streak >= s.cfg.SecretProviderRevokeAfter {
			s.revokeKey(ctx, err)
		}
	case recheckRetired:
		// A stale file, not a revoke: the server key is on a key version the
		// key store no longer decrypts. `sandboxd key rewrap` moves it.
		s.logger.Error("key custody: the server-key file is wrapped under a retired key version; run `sandboxd key rewrap`", "error", err)
	default:
		recordSecretProviderCanary(false)
		s.logger.Warn("key custody: re-check failed; not a revoke", "result", result, "error", err)
	}
	return result
}

func recheckResult(err error) string {
	switch {
	case err == nil:
		return recheckOK
	case errors.Is(err, secrets.ErrKeyRevoked):
		return recheckRevoked
	case errors.Is(err, secrets.ErrKeyVersionRetired):
		return recheckRetired
	case errors.Is(err, secrets.ErrProviderDenied):
		return recheckDenied
	case errors.Is(err, secrets.ErrProviderThrottled):
		return recheckThrottled
	case errors.Is(err, secrets.ErrProviderUnavailable):
		return recheckUnavailable
	case errors.Is(err, secrets.ErrServerKeyCheck):
		return recheckMismatch
	default:
		return recheckError
	}
}

// revokeKey is the full stop (CEO-E2R): the server key leaves memory, so
// every seal and open on this node fails with key_revoked; the egress CA
// and injection secrets leave the gateway and inspected connections close;
// SSH sessions and proxied toolbox streams end; health reports degraded.
// Running sandboxes keep running, and their own public routes stay up
// (CEO-E2D).
func (s *Service) revokeKey(ctx context.Context, cause error) {
	s.keyCustody.mu.Lock()
	if s.keyCustody.revoked.Load() {
		s.keyCustody.mu.Unlock()
		return
	}
	s.cipher.Revoke()
	s.keyCustody.revoked.Store(true)
	if s.keyCustody.stop == nil {
		s.keyCustody.stop = make(chan struct{})
	}
	close(s.keyCustody.stop)
	closers := append([]func() int(nil), s.keyCustody.closers...)
	restart := s.keyCustody.restartGateway
	s.keyCustody.mu.Unlock()
	keyRevokedGauge.Set(1)

	sessions := 0
	for _, closeAll := range closers {
		sessions += closeAll()
	}
	gateway := s.clearEgressInspection(ctx, restart)
	reason := fmt.Sprintf("revoked after %d consecutive re-checks; gateway %s; %d ssh sessions closed", s.cfg.SecretProviderRevokeAfter, gateway, sessions)
	s.emitKeyCustodyEvent(KindKeyRevoked, reason)
	s.logger.Error("key custody: KEY REVOKED by the customer's key store; this node stopped processing their data",
		"gateway", gateway, "ssh_sessions_closed", sessions, "error", cause)
}

// clearEgressInspection drops the CA here and in the gateway. A gateway that
// predates clear_inspect_ca is restarted instead; it comes back without the
// CA (memory only) and a revoked node never resends it (eng D4). It says
// what happened, for the audit record.
func (s *Service) clearEgressInspection(ctx context.Context, restart func(context.Context) error) string {
	s.egressCA.Store(nil)
	s.egressCAPushed.Store(false)
	if !s.egressEnabled() {
		return "not used"
	}
	cctx, cancel := context.WithTimeout(ctx, keyRecheckTimeout)
	defer cancel()
	err := s.egressGateway().ClearInspectCA(cctx)
	switch {
	case err == nil:
		return "cleared"
	case egress.IsUnknownOp(err):
		if restart == nil {
			restart = restartEgressGatewayUnit
		}
		if rerr := restart(cctx); rerr != nil {
			s.logger.Error("key custody: could not restart the egress gateway to drop its CA", "error", rerr)
			return "restart failed"
		}
		return "restarted (predates clear_inspect_ca)"
	default:
		// An unreachable gateway either holds no CA (it restarted) or drops
		// it once this node is silent past the bound it sent.
		s.logger.Warn("key custody: egress gateway unreachable while dropping its CA", "error", err)
		return "unreachable"
	}
}

func restartEgressGatewayUnit(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "systemctl", "restart", egressGatewayUnit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v: %s", egressGatewayUnit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// recoverKey brings the node back after the customer restored the key (eng
// D12): the same ring returns to the shared Cipher, the gateway gets its CA
// and the sandboxes' injection secrets again, and health returns to ok.
func (s *Service) recoverKey(ctx context.Context, keys []secrets.RingKey) error {
	if err := s.cipher.RestoreRing(keys); err != nil {
		return err
	}
	s.keyCustody.mu.Lock()
	s.keyCustody.revoked.Store(false)
	s.keyCustody.stop = make(chan struct{})
	s.keyCustody.mu.Unlock()
	keyRevokedGauge.Set(0)
	if s.egressEnabled() {
		s.egressMu.Lock()
		err := s.syncEgressGatewayLocked(ctx)
		s.egressMu.Unlock()
		if err != nil {
			s.logger.Warn("key custody: egress gateway not resynced after recovery; the next sync retries", "error", err)
		}
	}
	s.emitKeyCustodyEvent(KindKeyRecovered, "the key unwraps again and matches")
	s.logger.Warn("key custody: key restored by the customer's key store; this node resumed")
	return nil
}

// emitKeyCustodyEvent writes a key-custody record to the secret audit log,
// durably when the sink can.
func (s *Service) emitKeyCustodyEvent(kind, reason string) {
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	actor := s.auditActor()
	ev := SecretAuditEvent{
		Time: time.Now().UTC(), Actor: actor, NodeID: actor,
		Result: secretAuditResultSuccess, Reason: reason, Kind: kind,
	}
	ensureSecretAuditEventID(&ev)
	if durable, ok := sink.(DurableSecretAuditSink); ok {
		if err := durable.EmitDurable(ev); err != nil {
			s.logger.Error("key custody: audit record not written", "kind", kind, "error", err)
		}
		return
	}
	sink.Emit(ev)
}

// The rewrap sweep (§11, §12, CEO-E4).

// keySweepInterval is the sweep cadence after the boot pass (eng D19, a
// constant); keySweepPage is how many rows one store read pages through.
const (
	keySweepInterval = time.Hour
	keySweepPage     = 200
)

var (
	// keyRowsStale counts this node's rows not on the current key, plus its
	// server-key file. "0 on every member" is when an old version may be
	// retired (§11) or a local → key store switch is complete (§12).
	keyRowsStale = expvar.NewInt("aerolvm_key_rows_stale")
	// keyRowsRetired counts rows on a key version the key store no longer
	// decrypts: opens of those sandboxes fail on this node
	// (SandboxdKeyVersionRetiredInUse).
	keyRowsRetired    = expvar.NewInt("aerolvm_key_rows_retired")
	keyRowsRewrapped  = expvar.NewInt("aerolvm_key_rows_rewrapped_total")
	keyCurrentGauge   = expvar.NewMap("aerolvm_key_current")
	keyDecryptableMap = expvar.NewMap("aerolvm_key_decryptable")
)

// decryptableKeys is a key store that lists the key versions it still opens
// (the PKCS#11 helper: its current label and its decrypt-only labels).
type decryptableKeys interface {
	DecryptableKeyVersions() []string
}

func (s *Service) sweepPass(ctx context.Context) {
	stale, err := s.SweepKeys(ctx)
	if err != nil {
		s.logger.Warn("key custody: rewrap sweep stopped early; the next pass retries", "stale", stale, "error", err)
	}
}

// SweepKeys moves this node's stale rows and its server-key file onto the
// sealing provider's current key and returns how many stay stale. Each node
// sweeps only its own copies, every node reaching the same key store, so
// there is no fan-out. A row is read without a lock, the key store is
// called with no lock held, and only the conditional write takes the
// sandbox's secret lock (compare-and-swap): a reseal, a delete or a newer
// peer copy that lands in between wins and the row is skipped (Section 4).
func (s *Service) SweepKeys(ctx context.Context) (int, error) {
	if s == nil || s.keyStoreWrapper == nil || s.KeyRevoked() || !secrets.IsExternalProvider(s.cfg.SecretProvider) {
		return 0, nil
	}
	bctx := secrets.ContextForBackground(secrets.ContextWithBackgroundPurpose(ctx, "sweep"))
	step := func() (context.Context, context.CancelFunc) { return context.WithTimeout(bctx, keyRecheckTimeout) }
	cctx, cancel := step()
	current, _, err := secrets.CurrentKeyVersion(cctx, s.keyStoreWrapper)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("read the current key version: %w", err)
	}
	s.publishKeyVersions(current)
	provider := secrets.NormalizeProviderName(s.cfg.SecretProvider)
	stale, retired := 0, 0
	after := ""
	for {
		rows, err := s.store.ListClusterSecretsBatch(ctx, after, keySweepPage)
		if err != nil {
			return stale, err
		}
		for _, row := range rows {
			state, cerr := secrets.ClassifyRow(row.SealedPayload, s.cipher, provider, current)
			if cerr != nil || state != secrets.RowStale {
				continue
			}
			stale++
			cctx, cancel := step()
			rewrapped, rerr := secrets.RewrapEnvelope(cctx, row.SealedPayload, s.cipher, s.keyStoreWrapper)
			cancel()
			switch {
			case errors.Is(rerr, secrets.ErrKeyVersionRetired):
				retired++
				continue
			case rerr != nil && secrets.IsKeyStoreError(rerr):
				// The key store is down, throttling or refusing: stop here,
				// the next pass picks up where this one could not.
				keyRowsRetired.Set(int64(retired))
				return stale, rerr
			case rerr != nil:
				s.logger.Warn("key custody: row not rewrapped", "ref", row.Ref, "error", rerr)
				continue
			}
			unlock := lockSecretSandboxOps(row.SandboxID)
			ok, werr := s.store.RewrapClusterSecret(ctx, row.Ref, row.SealGeneration, row.SealedPayload, rewrapped)
			unlock()
			if werr != nil {
				s.logger.Warn("key custody: rewrapped row not stored", "ref", row.Ref, "error", werr)
				continue
			}
			if ok {
				stale--
				keyRowsRewrapped.Add(1)
			}
		}
		if len(rows) < keySweepPage {
			break
		}
		after = rows[len(rows)-1].Ref
	}
	fileStale, ferr := s.rewrapServerKeyFile(bctx, current)
	if ferr != nil {
		s.logger.Warn("key custody: server-key file not rewrapped", "error", ferr)
	}
	stale += fileStale
	keyRowsStale.Set(int64(stale))
	keyRowsRetired.Set(int64(retired))
	return stale, nil
}

// rewrapServerKeyFile moves the wrapped server-key file onto the current
// key, every key of its ring (§13), like `sandboxd key rewrap` does with
// the daemon stopped. It returns 1 while the file stays stale.
func (s *Service) rewrapServerKeyFile(ctx context.Context, current string) (int, error) {
	if s.cfg.CredentialKeyCustody != secrets.CustodyWrapped || current == "" {
		return 0, nil
	}
	path := s.cfg.CredentialKeyWrappedPath
	f, err := secrets.ReadWrappedKeyFile(path)
	if err != nil {
		return 1, err
	}
	if f.StaleRingKeys(current) == 0 {
		return 0, nil
	}
	cctx, cancel := context.WithTimeout(ctx, keyRecheckTimeout)
	defer cancel()
	nf, err := secrets.RewrapRing(cctx, s.keyStoreWrapper, f)
	if err != nil {
		return 1, err
	}
	if err := secrets.ReplaceWrappedKeyFile(path, f, nf); err != nil {
		// ErrKeyFileChanged: `sandboxd key rotate` edited it meanwhile; the
		// next pass rewraps what it wrote.
		return 1, err
	}
	s.logger.Info("key custody: server-key file rewrapped", "from", f.KeyVersion(), "to", nf.KeyVersion())
	return 0, nil
}

// publishKeyVersions sets the info gauges a PKCS#11 label rotation waits on
// (eng D23): aerolvm_key_current{key=backend,key2=version} and
// aerolvm_key_decryptable{key=backend,key2=version}.
func (s *Service) publishKeyVersions(current string) {
	backend := secrets.NormalizeProviderName(s.cfg.SecretProvider)
	setInfo := func(m *expvar.Map, versions []string) {
		inner := new(expvar.Map).Init()
		for _, v := range versions {
			one := new(expvar.Int)
			one.Set(1)
			inner.Set(v, one)
		}
		m.Init()
		m.Set(backend, inner)
	}
	if current != "" {
		setInfo(keyCurrentGauge, []string{current})
	}
	if d, ok := s.pkcs11Helper.(decryptableKeys); ok {
		setInfo(keyDecryptableMap, d.DecryptableKeyVersions())
	} else if current != "" {
		setInfo(keyDecryptableMap, []string{current})
	}
}
