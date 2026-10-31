package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// switchableKMS is a key store whose answer the test sets: the fake KMS, or
// a fixed error.
type switchableKMS struct {
	inner *secrets.FakeKMS
	mu    sync.Mutex
	err   error
}

func (k *switchableKMS) set(err error) { k.mu.Lock(); k.err = err; k.mu.Unlock() }

func (k *switchableKMS) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	return k.inner.Wrap(ctx, dek, encCtx)
}

func (k *switchableKMS) Unwrap(ctx context.Context, w []byte, encCtx map[string]string) ([]byte, error) {
	k.mu.Lock()
	err := k.err
	k.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return k.inner.Unwrap(ctx, w, encCtx)
}

// revokeHarness is a node under wrapped custody with an egress gateway, a
// server key that the fake key store wraps, and a counting SSH closer.
func revokeHarness(t *testing.T) (*Service, *switchableKMS, *fakeGateway, []byte, *int) {
	t.Helper()
	svc, gw, _ := newEgressHarness(t)
	fake, err := secrets.NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	kms := &switchableKMS{inner: fake}
	key := bytes.Repeat([]byte{8}, 32)
	cipher, err := secrets.NewCipherFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	svc.cipher = cipher
	svc.store.SetSecretCipher(cipher)
	dir := t.TempDir()
	svc.cfg.CredentialKeyCustody = secrets.CustodyWrapped
	svc.cfg.CredentialKeyWrappedPath = filepath.Join(dir, "credential_encryption.key.wrapped")
	svc.cfg.SecretProviderRevokeAfter = 3
	svc.cfg.SecretProviderRecheckInterval = 5 * time.Minute
	f, err := secrets.WrapServerKey(context.Background(), kms, key, "awskms", "alias/k")
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.WriteWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath, f); err != nil {
		t.Fatal(err)
	}
	svc.SetKeyStoreWrapper(kms)
	closed := new(int)
	svc.OnKeyRevoked(func() int { *closed++; return 2 })
	return svc, kms, gw, key, closed
}

// startKeyCustody starts svc's custody loops for one test and, when the
// test ends, stops them and waits: the loops publish process-wide gauges
// that later tests read, and a loop left running resets them under those
// tests (the reseal gauge flaked under -race that way).
func startKeyCustody(t *testing.T, svc *Service, ctx context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(func() {
		cancel()
		svc.keyCustody.loops.Wait()
	})
	svc.StartKeyCustody(ctx)
}

func custodyRecords(svc *Service, kind string) []SecretAuditEvent {
	sink, ok := svc.secretAuditSink().(*memSecretAuditSink)
	if !ok {
		return nil
	}
	var out []SecretAuditEvent
	for _, ev := range sink.Events() {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// §10: only N consecutive revoked results stop the node; a 403, an outage, a
// retired version or a good result in between never do.
func TestRecheckOnlyDeliberateSignalsRevoke(t *testing.T) {
	svc, kms, _, _, _ := revokeHarness(t)
	svc.secretAudit = &memSecretAuditSink{}
	ctx := context.Background()
	if got := svc.RecheckServerKey(ctx); got != recheckOK || svc.KeyRevoked() {
		t.Fatalf("healthy = %s", got)
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: 403", secrets.ErrProviderDenied), recheckDenied},
		{secrets.ErrProviderThrottled, recheckThrottled},
		{secrets.ErrProviderUnavailable, recheckUnavailable},
		{secrets.ErrKeyVersionRetired, recheckRetired},
		{errors.New("boom"), recheckError},
	} {
		kms.set(tc.err)
		for i := 0; i < 5; i++ {
			if got := svc.RecheckServerKey(ctx); got != tc.want {
				t.Fatalf("%v = %s, want %s", tc.err, got, tc.want)
			}
		}
		if svc.KeyRevoked() {
			t.Fatalf("%v revoked the node", tc.err)
		}
	}
	// Two revoked results, then an outage, resets the count.
	kms.set(secrets.ErrKeyRevoked)
	svc.RecheckServerKey(ctx)
	svc.RecheckServerKey(ctx)
	kms.set(secrets.ErrProviderUnavailable)
	svc.RecheckServerKey(ctx)
	kms.set(secrets.ErrKeyRevoked)
	svc.RecheckServerKey(ctx)
	svc.RecheckServerKey(ctx)
	if svc.KeyRevoked() {
		t.Fatal("revoked before N consecutive results")
	}
	svc.RecheckServerKey(ctx)
	if !svc.KeyRevoked() {
		t.Fatal("N consecutive revoked results did not stop the node")
	}
}

// The full stop and the way back (CEO-E2R, eng D12, D21).
func TestRevokeFullStopAndRecovery(t *testing.T) {
	svc, kms, gw, key, closed := revokeHarness(t)
	svc.secretAudit = &memSecretAuditSink{}
	ctx := context.Background()
	sealed, err := svc.cipher.Encrypt([]byte("toolbox token"))
	if err != nil {
		t.Fatal(err)
	}
	streamCtx, stopStream := svc.RevocableContext(ctx)
	defer stopStream()
	sb := &models.Sandbox{ID: "sb", Env: map[string]string{"TOKEN": "s3cret"}, NetworkEgressRules: []models.EgressRule{
		{Host: "api.example.org", Inspect: true, Inject: &models.EgressInject{Header: "Authorization", SecretRef: "env:TOKEN"}},
	}}
	if got := svc.egressSecrets(ctx, sb); got["TOKEN"] != "s3cret" {
		t.Fatalf("secrets before revoke = %v", got)
	}

	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(ctx)
	}
	if !svc.KeyRevoked() || keyRevokedGauge.Value() != 1 {
		t.Fatal("not revoked")
	}
	if _, err := svc.cipher.Decrypt(sealed); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("open after revoke = %v", err)
	}
	select {
	case <-streamCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a stream opened before the revoke kept running")
	}
	late, stopLate := svc.RevocableContext(ctx)
	defer stopLate()
	if late.Err() == nil {
		t.Fatal("a stream opened after the revoke started")
	}
	if *closed != 1 || gw.cleared != 1 {
		t.Fatalf("ssh closers %d, gateway clears %d", *closed, gw.cleared)
	}
	if got := svc.egressSecrets(ctx, sb); got != nil {
		t.Fatalf("secrets sent while revoked = %v", got)
	}
	if err := svc.resyncEgressCA(ctx); err != nil {
		t.Fatal(err)
	}
	if recs := custodyRecords(svc, KindKeyRevoked); len(recs) != 1 {
		t.Fatalf("key_revoked records = %d", len(recs))
	}
	// Still revoked: more revoked results change nothing.
	svc.RecheckServerKey(ctx)
	if *closed != 1 || len(custodyRecords(svc, KindKeyRevoked)) != 1 {
		t.Fatal("a second revoke ran")
	}

	kms.set(nil)
	if got := svc.RecheckServerKey(ctx); got != recheckOK {
		t.Fatalf("recovery re-check = %s", got)
	}
	if svc.KeyRevoked() || keyRevokedGauge.Value() != 0 {
		t.Fatal("not recovered")
	}
	if got, err := svc.cipher.Decrypt(sealed); err != nil || string(got) != "toolbox token" {
		t.Fatalf("open after recovery = %q %v", got, err)
	}
	if recs := custodyRecords(svc, KindKeyRecovered); len(recs) != 1 {
		t.Fatalf("key_recovered records = %d", len(recs))
	}
	if got := svc.egressSecrets(ctx, sb); got["TOKEN"] != "s3cret" {
		t.Fatalf("secrets after recovery = %v", got)
	}
	// A later revoke needs N results again.
	kms.set(secrets.ErrKeyRevoked)
	svc.RecheckServerKey(ctx)
	if svc.KeyRevoked() {
		t.Fatal("the streak survived recovery")
	}
	_ = key
}

// A gateway Sync while revoked (the one a gateway restart triggers) carries
// the sandbox but not its injection secrets, and sends no CA (eng D4, D21);
// the recovery re-check sends both again and health returns to ok (eng D12).
func TestRevokedGatewaySyncAndRecovery(t *testing.T) {
	svc, kms, gw, _, _ := revokeHarness(t)
	tempDataDir(t, svc)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"TOKEN": "s3cret"}, NetworkAllowOut: []string{"api.example.org"},
		NetworkEgressRules: []models.EgressRule{{Host: "api.example.org", Inspect: true, Inject: &models.EgressInject{Header: "Authorization", SecretRef: "env:TOKEN"}}}})
	if err != nil {
		t.Fatal(err)
	}
	synced := func() (egress.Spec, int) {
		t.Helper()
		if err := svc.ResyncEgressGateway(ctx); err != nil {
			t.Fatalf("resync: %v", err)
		}
		gw.mu.Lock()
		defer gw.mu.Unlock()
		for _, spec := range gw.synced[len(gw.synced)-1] {
			if spec.ID == resp.ID {
				return spec, len(gw.inspectCA)
			}
		}
		t.Fatalf("the sync left out %s", resp.ID)
		return egress.Spec{}, 0
	}
	if spec, cas := synced(); spec.Secrets["TOKEN"] != "s3cret" || cas == 0 {
		t.Fatalf("before the revoke: secrets %v, CA pushes %d", spec.Secrets, cas)
	}

	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(ctx)
	}
	if !svc.KeyRevoked() {
		t.Fatal("not revoked")
	}
	_, before := synced()
	spec, after := synced()
	if spec.Secrets != nil {
		t.Fatalf("a sync while revoked sent secrets %v", spec.Secrets)
	}
	if after != before {
		t.Fatalf("a sync while revoked sent the CA (%d -> %d pushes)", before, after)
	}

	kms.set(nil)
	if got := svc.RecheckServerKey(ctx); got != recheckOK {
		t.Fatalf("recovery re-check = %s", got)
	}
	gw.mu.Lock()
	recovered, cas := gw.synced[len(gw.synced)-1], len(gw.inspectCA)
	gw.mu.Unlock()
	if cas <= after {
		t.Fatal("recovery did not send the CA again")
	}
	sent := false
	for _, s := range recovered {
		sent = sent || (s.ID == resp.ID && s.Secrets["TOKEN"] == "s3cret")
	}
	if !sent {
		t.Fatal("recovery did not send the injection secret again")
	}
	if h, err := svc.Health(ctx); err != nil || h.Status != "ok" || h.KeyCustody != "" {
		t.Fatalf("health after recovery = %+v %v", h, err)
	}
}

// An older gateway answers clear_inspect_ca with "unknown op": sandboxd
// restarts it instead, and it comes back without the CA (eng D4).
func TestRevokeRestartsAnOldGateway(t *testing.T) {
	svc, kms, gw, _, _ := revokeHarness(t)
	gw.clearErr = errors.New(`unknown op "clear_inspect_ca"`)
	restarts := 0
	svc.SetEgressGatewayRestarter(func(context.Context) error { restarts++; return nil })
	tempDataDir(t, svc)
	if _, err := svc.ensureEgressCA(); err != nil {
		t.Fatal(err)
	}
	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(context.Background())
	}
	if restarts != 1 {
		t.Fatalf("restarts = %d", restarts)
	}
	// The restarted gateway reconnects: sandboxd sends it no CA.
	if err := svc.ResyncEgressGateway(context.Background()); err != nil || len(gw.inspectCA) != 0 {
		t.Fatalf("resync after the restart = %v, CA pushes %d", err, len(gw.inspectCA))
	}
	if got := svc.clearEgressInspection(context.Background(), func(context.Context) error { return errors.New("no systemd") }); got != "restart failed" {
		t.Fatalf("failed restart = %q", got)
	}
	gw.clearErr = errors.New("connection refused")
	if got := svc.clearEgressInspection(context.Background(), nil); got != "unreachable" {
		t.Fatalf("unreachable gateway = %q", got)
	}
	svc.cfg.EgressFQDNEnabled = false
	if got := svc.clearEgressInspection(context.Background(), nil); got != "not used" {
		t.Fatalf("no egress = %q", got)
	}
}

// heldCAGateway holds SetInspectCA until released and tracks whether the
// gateway ends up holding the CA, in the order set and clear arrive.
type heldCAGateway struct {
	*fakeGateway
	entered, release chan struct{}
	once             sync.Once
	holds            bool
}

func (g *heldCAGateway) SetInspectCA(context.Context, egress.InspectCA) error {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	g.mu.Lock()
	defer g.mu.Unlock()
	g.holds = true
	return nil
}

func (g *heldCAGateway) ClearInspectCA(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.holds = false
	g.cleared++
	return nil
}

// TestInFlightCAPushLandsBeforeTheRevokeClear: a CA push in flight when
// the key is revoked must not reach the gateway after the revoke's clear,
// and no push starts once the key is revoked (eng D4).
func TestInFlightCAPushLandsBeforeTheRevokeClear(t *testing.T) {
	svc, _, gw, _, _ := revokeHarness(t)
	tempDataDir(t, svc)
	ctx := context.Background()
	ca, err := svc.ensureEgressCA()
	if err != nil {
		t.Fatal(err)
	}
	g := &heldCAGateway{fakeGateway: gw, entered: make(chan struct{}), release: make(chan struct{})}
	svc.SetEgressGateway(g, nil)
	pushed := make(chan error, 1)
	go func() { pushed <- svc.pushEgressCA(ctx, ca) }()
	<-g.entered
	revoked := make(chan struct{})
	go func() { svc.revokeKey(ctx, secrets.ErrKeyRevoked); close(revoked) }()
	select {
	case <-revoked:
		t.Fatal("the revoke's clear did not wait for the push in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(g.release)
	<-revoked
	if err := <-pushed; err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	holds := g.holds
	g.mu.Unlock()
	if holds {
		t.Fatal("the gateway holds the CA after the revoke")
	}
	if err := svc.pushEgressCA(ctx, ca); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("a push after the revoke = %v", err)
	}
	if err := svc.resyncEgressCA(ctx); err != nil || svc.egressCA.Load() != nil {
		t.Fatalf("a resync after the revoke = %v, CA in memory %v", err, svc.egressCA.Load() != nil)
	}
}

// TestOwedGatewayClearIsRetried: a revoke whose clear never reached the
// gateway sends it again on each re-check and on a gateway reconnect,
// until it lands. A revoked node that keeps talking to the gateway is never
// silent long enough for the gateway's own bound to drop the CA.
func TestOwedGatewayClearIsRetried(t *testing.T) {
	svc, kms, gw, _, _ := revokeHarness(t)
	tempDataDir(t, svc)
	ctx := context.Background()
	if _, err := svc.ensureEgressCA(); err != nil {
		t.Fatal(err)
	}
	clears := func() int {
		gw.mu.Lock()
		defer gw.mu.Unlock()
		return gw.cleared
	}
	gw.mu.Lock()
	gw.clearErr = errors.New("connection refused")
	gw.mu.Unlock()
	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(ctx)
	}
	if !svc.KeyRevoked() || clears() != 1 {
		t.Fatalf("revoked %v, clears %d", svc.KeyRevoked(), clears())
	}
	svc.RecheckServerKey(ctx)
	if clears() != 2 {
		t.Fatalf("the next re-check did not send the clear again: %d", clears())
	}
	gw.mu.Lock()
	gw.clearErr = nil
	gw.mu.Unlock()
	if err := svc.ResyncEgressGateway(ctx); err != nil || clears() != 3 {
		t.Fatalf("a reconnect = %v, clears %d", err, clears())
	}
	svc.RecheckServerKey(ctx)
	if err := svc.ResyncEgressGateway(ctx); err != nil || clears() != 3 {
		t.Fatalf("a clear that landed was sent again: %v, clears %d", err, clears())
	}
}

// TestVaultReplyTextNeverReachesLogs: a key-store reply can echo request
// content (a plugin, a proxy in front of Vault), and the re-check logs its
// error, so nothing of the reply's text may reach the log.
func TestVaultReplyTextNeverReachesLogs(t *testing.T) {
	const marker = "SENSITIVE_PROVIDER_BODY_MARKER"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"errors":[%q]}`, marker)
	}))
	t.Cleanup(srv.Close)
	v, err := secrets.NewVault(secrets.VaultOptions{Addr: srv.URL, KeyName: "k"})
	if err != nil {
		t.Fatal(err)
	}
	svc, _, _, _, _ := revokeHarness(t)
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	svc.SetKeyStoreWrapper(v)
	f, err := secrets.ReadWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath)
	if err != nil {
		t.Fatal(err)
	}
	f.Wrapped = []byte("vault:v1:fixture")
	if err := secrets.WriteWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath, f); err != nil {
		t.Fatal(err)
	}
	if got := svc.RecheckServerKey(context.Background()); got != recheckDenied {
		t.Fatalf("re-check = %s, want %s", got, recheckDenied)
	}
	if strings.Contains(logs.String(), marker) || !strings.Contains(logs.String(), "403") {
		t.Fatalf("log = %s, want the status and none of the reply", logs.String())
	}
}

// The file swapped for another key: it unwraps and matches its own check,
// but the node only takes back the key it was built with.
func TestRecoveryRefusesADifferentKey(t *testing.T) {
	svc, kms, _, _, _ := revokeHarness(t)
	ctx := context.Background()
	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(ctx)
	}
	other, err := secrets.WrapServerKey(ctx, kms.inner, bytes.Repeat([]byte{1}, 32), "awskms", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.WriteWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath, other); err != nil {
		t.Fatal(err)
	}
	kms.set(nil)
	svc.RecheckServerKey(ctx)
	if !svc.KeyRevoked() {
		t.Fatal("recovered onto a different key")
	}
	// A missing or edited file reads as an error or a mismatch, never a revoke.
	if got := recheckResult(secrets.ErrServerKeyCheck); got != recheckMismatch {
		t.Fatal(got)
	}
}

func TestStartKeyCustody(t *testing.T) {
	svc, _, _, _, _ := revokeHarness(t)
	svc.cfg.SecretProviderRecheckInterval = time.Millisecond
	count := func() string {
		if v := keyRecheckTotal.Get(recheckOK); v != nil {
			return v.String()
		}
		return "0"
	}
	before := count()
	ctx, cancel := context.WithCancel(context.Background())
	startKeyCustody(t, svc, ctx)
	deadline := time.Now().Add(2 * time.Second)
	for count() == before {
		if time.Now().After(deadline) {
			t.Fatal("the loop never re-checked")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	// File custody: no loop at all.
	svc.cfg.CredentialKeyCustody = secrets.CustodyFile
	startKeyCustody(t, svc, context.Background())
	(*Service)(nil).StartKeyCustody(context.Background())
	if (*Service)(nil).KeyRevoked() {
		t.Fatal("nil service revoked")
	}
	nilCtx, nilCancel := (*Service)(nil).RevocableContext(context.Background())
	nilCancel()
	<-nilCtx.Done()
}

// Health reports degraded with key_custody "revoked" (§10).
func TestHealthReportsRevokedKey(t *testing.T) {
	svc, kms, _, _, _ := revokeHarness(t)
	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(context.Background())
	}
	h, err := svc.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "degraded" || h.KeyCustody != "revoked" {
		t.Fatalf("health = %+v", h)
	}
	kms.set(nil)
	svc.RecheckServerKey(context.Background())
	if h, _ := svc.Health(context.Background()); h.KeyCustody != "" {
		t.Fatalf("health after recovery = %+v", h)
	}
}

func TestSealedOpenError(t *testing.T) {
	if err := sealedOpenError("decrypt env", fmt.Errorf("x: %w", secrets.ErrKeyRevoked)); !errors.Is(err, secrets.ErrKeyRevoked) || errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("revoked = %v", err)
	}
	if err := sealedOpenError("decrypt env", errors.New("bad tag")); !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("tamper = %v", err)
	}
}
