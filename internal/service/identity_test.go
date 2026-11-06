package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

const testIssuer = "https://api.example.com"

type identityHarness struct {
	svc  *Service
	st   *storepkg.Store
	rt   *recordingRuntime
	sink *memSecretAuditSink

	mu        sync.Mutex
	delivered map[string][]string
	failMu    sync.Mutex
	failPush  error
}

func (h *identityHarness) setFail(err error) {
	h.failMu.Lock()
	h.failPush = err
	h.failMu.Unlock()
}

func (h *identityHarness) fail() error {
	h.failMu.Lock()
	defer h.failMu.Unlock()
	return h.failPush
}

func newIdentityHarness(t *testing.T) *identityHarness {
	t.Helper()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.IdentityIssuerURL = testIssuer
	h := &identityHarness{svc: svc, st: st, rt: rt, sink: &memSecretAuditSink{}, delivered: map[string][]string{}}
	svc.secretAudit = h.sink
	svc.secretAuditOnce.Do(func() {})
	svc.identity.deliver = func(_ context.Context, sb *models.Sandbox, token string) error {
		if err := h.fail(); err != nil {
			return err
		}
		h.mu.Lock()
		h.delivered[sb.ID] = append(h.delivered[sb.ID], token)
		h.mu.Unlock()
		return nil
	}
	return h
}

func (h *identityHarness) tokens(id string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.delivered[id]...)
}

func (h *identityHarness) waitTokens(t *testing.T, id string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := h.tokens(id); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s got %d tokens, want %d", id, len(h.tokens(id)), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *identityHarness) allow(t *testing.T, team, tag, minRole string) {
	t.Helper()
	if _, err := h.svc.PutIdentityRole(adminCtx(), team, tag, models.IdentityRoleRequest{MinRole: minRole}); err != nil {
		t.Fatal(err)
	}
}

func (h *identityHarness) jwks(t *testing.T) []byte {
	t.Helper()
	raw, err := h.svc.IdentityJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIdentityDisabledEverywhere(t *testing.T) {
	h := newIdentityHarness(t)
	h.svc.cfg.IdentityIssuerURL = ""
	ctx := adminCtx()
	if h.svc.IdentityEnabled() || h.svc.IdentityIssuer() != "" {
		t.Fatal("identity reported on")
	}
	checks := map[string]error{}
	_, checks["discovery"] = h.svc.IdentityDiscovery()
	_, checks["jwks"] = h.svc.IdentityJWKS(ctx)
	_, checks["rotate"] = h.svc.RotateIdentityKey(ctx, "")
	_, checks["put"] = h.svc.PutIdentityRole(ctx, "", "deploy", models.IdentityRoleRequest{MinRole: "runner"})
	_, checks["list"] = h.svc.ListIdentityRoles(ctx, "", "", 0)
	checks["delete"] = h.svc.DeleteIdentityRole(ctx, "", "deploy")
	checks["ensure"] = h.svc.EnsureIdentityKeysReady(ctx)
	for name, err := range checks {
		if !errors.Is(err, ErrIdentityDisabled) {
			t.Errorf("%s = %v, want ErrIdentityDisabled", name, err)
		}
	}
	// Section 4: identity on create gives 400 naming the setting.
	_, err := h.svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "deploy"}})
	if !errors.Is(err, ErrIdentityInvalid) || !strings.Contains(err.Error(), "SB_IDENTITY_ISSUER_URL") {
		t.Fatalf("create = %v", err)
	}
	if h.rt.createCalls != 0 {
		t.Fatal("a refused create reached the runtime")
	}
	var nilSvc *Service
	if nilSvc.IdentityEnabled() || nilSvc.IdentityIssuer() != "" {
		t.Fatal("nil service reported identity")
	}
	h.svc.pushIdentityTokenSoon("sb-x", identityPushStart) // a no-op when off
}

// The lazy bootstrap makes exactly one first key however many callers race,
// and a failure leaves the latch unset for the next caller (rule 3).
func TestEnsureIdentityKeysReadyLatch(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := context.Background()
	cipher := h.svc.cipher
	h.svc.cipher = nil
	if err := h.svc.EnsureIdentityKeysReady(ctx); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("no server key = %v", err)
	}
	if h.svc.identity.keysReady.Load() {
		t.Fatal("a failed bootstrap set the latch")
	}
	h.svc.cipher = cipher
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	set, err := h.st.ReadIdentityKeys(ctx)
	if err != nil || set.Generation != 1 || len(set.Keys) != 1 {
		t.Fatalf("after racing bootstraps = gen %d, %d keys, %v", set.Generation, len(set.Keys), err)
	}
	// Point 1: the key is sealed at rest; the stored bytes are not DER.
	if strings.Contains(string(set.Keys[0].SealedPrivate), "\x30\x82") && len(set.Keys[0].SealedPrivate) < 1200 {
		t.Fatal("the stored private key looks unsealed")
	}
	if _, err := cloudidentity.ParsePrivateKey(set.Keys[0].SealedPrivate); err == nil {
		t.Fatal("the stored private key parses without opening the seal")
	}
	if !h.svc.identity.keysReady.Load() {
		t.Fatal("the latch is unset after a bootstrap")
	}
}

// Another node's first key (a lost CAS) is adopted, not overwritten.
func TestEnsureIdentityKeysAdoptsAConcurrentFirstKey(t *testing.T) {
	h := newIdentityHarness(t)
	other := newIdentityHarness(t)
	// Both share other's store: other makes the key while h is deciding.
	h.svc.identity.backend = &racingIdentityBackend{identityBackend: other.st, before: func() {
		if err := other.svc.EnsureIdentityKeysReady(context.Background()); err != nil {
			t.Error(err)
		}
	}}
	h.svc.cipher = other.svc.cipher
	if err := h.svc.EnsureIdentityKeysReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	set, _ := other.st.ReadIdentityKeys(context.Background())
	active, _ := set.Active()
	if set.Generation != 1 || h.svc.identity.signer.Load().signer.KeyID != active.ID {
		t.Fatalf("did not adopt the other node's key: gen %d", set.Generation)
	}
}

// racingIdentityBackend runs before once, right before the first key-set
// write, to make that write lose its CAS.
type racingIdentityBackend struct {
	identityBackend
	once   sync.Once
	before func()
	fail   error
}

func (b *racingIdentityBackend) WriteIdentityKeys(ctx context.Context, expected int64, keys []cloudidentity.KeyRecord) (cloudidentity.KeySet, error) {
	b.once.Do(b.before)
	if b.fail != nil {
		return cloudidentity.KeySet{}, b.fail
	}
	return b.identityBackend.WriteIdentityKeys(ctx, expected, keys)
}

func TestIdentityDocumentsAndSignedToken(t *testing.T) {
	h := newIdentityHarness(t)
	raw, err := h.svc.IdentityDiscovery()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["issuer"] != testIssuer || doc["jwks_uri"] != testIssuer+cloudidentity.JWKSPath {
		t.Fatalf("discovery = %s", raw)
	}
	jwks := h.jwks(t)
	// Point 4: public keys only.
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks = %s %v", jwks, err)
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := set.Keys[0][private]; ok {
			t.Fatalf("JWKS carries private member %q", private)
		}
	}
	if set.Keys[0]["alg"] != "RS256" || set.Keys[0]["use"] != "sig" || set.Keys[0]["kty"] != "RSA" {
		t.Fatalf("jwk = %v", set.Keys[0])
	}
}

func TestRotateIdentityKeyOverlapAndIdempotency(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := adminCtx()
	now := time.Now()
	h.svc.identity.now = func() time.Time { return now }
	if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
		t.Fatal(err)
	}
	first := h.svc.identity.signer.Load().signer.KeyID
	// Bootstrapping and serving the JWKS open no private key; signing does.
	if h.svc.identity.signer.Load().signer.Key != nil {
		t.Fatal("the bootstrap opened the private key")
	}
	signer, err := h.svc.currentIdentitySigner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := signer.signer.Issue(cloudidentity.IssueRequest{Issuer: testIssuer, SandboxID: "sb", RoleTag: "r", Audience: "a", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.svc.RotateIdentityKey(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if out.ActiveKeyID == first || len(out.PublishedKeyID) != 2 || out.PublishedKeyID[1] != first {
		t.Fatalf("rotation = %+v", out)
	}
	// The new key signs at once; the old key's tokens verify for the overlap.
	if signer, _ := h.svc.currentIdentitySigner(ctx); signer.signer.KeyID != out.ActiveKeyID {
		t.Fatalf("signing with %s after rotation", signer.signer.KeyID)
	}
	if _, err := cloudidentity.Verify(old.Raw, h.jwks(t), now.Add(30*time.Minute)); err != nil {
		t.Fatalf("a pre-rotation token: %v", err)
	}
	now = now.Add(2 * time.Hour)
	h.svc.identity.signer.Store(nil)
	if pub := h.svc.identity.signer.Load(); pub != nil {
		t.Fatal("signer not cleared")
	}
	if strings.Contains(string(h.jwks(t)), first) {
		t.Fatal("the retired key is still published after two hours")
	}
	// A retry naming the key that was active is a no-op.
	again, err := h.svc.RotateIdentityKey(ctx, first)
	if err != nil || again.ActiveKeyID != out.ActiveKeyID {
		t.Fatalf("retried rotation = %+v %v", again, err)
	}
	// Past MaxKeys inside the window, a rotation is refused (409).
	for i := 0; ; i++ {
		_, err := h.svc.RotateIdentityKey(ctx, "")
		if errors.Is(err, cloudidentity.ErrTooManyKeys) {
			break
		}
		if err != nil || i > cloudidentity.MaxKeys {
			t.Fatalf("rotation %d = %v", i, err)
		}
	}
}

// A rotation that loses its CAS to a reseal decides again on the new set;
// one that loses to another rotation is that rotation.
func TestRotateIdentityKeyConflicts(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := adminCtx()
	if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
		t.Fatal(err)
	}
	other := &Service{cfg: h.svc.cfg, cipher: h.svc.cipher, store: h.st, logger: h.svc.logger}
	first := h.svc.identity.signer.Load().signer.KeyID
	var rotatedByOther string
	h.svc.identity.backend = &racingIdentityBackend{identityBackend: h.st, before: func() {
		out, err := other.RotateIdentityKey(ctx, "")
		if err != nil {
			t.Error(err)
			return
		}
		rotatedByOther = out.ActiveKeyID
	}}
	out, err := h.svc.RotateIdentityKey(ctx, "")
	if err != nil || out.ActiveKeyID != rotatedByOther || rotatedByOther == first {
		t.Fatalf("rotation racing a rotation = %+v %v (other made %s)", out, err, rotatedByOther)
	}
	h.svc.identity.backend = &racingIdentityBackend{identityBackend: h.st, before: func() {}, fail: errors.New("disk full")}
	if _, err := h.svc.RotateIdentityKey(ctx, ""); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("a failed write = %v", err)
	}
	h.svc.identity.backend = alwaysConflict{h.st}
	if _, err := h.svc.RotateIdentityKey(ctx, ""); !errors.Is(err, ErrIdentityUnavailable) || !strings.Contains(err.Error(), "kept changing") {
		t.Fatalf("endless conflicts = %v", err)
	}
}

type alwaysConflict struct{ identityBackend }

func (alwaysConflict) WriteIdentityKeys(context.Context, int64, []cloudidentity.KeyRecord) (cloudidentity.KeySet, error) {
	return cloudidentity.KeySet{}, ErrIdentityKeysConflict
}

// failingKeyReads fails every key-set read after the first n.
type failingKeyReads struct {
	identityBackend
	n     atomic.Int32
	limit int32
}

func (b *failingKeyReads) ReadIdentityKeys(ctx context.Context) (cloudidentity.KeySet, error) {
	if b.n.Add(1) > b.limit {
		return cloudidentity.KeySet{}, errors.New("server tier unreachable")
	}
	return b.identityBackend.ReadIdentityKeys(ctx)
}

// The signer is re-read every TTL; a failed re-read keeps the last set for
// the stale window, then fails closed.
func TestIdentitySignerRefreshAndStaleness(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := context.Background()
	now := time.Now()
	h.svc.identity.now = func() time.Time { return now }
	if _, err := h.svc.currentIdentitySigner(ctx); err != nil {
		t.Fatal(err)
	}
	loaded := h.svc.identity.signer.Load()
	if s, _ := h.svc.currentIdentitySigner(ctx); s != loaded {
		t.Fatal("a fresh signer was re-read")
	}
	now = now.Add(identitySignerTTL)
	if s, _ := h.svc.currentIdentitySigner(ctx); s == loaded {
		t.Fatal("a stale signer was not re-read")
	}
	h.svc.identity.backend = &failingKeyReads{identityBackend: h.st}
	now = now.Add(identitySignerTTL)
	if s, err := h.svc.currentIdentitySigner(ctx); err != nil || s == nil {
		t.Fatalf("within the stale window = %v", err)
	}
	now = now.Add(identitySignerMaxStale)
	if _, err := h.svc.currentIdentitySigner(ctx); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("past the stale window = %v", err)
	}
	// A set with no active key cannot sign.
	h.svc.identity.backend = h.st
	if _, err := h.st.WriteIdentityKeys(ctx, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.loadIdentitySigner(ctx, false); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("no active key = %v", err)
	}
	// A key sealed under another server key cannot be opened.
	set, _ := h.st.ReadIdentityKeys(ctx)
	rec, err := cloudidentity.NewKeyRecord(mustRSAKey(t), now, newTestCipher(t).EncryptWithAAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.WriteIdentityKeys(ctx, set.Generation, []cloudidentity.KeyRecord{rec}); err != nil {
		t.Fatal(err)
	}
	h.svc.identity.signer.Store(nil)
	// The JWKS needs only the public half, so it is still served...
	if _, err := h.svc.IdentityJWKS(ctx); err != nil {
		t.Fatalf("JWKS with a key this node cannot open = %v", err)
	}
	// ...but signing fails, naming the key and never its bytes.
	if _, err := h.svc.currentIdentitySigner(ctx); !errors.Is(err, ErrIdentityUnavailable) || strings.Contains(err.Error(), string(rec.SealedPrivate)) {
		t.Fatalf("foreign key = %v", err)
	}
	h.svc.cipher = nil
	if _, err := h.svc.openIdentityKey(rec); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("no cipher = %v", err)
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := cloudidentity.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// secretsTestKey is a 32-byte server key, distinct per n.
func secretsTestKey(t *testing.T, n byte) []byte {
	t.Helper()
	return bytes.Repeat([]byte{n}, 32)
}

func TestIdentityRolesAPI(t *testing.T) {
	h := newIdentityHarness(t)
	admin := adminCtx()
	role, err := h.svc.PutIdentityRole(admin, "payments", " deploy ", models.IdentityRoleRequest{MinRole: "runner"})
	if err != nil || role.Tag != "deploy" || role.Team != "payments" || role.MinRole != "runner" {
		t.Fatalf("put = %+v %v", role, err)
	}
	// Idempotent: the same body twice.
	if again, err := h.svc.PutIdentityRole(admin, "payments", "deploy", models.IdentityRoleRequest{MinRole: "runner"}); err != nil || !again.UpdatedAt.Equal(role.UpdatedAt) {
		t.Fatalf("repeat put = %+v %v", again, err)
	}
	h.allow(t, "payments", "build", "admin")
	h.allow(t, "", "ops", "runner") // the operator namespace
	list, err := h.svc.ListIdentityRoles(admin, "payments", "", 1)
	if err != nil || len(list.Roles) != 1 || list.Roles[0].Tag != "build" || list.NextCursor != "build" || list.Roles[0].Team != "payments" {
		t.Fatalf("page 1 = %+v %v", list, err)
	}
	list, _ = h.svc.ListIdentityRoles(admin, "payments", list.NextCursor, 1)
	if len(list.Roles) != 1 || list.Roles[0].Tag != "deploy" {
		t.Fatalf("page 2 = %+v", list)
	}
	if list, _ := h.svc.ListIdentityRoles(admin, "", "", 1000); len(list.Roles) != 1 || list.Roles[0].Tag != "ops" || list.Roles[0].Team != "" {
		t.Fatalf("operator namespace = %+v", list)
	}
	// A team-bound caller sees its own team only (defence in depth: the
	// route is admin only).
	runner := controlplane.ContextWithAccess(context.Background(), paymentsToken())
	if list, err := h.svc.ListIdentityRoles(runner, "", "", 0); err != nil || len(list.Roles) != 2 {
		t.Fatalf("own team = %+v %v", list, err)
	}
	if _, err := h.svc.ListIdentityRoles(runner, "other", "", 0); !errors.Is(err, ErrIdentityRoleDenied) {
		t.Fatalf("another team = %v", err)
	}
	managed := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct-1"}, Role: controlplane.RoleRunner})
	if list, err := h.svc.ListIdentityRoles(managed, "", "", 0); err != nil || len(list.Roles) != 0 {
		t.Fatalf("managed account = %+v %v", list, err)
	}
	if _, err := h.svc.ListIdentityRoles(managed, "payments", "", 0); !errors.Is(err, ErrIdentityRoleDenied) {
		t.Fatalf("managed account naming a team = %v", err)
	}
	for name, err := range map[string]error{
		"bad tag": func() error {
			_, err := h.svc.PutIdentityRole(admin, "payments", "Bad:Tag", models.IdentityRoleRequest{MinRole: "runner"})
			return err
		}(),
		"bad role": func() error {
			_, err := h.svc.PutIdentityRole(admin, "payments", "x", models.IdentityRoleRequest{MinRole: "viewer"})
			return err
		}(),
		"bad team": func() error {
			_, err := h.svc.PutIdentityRole(admin, "Bad Team", "x", models.IdentityRoleRequest{MinRole: "runner"})
			return err
		}(),
		"del tag":   h.svc.DeleteIdentityRole(admin, "payments", "Bad:Tag"),
		"del team":  h.svc.DeleteIdentityRole(admin, "Bad Team", "x"),
		"list team": func() error { _, err := h.svc.ListIdentityRoles(admin, "Bad Team", "", 0); return err }(),
	} {
		if !errors.Is(err, ErrIdentityInvalid) {
			t.Errorf("%s = %v, want ErrIdentityInvalid", name, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := h.svc.DeleteIdentityRole(admin, "payments", "deploy"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	if list, _ := h.svc.ListIdentityRoles(admin, "payments", "", maxIdentityRoleListLimit+10); len(list.Roles) != 1 {
		t.Fatalf("after delete = %+v", list)
	}
	h.svc.identity.backend = noClusterIdentity{}
	if _, err := h.svc.ListIdentityRoles(admin, "payments", "", 0); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("unavailable backend = %v", err)
	}
	if _, err := h.svc.PutIdentityRole(admin, "payments", "x", models.IdentityRoleRequest{MinRole: "runner"}); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("unavailable put = %v", err)
	}
	if err := h.svc.DeleteIdentityRole(admin, "payments", "x"); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("unavailable delete = %v", err)
	}
	if err := identityBackendError(errors.New("plain")); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("plain backend error = %v", err)
	}
}

func TestPrepareCreateIdentity(t *testing.T) {
	h := newIdentityHarness(t)
	h.allow(t, "payments", "deploy", "runner")
	h.allow(t, "payments", "prod", "admin")
	runner := controlplane.ContextWithAccess(context.Background(), paymentsToken())
	const arn = "arn:aws:iam::123456789012:role/deploy"
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		owner   string
		runtime string
		req     models.CreateSandboxRequest
		want    error
		env     map[string]string
	}{
		{name: "no identity", ctx: runner, owner: "team:payments", req: models.CreateSandboxRequest{}},
		{name: "allowed", ctx: runner, owner: "team:payments", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy", AWSRoleARN: arn}},
			env: map[string]string{cloudidentity.EnvTokenFile: cloudidentity.TokenFile, cloudidentity.EnvAWSRoleARN: arn, cloudidentity.EnvAWSTokenFile: cloudidentity.TokenFile}},
		{name: "env already right", ctx: runner, owner: "team:payments", runtime: models.RuntimeGvisor,
			req: models.CreateSandboxRequest{Env: map[string]string{cloudidentity.EnvTokenFile: cloudidentity.TokenFile, "A": "1"}, Identity: &models.IdentityRequest{RoleTag: "deploy"}},
			env: map[string]string{cloudidentity.EnvTokenFile: cloudidentity.TokenFile, "A": "1"}},
		{name: "env conflict", ctx: runner, owner: "team:payments", runtime: models.RuntimeDocker,
			req:  models.CreateSandboxRequest{Env: map[string]string{cloudidentity.EnvAWSRoleARN: "arn:aws:iam::999999999999:role/x"}, Identity: &models.IdentityRequest{RoleTag: "deploy", AWSRoleARN: arn}},
			want: ErrIdentityInvalid},
		{name: "tag not listed", ctx: runner, owner: "team:payments", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "unlisted"}}, want: ErrIdentityRoleDenied},
		{name: "another team's tag", ctx: runner, owner: "team:other", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}, want: ErrIdentityRoleDenied},
		{name: "caller below the tag's role", ctx: runner, owner: "team:payments", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "prod"}}, want: ErrIdentityRoleDenied},
		{name: "admin may use it", ctx: controlplane.ContextWithAccess(context.Background(), controlplane.TokenAccess("tok_a", "a", controlplane.RoleAdmin, "*", time.Time{})),
			owner: "team:payments", runtime: models.RuntimeFirecracker, req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "prod"}}},
		{name: "internal create needs the tag only", ctx: context.Background(), owner: "team:payments", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "prod"}}},
		{name: "failover replay skips the list", ctx: contextWithStoredSpecReplay(context.Background()), owner: "team:payments", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "since-removed"}}},
		{name: "wasm", ctx: runner, owner: "team:payments", runtime: models.RuntimeWasm,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}, want: ErrIdentityRuntime},
		{name: "isolate", ctx: runner, owner: "team:payments", runtime: models.RuntimeIsolate,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}, want: ErrIdentityRuntime},
		{name: "bad option", ctx: runner, owner: "team:payments", runtime: models.RuntimeDocker,
			req: models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy", AzureClientID: "x"}}, want: ErrIdentityInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			err := h.svc.prepareCreateIdentity(tc.ctx, &req, tc.owner, tc.runtime)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && req.Identity != nil && req.Identity.Audience != cloudidentity.DefaultAudience {
				t.Fatalf("audience not normalized: %+v", req.Identity)
			}
			for k, v := range tc.env {
				if req.Env[k] != v {
					t.Fatalf("env[%s] = %q, want %q (env %v)", k, req.Env[k], v, req.Env)
				}
			}
		})
	}
	// Cluster mode: refused until every member runs a build with identity,
	// and an unreadable allow list is a 503.
	h.svc.cfg.EnableCluster = true
	h.svc.AttachCluster(cluster.NewNoop("node-a", "", ""))
	req := models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}
	if err := h.svc.prepareCreateIdentity(runner, &req, "team:payments", models.RuntimeDocker); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("gate closed = %v", err)
	}
	h.svc.cfg.EnableCluster = false
	h.svc.identity.backend = noClusterIdentity{}
	if err := h.svc.prepareCreateIdentity(runner, &req, "team:payments", models.RuntimeDocker); !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("unreadable allow list = %v", err)
	}
}

// End to end on one node: the create records the identity, gives the
// runtime the env, returns at once, and the first token lands right after,
// with the claims of point 3 and an audit record (D1.10) that never holds
// the token.
func TestCreateSandboxWithIdentity(t *testing.T) {
	h := newIdentityHarness(t)
	h.allow(t, "payments", "deploy", "runner")
	runner := controlplane.ContextWithAccess(context.Background(), paymentsToken())
	resp, err := h.svc.CreateSandbox(runner, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 256, DiskGB: 5,
		Identity: &models.IdentityRequest{RoleTag: "deploy", AWSRoleARN: "arn:aws:iam::123456789012:role/deploy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Sandbox.ID
	if v := resp.Sandbox.Identity; v == nil || v.Subject != "team:payments:role:deploy" || v.TokenFile != cloudidentity.TokenFile {
		t.Fatalf("create response identity = %+v", resp.Sandbox.Identity)
	}
	if got := h.rt.lastCreateReq.Env[cloudidentity.EnvAWSTokenFile]; got != cloudidentity.TokenFile {
		t.Fatalf("runtime env = %v", h.rt.lastCreateReq.Env)
	}
	tokens := h.waitTokens(t, id, 1)
	claims, err := cloudidentity.Verify(tokens[0], h.jwks(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "team:payments:role:deploy" || claims.Team != "payments" || claims.Sandbox != id ||
		claims.Audience != cloudidentity.DefaultAudience || claims.Issuer != testIssuer || claims.Expiry-claims.IssuedAt != 3600 ||
		claims.IssuedAt-claims.NotBefore != 60 {
		t.Fatalf("claims = %+v", claims)
	}
	waitIdentity(t, func() bool {
		sb, err := h.svc.GetSandbox(runner, id)
		return err == nil && sb.Identity != nil && sb.Identity.TokenExpiresAt != nil
	})
	var issued *SecretAuditEvent
	waitIdentity(t, func() bool {
		h.sink.mu.Lock()
		defer h.sink.mu.Unlock()
		for i := range h.sink.events {
			if h.sink.events[i].Kind == KindIdentityTokenIssued {
				ev := h.sink.events[i]
				issued = &ev
				return true
			}
		}
		return false
	})
	if issued.SandboxID != id || issued.OwnerRef != "team:payments" || !strings.Contains(issued.Reason, "role_tag=deploy") ||
		!strings.Contains(issued.Reason, "jti="+claims.ID) || !strings.Contains(issued.Reason, "exp="+strconv.FormatInt(claims.Expiry, 10)) {
		t.Fatalf("audit record = %+v", issued)
	}
	if raw, _ := json.Marshal(issued); strings.Contains(string(raw), tokens[0]) {
		t.Fatal("the audit record holds the token")
	}
	// A start pushes a fresh token at once.
	if _, err := h.svc.StopSandbox(runner, id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.StartSandbox(runner, id); err != nil {
		t.Fatal(err)
	}
	h.waitTokens(t, id, 2)
}

func waitIdentity(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The create is undone when its identity row cannot be written (the
// failure-path rule shared with egress profile state).
func TestCreateSandboxIdentityRowFailureUndoesCreate(t *testing.T) {
	h := newIdentityHarness(t)
	h.allow(t, "", "deploy", "runner")
	sb := &models.Sandbox{ID: "sb-missing"}
	if err := h.svc.recordCreateIdentity(context.Background(), sb, &models.IdentityRequest{RoleTag: "deploy", Audience: "a"}); err == nil {
		t.Fatal("an identity row for a sandbox with no row was written")
	}
	if err := h.svc.recordCreateIdentity(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityRefresher(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := context.Background()
	h.allow(t, "", "deploy", "runner")
	now := time.Now()
	h.svc.identity.now = func() time.Time { return now }
	seed := func(id string, status models.SandboxStatus, expires time.Time) {
		t.Helper()
		if err := h.st.Create(ctx, &models.Sandbox{ID: id, Image: "alpine", Status: status, ContainerIP: "10.0.0.9", Runtime: models.RuntimeDocker}); err != nil {
			t.Fatal(err)
		}
		if err := h.st.PutSandboxIdentity(ctx, storepkg.SandboxIdentity{SandboxID: id, RoleTag: "deploy", Audience: "a"}); err != nil {
			t.Fatal(err)
		}
		if !expires.IsZero() {
			if err := h.st.RecordIdentityTokenPushed(ctx, id, "k", expires); err != nil {
				t.Fatal(err)
			}
		}
	}
	seed("sb-due", models.SandboxStatusStarted, now.Add(20*time.Minute))
	seed("sb-new", models.SandboxStatusStarted, time.Time{})
	seed("sb-fresh", models.SandboxStatusStarted, now.Add(50*time.Minute))
	seed("sb-stopped", models.SandboxStatusStopped, now.Add(time.Minute))
	seed("sb-busy", models.SandboxStatusStarted, now.Add(time.Minute))
	h.svc.identity.inflight.Store("sb-busy", struct{}{})
	if n := h.svc.refreshIdentityTokens(ctx); n != 2 {
		t.Fatalf("pushed %d, want the due and the new one", n)
	}
	for id, want := range map[string]int{"sb-due": 1, "sb-new": 1, "sb-fresh": 0, "sb-stopped": 0, "sb-busy": 0} {
		if got := len(h.tokens(id)); got != want {
			t.Errorf("%s got %d tokens, want %d", id, got, want)
		}
	}
	// Pushed rows are no longer due.
	if n := h.svc.refreshIdentityTokens(ctx); n != 0 {
		t.Fatalf("second pass pushed %d", n)
	}
	// A failed push is recorded on the row and counted, and an expired
	// token that could not be refreshed is counted as such.
	// Keep the count, not the counter: Get returns the same *expvar.Int
	// before and after, so comparing the two always matched on a re-run.
	before := ""
	if v := identityRefreshFailures.Get(identityFailExpired); v != nil {
		before = v.String()
	}
	h.setFail(errors.New("toolbox down"))
	now = now.Add(3 * time.Hour)
	if n := h.svc.refreshIdentityTokens(ctx); n != 0 {
		t.Fatalf("a failing pass pushed %d", n)
	}
	if row, _ := h.st.GetSandboxIdentity(ctx, "sb-due"); !strings.Contains(row.LastError, "toolbox down") {
		t.Fatalf("row = %+v", row)
	}
	if after := identityRefreshFailures.Get(identityFailExpired); after == nil || after.String() == before {
		t.Fatal("an expired unrefreshed token was not counted")
	}
	// A tag taken off the allow list stops refresh (fail closed).
	h.setFail(nil)
	if err := h.svc.DeleteIdentityRole(adminCtx(), "", "deploy"); err != nil {
		t.Fatal(err)
	}
	if n := h.svc.refreshIdentityTokens(ctx); n != 0 {
		t.Fatalf("a removed tag was refreshed %d times", n)
	}
	if row, _ := h.st.GetSandboxIdentity(ctx, "sb-due"); !strings.Contains(row.LastError, "removed from the allow list") {
		t.Fatalf("row after removal = %+v", row)
	}
	// Unreadable allow list: skipped, retried next pass.
	h.allow(t, "", "deploy", "runner")
	h.svc.identity.backend = &roleReadsFail{identityBackend: h.st}
	if n := h.svc.refreshIdentityTokens(ctx); n != 0 {
		t.Fatalf("an unreadable allow list still pushed %d", n)
	}
	h.svc.identity.backend = nil
	if n := h.svc.refreshIdentityTokens(ctx); n != 3 {
		t.Fatalf("after recovery pushed %d, want 3 (due, new, fresh-now-due)", n)
	}
	// The loop stops with its context.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	h.svc.SuperviseIdentityTokens(cctx)
	h.svc.cfg.IdentityIssuerURL = ""
	h.svc.SuperviseIdentityTokens(ctx) // off: returns at once
}

type roleReadsFail struct{ identityBackend }

func (roleReadsFail) GetIdentityRole(context.Context, string, string) (models.IdentityRole, error) {
	return models.IdentityRole{}, errors.New("server tier unreachable")
}

func TestPushIdentityTokenByIDOutcomes(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := context.Background()
	h.allow(t, "", "deploy", "runner")
	if done, err := h.svc.pushIdentityTokenByID(ctx, "sb-none", identityPushStart); !done || err != nil {
		t.Fatalf("no identity = %v %v", done, err)
	}
	for _, sb := range []*models.Sandbox{
		{ID: "sb-creating", Status: models.SandboxStatusCreating},
		{ID: "sb-stopped", Status: models.SandboxStatusStopped},
		{ID: "sb-noip", Status: models.SandboxStatusStarted},
		{ID: "sb-ip", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.5"},
	} {
		sb.Image = "alpine"
		if err := h.st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		if err := h.st.PutSandboxIdentity(ctx, storepkg.SandboxIdentity{SandboxID: sb.ID, RoleTag: "deploy", Audience: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	for id, wantDone := range map[string]bool{"sb-creating": false, "sb-stopped": true, "sb-noip": false} {
		if done, _ := h.svc.pushIdentityTokenByID(ctx, id, identityPushFirst); done != wantDone {
			t.Errorf("%s done = %v, want %v", id, done, wantDone)
		}
	}
	h.setFail(errIdentityToolboxTooOld)
	if done, err := h.svc.pushIdentityTokenByID(ctx, "sb-ip", identityPushFirst); !done || !errors.Is(err, errIdentityToolboxTooOld) {
		t.Fatalf("old toolbox = %v %v", done, err)
	}
	h.setFail(errors.New("connection refused"))
	if done, err := h.svc.pushIdentityTokenByID(ctx, "sb-ip", identityPushFirst); done || err == nil {
		t.Fatalf("transient failure = %v %v", done, err)
	}
	// A second request for a sandbox a push already runs for is a no-op.
	h.svc.identity.inflight.Store("sb-ip", struct{}{})
	h.setFail(nil)
	h.svc.pushIdentityTokenSoon("sb-ip", identityPushStart)
	time.Sleep(50 * time.Millisecond)
	if len(h.tokens("sb-ip")) != 0 {
		t.Fatal("a duplicate push ran")
	}
	h.svc.identity.inflight.Delete("sb-ip")
	// A sandbox that comes up during the window gets its token.
	if err := h.st.UpdateStatus(ctx, "sb-creating", models.SandboxStatusCreating, ""); err != nil {
		t.Fatal(err)
	}
	h.svc.pushIdentityTokenSoon("sb-ip", identityPushFirst)
	h.waitTokens(t, "sb-ip", 1)
}

// deliverIdentityToken speaks toolboxd's push route: the sandbox's toolbox
// token, a JSON body, 204; an old toolboxd's route-missing 404 is told apart.
func TestDeliverIdentityTokenHTTP(t *testing.T) {
	h := newIdentityHarness(t)
	h.svc.identity.deliver = nil
	var got atomic.Value
	var status atomic.Int32
	status.Store(http.StatusNoContent)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got.Store(r.Method + " " + r.URL.Path + " " + r.Header.Get("Authorization") + " " + body.Token)
		if status.Load() == http.StatusNotFound {
			w.Header().Set("X-Toolbox-Route", "none")
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	h.svc.cfg.ToolboxPort, _ = strconv.Atoi(port)
	sb := &models.Sandbox{ID: "sb-http", Status: models.SandboxStatusStarted, ContainerIP: host, ToolboxToken: "tbx", Runtime: models.RuntimeDocker}
	if err := h.svc.deliverIdentityToken(context.Background(), sb, "a.b.c"); err != nil {
		t.Fatal(err)
	}
	if got.Load() != "PUT /admin/identity/token Bearer tbx a.b.c" {
		t.Fatalf("toolboxd saw %q", got.Load())
	}
	status.Store(http.StatusNotFound)
	if err := h.svc.deliverIdentityToken(context.Background(), sb, "a.b.c"); !errors.Is(err, errIdentityToolboxTooOld) {
		t.Fatalf("route missing = %v", err)
	}
	status.Store(http.StatusInternalServerError)
	if err := h.svc.deliverIdentityToken(context.Background(), sb, "a.b.c"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500 = %v", err)
	}
	stopped := *sb
	stopped.Status = models.SandboxStatusStopped
	if err := h.svc.deliverIdentityToken(context.Background(), &stopped, "a.b.c"); !errors.Is(err, ErrSandboxNotRunning) {
		t.Fatalf("stopped = %v", err)
	}
	srv.Close()
	if err := h.svc.deliverIdentityToken(context.Background(), sb, "a.b.c"); err == nil {
		t.Fatal("a closed toolbox accepted a push")
	}
}

// Point 5: the push route sits under /admin, which every tenant-facing
// toolbox proxy refuses.
func TestIdentityTokenRouteIsNotProxied(t *testing.T) {
	for _, p := range []string{identityTokenPath, "admin/identity/token", "/x/../admin/identity/token"} {
		if err := refuseToolboxAdminPath(p); !errors.Is(err, storepkg.ErrNotFound) {
			t.Errorf("%s reachable through the proxy: %v", p, err)
		}
	}
}

// A server-key rotation reseals the signing keys onto the new key and
// counts them, so a retire never strands them.
func TestResealIdentityKeys(t *testing.T) {
	h := newIdentityHarness(t)
	ctx := context.Background()
	counts := map[uint32]int{}
	moved := 0
	count := func(from uint32, m bool) {
		counts[from]++
		if m {
			moved++
		}
	}
	unopenable := 0
	// No keys: nothing to do.
	if err := h.svc.resealIdentityKeys(ctx, count, func() { unopenable++ }); err != nil || len(counts) != 0 {
		t.Fatalf("no keys = %v %v", err, counts)
	}
	if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
		t.Fatal(err)
	}
	// One key in the ring: counted, not moved.
	if err := h.svc.resealIdentityKeys(ctx, count, func() { unopenable++ }); err != nil || counts[0] != 1 || moved != 0 {
		t.Fatalf("one ring key = %v %v moved=%d", err, counts, moved)
	}
	oldKey := secretsTestKey(t, 1)
	newKey := secretsTestKey(t, 2)
	ring, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: oldKey, Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.cipher = ring
	h.svc.identity.signer.Store(nil)
	h.svc.identity.keysReady.Store(false)
	if _, err := h.st.WriteIdentityKeys(ctx, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ring.SetRing([]secrets.RingKey{{ID: 0}, {ID: 7, Key: newKey, Current: true}}); err != nil {
		t.Fatal(err)
	}
	moved = 0
	if err := h.svc.resealIdentityKeys(ctx, count, func() { unopenable++ }); err != nil || moved != 1 {
		t.Fatalf("reseal = %v moved=%d", err, moved)
	}
	// After the retire the key still opens and still signs.
	if err := ring.SetRing([]secrets.RingKey{{ID: 7, Current: true}}); err != nil {
		t.Fatal(err)
	}
	h.svc.identity.signer.Store(nil)
	if _, err := h.svc.currentIdentitySigner(ctx); err != nil {
		t.Fatalf("signing key after the old server key retired: %v", err)
	}
	// A key no ring key opens is reported, not dropped.
	set, _ := h.st.ReadIdentityKeys(ctx)
	set.Keys[0].SealedPrivate = []byte("garbage")
	h.svc.identity.backend = staticKeys{identityBackend: h.st, set: set}
	if err := h.svc.resealIdentityKeys(ctx, count, func() { unopenable++ }); err != nil || unopenable != 1 {
		t.Fatalf("unopenable = %v %d", err, unopenable)
	}
	// An unreadable set stops an issuer's pass; a non-issuer has nothing.
	h.svc.identity.backend = noClusterIdentity{}
	if err := h.svc.resealIdentityKeys(ctx, count, func() {}); err == nil {
		t.Fatal("an issuer's unreadable set did not stop the pass")
	}
	h.svc.cfg.IdentityIssuerURL = ""
	if err := h.svc.resealIdentityKeys(ctx, count, func() {}); err != nil {
		t.Fatalf("non-issuer = %v", err)
	}
	empty := &Service{}
	if err := empty.resealIdentityKeys(ctx, count, func() {}); err != nil {
		t.Fatalf("no store = %v", err)
	}
}

type staticKeys struct {
	identityBackend
	set cloudidentity.KeySet
}

func (s staticKeys) ReadIdentityKeys(context.Context) (cloudidentity.KeySet, error) {
	return s.set, nil
}
