package e2b

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// A low-entropy secret: exactly what an unkeyed hash lets someone holding the
// fingerprint (or the sandbox ID cut from it) confirm by guessing.
const fpTestSecret = "hunter2"

func fpKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func fpCipher(t *testing.T, keys ...secrets.RingKey) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipherRing(keys)
	if err != nil {
		t.Fatalf("NewCipherRing: %v", err)
	}
	return c
}

// cipherDigester is the service's RequestDigests over a bare Cipher.
type cipherDigester struct{ c *secrets.Cipher }

func (d cipherDigester) RequestDigests(purpose string, data []byte) ([]secrets.KeyedDigest, error) {
	return d.c.Digests(purpose, data)
}

type stubDigester struct {
	digests []secrets.KeyedDigest
	err     error
}

func (d stubDigester) RequestDigests(string, []byte) ([]secrets.KeyedDigest, error) {
	return d.digests, d.err
}

func fpInputs() (models.CreateSandboxRequest, sandboxMeta) {
	return models.CreateSandboxRequest{Image: "ubuntu:22.04", Env: map[string]string{"DB_PASSWORD": fpTestSecret}},
		sandboxMeta{TemplateID: "base", TimeoutSeconds: 120, OnTimeout: "kill"}
}

// legacyFingerprint is the unkeyed format the previous server stored, written
// out here independently so a change to it cannot pass unnoticed.
func legacyFingerprint(t *testing.T, ownerRef, templateID string, req models.CreateSandboxRequest, meta sandboxMeta) string {
	t.Helper()
	payload, err := createFingerprintPayloadJSON(ownerRef, templateID, req, meta)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return "fingerprint:" + hex.EncodeToString(sum[:])
}

func TestCreateFingerprintIsKeyedAndStable(t *testing.T) {
	req, meta := fpInputs()
	one := cipherDigester{fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(1), Current: true})}
	// The same key loaded again: a restart, or another node sharing the key.
	again := cipherDigester{fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(1), Current: true})}
	other := cipherDigester{fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(2), Current: true})}

	a, err := createRequestFingerprints(one, "acme", "base", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := createRequestFingerprints(again, "acme", "base", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.current != b.current {
		t.Fatalf("same input and key gave %q and %q", a.current, b.current)
	}
	if len(a.earlier) != 0 {
		t.Fatalf("a one-key ring with no legacy window has earlier fingerprints: %q", a.earlier)
	}
	if !strings.HasPrefix(a.current, "hmac:0:") || len(strings.TrimPrefix(a.current, "hmac:0:")) != 64 {
		t.Fatalf("fingerprint %q is not hmac:<key id>:<64 hex>", a.current)
	}

	c, err := createRequestFingerprints(other, "acme", "base", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.current == a.current {
		t.Fatal("a different server key gave the same fingerprint")
	}

	legacy := legacyFingerprint(t, "acme", "base", req, meta)
	for _, fp := range []string{a.current, c.current} {
		if strings.Contains(fp, fpTestSecret) {
			t.Fatalf("fingerprint %q holds the env value", fp)
		}
		if strings.HasSuffix(legacy, fp[strings.LastIndex(fp, ":")+1:]) {
			t.Fatal("the keyed fingerprint is the unkeyed hash")
		}
		if sandboxIDFromFingerprint(fp) == sandboxIDFromFingerprint(legacy) {
			t.Fatal("the sandbox ID is still cut from the unkeyed hash")
		}
	}
}

func TestCreateFingerprintChangesWithTheEnv(t *testing.T) {
	d := cipherDigester{fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(1), Current: true})}
	req, meta := fpInputs()
	a, err := createRequestFingerprints(d, "", "base", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	req.Env = map[string]string{"DB_PASSWORD": fpTestSecret + "!"}
	b, err := createRequestFingerprints(d, "", "base", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.current == b.current {
		t.Fatal("two creates with different env share a fingerprint")
	}
}

// The create idempotency ledger is keyed (scope, fingerprint) with no owner
// column, so the owner must be folded into the fingerprint — otherwise two
// tenants sending the same create body would collide and the second would
// replay the first tenant's sandbox (D13). This pins that invariant.
func TestCreateRequestFingerprintIsOwnerNamespaced(t *testing.T) {
	d := cipherDigester{fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(1), Current: true})}
	req, meta := fpInputs()
	acme, err := createRequestFingerprints(d, "acme", "tid", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	globex, err := createRequestFingerprints(d, "globex", "tid", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	if acme.current == globex.current {
		t.Fatalf("same fingerprint for different owners: %q", acme.current)
	}
}

// During a rotation the server holds the previous key too: a claim stored
// under it is found, and the new claim is made under the current key.
func TestCreateFingerprintAcrossAKeyRotation(t *testing.T) {
	req, meta := fpInputs()
	before := cipherDigester{fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(1), Current: true})}
	during := cipherDigester{fpCipher(t,
		secrets.RingKey{ID: 0, Key: fpKey(1)},
		secrets.RingKey{ID: 1, Key: fpKey(2), Current: true})}

	old, err := createRequestFingerprints(before, "", "base", req, meta, false)
	if err != nil {
		t.Fatal(err)
	}
	now, err := createRequestFingerprints(during, "", "base", req, meta, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(now.current, "hmac:1:") {
		t.Fatalf("current fingerprint %q is not under the current key", now.current)
	}
	want := []string{old.current, legacyFingerprint(t, "", "base", req, meta)}
	if len(now.earlier) != len(want) || now.earlier[0] != want[0] || now.earlier[1] != want[1] {
		t.Fatalf("earlier = %q, want the previous key's then the unkeyed one %q", now.earlier, want)
	}
}

func TestCreateFingerprintErrors(t *testing.T) {
	req, meta := fpInputs()
	boom := errors.New("key store down")
	for name, d := range map[string]requestDigester{
		"no service":       nil,
		"digest fails":     stubDigester{err: boom},
		"empty key ring":   stubDigester{},
		"service, no key":  (*service.Service)(nil),
		"revoked key ring": revokedDigester(t),
	} {
		t.Run(name, func(t *testing.T) {
			if fp, err := createRequestFingerprints(d, "", "base", req, meta, true); err == nil {
				t.Fatalf("fingerprint %+v, want an error", fp)
			}
		})
	}
}

func revokedDigester(t *testing.T) requestDigester {
	c := fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(1), Current: true})
	c.Revoke()
	return cipherDigester{c}
}

// ---------------------------------------------------------------------------
// The handler: claims under an earlier fingerprint replay instead of creating.
// ---------------------------------------------------------------------------

type fpEnv struct {
	svc     *service.Service
	st      *store.Store
	cipher  *secrets.Cipher
	h       *handlers
	runtime *fakeE2BRuntime
	logs    *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newFingerprintEnv(t *testing.T) *fpEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	mountManager, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir: filepath.Join(dir, "mounts"), CredDir: filepath.Join(dir, "creds"), WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mountManager.Close)
	cipher := fpCipher(t, secrets.RingKey{ID: 0, Key: fpKey(7), Current: true})
	cfg := config.Config{PublicHost: "sandbox.test", ToolboxPort: 2280}
	runtime := newFakeE2BRuntime()
	svc := service.New(cfg, logger, st, runtime, nil, caddy.New(cfg), cipher, mountManager, nil)
	h := newHandlers(Deps{Service: svc, Logger: logger, TemplateMapJSON: `{"base":"ubuntu:22.04"}`})
	return &fpEnv{svc: svc, st: st, cipher: cipher, h: h, runtime: runtime, logs: logs}
}

func (e *fpEnv) create(t *testing.T, body string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	e.h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	var created sandboxResponse
	_ = json.NewDecoder(rr.Body).Decode(&created)
	return rr.Code, created.SandboxID
}

func (e *fpEnv) fingerprints(t *testing.T, body string, withLegacy bool) createFingerprints {
	t.Helper()
	var req createSandboxRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	serviceReq, meta, err := e.h.translateCreateSandboxRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	fps, err := createRequestFingerprints(e.svc, "", req.TemplateID, serviceReq, meta, withLegacy)
	if err != nil {
		t.Fatal(err)
	}
	return fps
}

// claimReady stores a finished claim of fingerprint pointing at target, as
// the server that made the create would have.
func (e *fpEnv) claimReady(t *testing.T, fingerprint, target string) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	if _, acquired, err := e.svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, e2bCreatePendingTTL); err != nil || !acquired {
		t.Fatalf("claim %s: acquired=%v err=%v", fingerprint, acquired, err)
	}
	if err := e.svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, target, now, e2bCreateReplayWindow); err != nil {
		t.Fatalf("complete %s: %v", fingerprint, err)
	}
}

const (
	fpBody      = `{"templateID":"base","timeout":120,"envVars":{"DB_PASSWORD":"hunter2"}}`
	fpOtherBody = `{"templateID":"base","timeout":120,"envVars":{"OTHER":"x"}}`
)

func TestCreateReplaysAClaimUnderTheUnkeyedFingerprintAfterUpgrade(t *testing.T) {
	e := newFingerprintEnv(t)
	// The sandbox the previous server made for fpBody, under an ID cut from
	// its unkeyed fingerprint: any ID that is not this server's for fpBody.
	code, earlier := e.create(t, fpOtherBody)
	if code != http.StatusCreated {
		t.Fatalf("seed create = %d", code)
	}
	fps := e.fingerprints(t, fpBody, true)
	e.claimReady(t, fps.earlier[len(fps.earlier)-1], earlier)

	code, got := e.create(t, fpBody)
	if code != http.StatusCreated || got != earlier {
		t.Fatalf("retry after upgrade = %d %q, want a replay of %q", code, got, earlier)
	}
}

func TestCreateIgnoresTheUnkeyedFingerprintOnceTheWindowCloses(t *testing.T) {
	e := newFingerprintEnv(t)
	_, earlier := e.create(t, fpOtherBody)
	fps := e.fingerprints(t, fpBody, true)
	e.claimReady(t, fps.earlier[len(fps.earlier)-1], earlier)

	e.h.legacyFingerprintsUntil = time.Now().Add(-time.Second)
	code, got := e.create(t, fpBody)
	if code != http.StatusCreated || got == earlier || got != sandboxIDFromFingerprint(fps.current) {
		t.Fatalf("create after the window = %d %q, want a new sandbox %q", code, got, sandboxIDFromFingerprint(fps.current))
	}
}

func TestCreateWaitsForAClaimUnderTheUnkeyedFingerprint(t *testing.T) {
	e := newFingerprintEnv(t)
	_, earlier := e.create(t, fpOtherBody)
	legacy := e.fingerprints(t, fpBody, true).earlier[0]
	ctx := context.Background()
	if _, acquired, err := e.svc.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, legacy, time.Now().UTC(), e2bCreatePendingTTL); err != nil || !acquired {
		t.Fatalf("pending claim: acquired=%v err=%v", acquired, err)
	}
	// The create the old process was running finishes while the retry waits.
	done := make(chan error, 1)
	go func() {
		time.Sleep(3 * e2bCreatePollInterval)
		done <- e.svc.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, legacy, earlier, time.Now().UTC(), e2bCreateReplayWindow)
	}()
	code, got := e.create(t, fpBody)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != http.StatusCreated || got != earlier {
		t.Fatalf("retry = %d %q, want it to wait for and replay %q", code, got, earlier)
	}
}

func TestCreateReplaysAClaimUnderThePreviousKeyDuringARotation(t *testing.T) {
	e := newFingerprintEnv(t)
	e.h.legacyFingerprintsUntil = time.Time{}
	_, earlier := e.create(t, fpOtherBody)
	beforePromote := e.fingerprints(t, fpBody, false).current
	e.claimReady(t, beforePromote, earlier)

	// sandboxd key rotate: stage key 1 and promote it; key 0 stays readable.
	if err := e.cipher.SetRing([]secrets.RingKey{{ID: 0}, {ID: 1, Key: fpKey(8), Current: true}}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if now := e.fingerprints(t, fpBody, false); now.current == beforePromote || len(now.earlier) != 1 || now.earlier[0] != beforePromote {
		t.Fatalf("after promote: %+v, want a new current and the old one earlier", now)
	}
	code, got := e.create(t, fpBody)
	if code != http.StatusCreated || got != earlier {
		t.Fatalf("retry across the promote = %d %q, want a replay of %q", code, got, earlier)
	}
}

// The idempotency table holds the keyed fingerprint, never the unkeyed one,
// and a create that fails logs the sandbox ID, not the fingerprint.
func TestCreateStoresAndLogsOnlyTheKeyedFingerprint(t *testing.T) {
	e := newFingerprintEnv(t)
	fps := e.fingerprints(t, fpBody, true)
	legacy := fps.earlier[len(fps.earlier)-1]

	e.runtime.blockCreate = make(chan struct{})
	e.runtime.onCreateChan = make(chan struct{}, 1)
	e.runtime.errCreate = errors.New("runtime refused")
	result := make(chan int, 1)
	go func() {
		code, _ := e.create(t, fpBody)
		result <- code
	}()
	<-e.runtime.onCreateChan

	// Mid-create: the claim is pending under the keyed fingerprint only.
	ctx := context.Background()
	record, err := e.svc.GetIdempotentRequest(ctx, idempotencyScopeCreate, fps.current)
	if err != nil || record.State != models.RequestStatePending {
		t.Fatalf("keyed claim = %+v, %v; want pending", record, err)
	}
	if _, err := e.svc.GetIdempotentRequest(ctx, idempotencyScopeCreate, legacy); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unkeyed claim was written: %v", err)
	}

	// The create fails, and its claim cleanup too (the store goes away), so
	// the cleanup's warning is logged.
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	close(e.runtime.blockCreate)
	if code := <-result; code == http.StatusCreated {
		t.Fatalf("create = %d, want a failure", code)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "e2b create reservation cleanup failed") {
		t.Fatalf("the cleanup failure was not logged:\n%s", logs)
	}
	for _, leak := range []string{fps.current, strings.TrimPrefix(fps.current, "hmac:0:"), legacy, fpTestSecret} {
		if strings.Contains(logs, leak) {
			t.Fatalf("the log holds %q:\n%s", leak, logs)
		}
	}
	if !strings.Contains(logs, "sandbox_id="+sandboxIDFromFingerprint(fps.current)) {
		t.Fatalf("the cleanup warning does not name the sandbox:\n%s", logs)
	}
}

// With the server key revoked there is no fingerprint, and no create: it must
// not fall back to an unkeyed one.
func TestCreateFailsClosedWithoutTheServerKey(t *testing.T) {
	e := newFingerprintEnv(t)
	e.cipher.Revoke()
	if code, id := e.create(t, fpBody); code != http.StatusServiceUnavailable || id != "" {
		t.Fatalf("create with the key revoked = %d %q, want 503", code, id)
	}
	if e.runtime.createHits != 0 {
		t.Fatalf("the runtime was asked to create %d sandboxes", e.runtime.createHits)
	}
}

// A retry that gives up while it looks for an earlier claim creates nothing.
func TestCreateStopsWhenTheCallerGoesWhileCheckingEarlierClaims(t *testing.T) {
	e := newFingerprintEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rr := httptest.NewRecorder()
	e.h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(fpBody)).WithContext(ctx))
	if rr.Code == http.StatusCreated || e.runtime.createHits != 0 {
		t.Fatalf("create = %d with %d runtime creates, want a failure and none", rr.Code, e.runtime.createHits)
	}
}
