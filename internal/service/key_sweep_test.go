package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// transitLike is a key store with Transit's versioning: wraps carry
// "vault:vN:", rotation adds a version, and versions below min no longer
// decrypt (ErrKeyVersionRetired).
type transitLike struct {
	mu     sync.Mutex
	keys   map[int]*secrets.FakeKMS
	latest int
	min    int
	down   bool
}

func newTransitLike(t *testing.T) *transitLike {
	tl := &transitLike{keys: map[int]*secrets.FakeKMS{}, min: 1}
	tl.rotate(t)
	return tl
}

func (tl *transitLike) rotate(t *testing.T) {
	k, err := secrets.NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	tl.mu.Lock()
	tl.latest++
	tl.keys[tl.latest] = k
	tl.mu.Unlock()
}

func (tl *transitLike) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.down {
		return nil, secrets.ErrProviderUnavailable
	}
	w, err := tl.keys[tl.latest].Wrap(ctx, dek, encCtx)
	return append([]byte(fmt.Sprintf("vault:v%d:", tl.latest)), w...), err
}

func (tl *transitLike) Unwrap(ctx context.Context, w []byte, encCtx map[string]string) ([]byte, error) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.down {
		return nil, secrets.ErrProviderUnavailable
	}
	rest := strings.TrimPrefix(string(w), "vault:v")
	i := strings.Index(rest, ":")
	v, _ := strconv.Atoi(rest[:i])
	if v < tl.min {
		return nil, fmt.Errorf("%w: too old", secrets.ErrKeyVersionRetired)
	}
	return tl.keys[v].Unwrap(ctx, []byte(rest[i+1:]), encCtx)
}

func (tl *transitLike) CurrentKeyVersion(context.Context) (string, error) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.down {
		return "", secrets.ErrProviderUnavailable
	}
	return fmt.Sprintf("vault:v%d", tl.latest), nil
}

// sweepHarness is a Vault node holding n key-store rows and one local row
// from before the switch, with a wrapped server-key file.
func sweepHarness(t *testing.T, n int) (*Service, *transitLike, []string) {
	t.Helper()
	svc, _, _, _, _ := revokeHarness(t)
	tl := newTransitLike(t)
	svc.cfg.SecretProvider = "vault"
	svc.SetKeyStoreWrapper(tl)
	ctx := context.Background()
	f, err := secrets.WrapServerKey(ctx, tl, bytes.Repeat([]byte{8}, 32), "vault", "transit/k")
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.WriteWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath, f); err != nil {
		t.Fatal(err)
	}
	var refs []string
	put := func(i int, local bool) {
		id, inc := fmt.Sprintf("sb-%03d", i), "inc"
		ref := secrets.FormatRef(id, inc, secrets.RefVersion)
		binding := secrets.SealBinding{SandboxID: id, IncarnationID: inc, Ref: ref, Version: secrets.RefVersion, Generation: 1}
		plain := []byte(`{"env":{"K":"` + id + `"}}`)
		var sealed []byte
		if local {
			sealed, err = secrets.SealRawEnvelopeBound(svc.cipher, plain, []string{"node-a"}, binding)
		} else {
			sealed, err = secrets.SealRawEnvelopeWrappedBound(plain, []string{"node-a"}, binding, func(dek []byte) ([]byte, error) {
				return tl.Wrap(ctx, dek, secrets.EncryptionContextForBinding(binding))
			})
		}
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if _, err := svc.store.PutClusterSecret(ctx, store.ClusterSecretRecord{Ref: ref, SandboxID: id, Version: 1, Recipients: []string{"node-a"}, SealedPayload: sealed, SealGeneration: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
	}
	for i := 0; i < n; i++ {
		put(i, false)
	}
	put(n, true)
	return svc, tl, refs
}

func rowVersion(t *testing.T, svc *Service, ref string) string {
	t.Helper()
	rec, err := svc.store.GetClusterSecret(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return secrets.WrappedKeyVersion(envelopeWrappedKey(t, rec.SealedPayload))
}

func envelopeWrappedKey(t *testing.T, sealed []byte) []byte {
	t.Helper()
	var env struct {
		WrappedKey []byte `json:"wrapped_key"`
	}
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	return env.WrappedKey
}

// §11, §12: the sweep converts the local row, then moves every row and the
// server-key file to a rotated version, keeping the content.
func TestSweepConvertsAndRewraps(t *testing.T) {
	// More rows than one page, to cover paging.
	svc, tl, refs := sweepHarness(t, keySweepPage+3)
	ctx := context.Background()
	localRef := refs[len(refs)-1]
	if v := rowVersion(t, svc, localRef); v != "" {
		t.Fatalf("local row starts tagged: %q", v)
	}
	stale, err := svc.SweepKeys(ctx)
	if err != nil || stale != 0 {
		t.Fatalf("first pass = %d %v", stale, err)
	}
	if v := rowVersion(t, svc, localRef); v != "vault:v1" {
		t.Fatalf("local row after the sweep = %q, want converted", v)
	}
	before := keyRowsRewrapped.Value()
	tl.rotate(t)
	if stale, err := svc.SweepKeys(ctx); err != nil || stale != 0 {
		t.Fatalf("after rotation = %d %v", stale, err)
	}
	if got := keyRowsRewrapped.Value() - before; got != int64(len(refs)) {
		t.Fatalf("rewrapped %d rows, want %d", got, len(refs))
	}
	for _, ref := range []string{refs[0], refs[keySweepPage+1], localRef} {
		if v := rowVersion(t, svc, ref); v != "vault:v2" {
			t.Fatalf("%s on %q after rotation", ref, v)
		}
	}
	if f, _ := secrets.ReadWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath); f.KeyVersion() != "vault:v2" {
		t.Fatalf("server-key file on %q", f.KeyVersion())
	}
	if keyRowsStale.Value() != 0 {
		t.Fatalf("stale gauge = %d", keyRowsStale.Value())
	}
	// The content is unchanged: the provider opens the converted row.
	p, _, err := secrets.NewProvider(ctx, secrets.ProviderOptions{Name: "vault", Cipher: svc.cipher, Store: newSecretBlobStore(svc.store), Prebuilt: tl})
	if err != nil {
		t.Fatal(err)
	}
	inc := secrets.ContextWithIncarnationID(ctx, "inc")
	parsed, _ := secrets.ParseRef(localRef)
	bag, err := p.Open(inc, parsed.SandboxID, secrets.Handle{Ref: localRef, Version: secrets.RefVersion, SealGeneration: 1}, "node-a")
	if err != nil || bag.Env["K"] != parsed.SandboxID {
		t.Fatalf("converted row opens to %+v %v", bag.Env, err)
	}
	if v := keyCurrentGauge.Get("vault"); v == nil || !strings.Contains(v.String(), "vault:v2") {
		t.Fatalf("aerolvm_key_current = %v", v)
	}
}

// A version retired before the sweep moved its rows is counted, not lost,
// and is never a revoke (§11).
func TestSweepCountsRetiredRows(t *testing.T) {
	svc, tl, refs := sweepHarness(t, 3)
	tl.rotate(t)
	tl.mu.Lock()
	tl.min = 2
	tl.mu.Unlock()
	stale, err := svc.SweepKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Three v1 rows can no longer be opened; the local row converts; the
	// server-key file (on v1) cannot be rewrapped either.
	if keyRowsRetired.Value() != 3 || stale != 4 {
		t.Fatalf("retired %d, stale %d", keyRowsRetired.Value(), stale)
	}
	if svc.KeyRevoked() {
		t.Fatal("a retired version revoked the node")
	}
	if v := rowVersion(t, svc, refs[len(refs)-1]); v != "vault:v2" {
		t.Fatalf("local row = %q", v)
	}
}

func TestSweepStopsWhenTheKeyStoreFails(t *testing.T) {
	svc, tl, _ := sweepHarness(t, 2)
	tl.mu.Lock()
	tl.down = true
	tl.mu.Unlock()
	if _, err := svc.SweepKeys(context.Background()); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("key store down at the version read = %v", err)
	}
	// Down after the version read: the pass stops at the first row.
	tl.mu.Lock()
	tl.down = false
	tl.mu.Unlock()
	tl.rotate(t)
	svc.SetKeyStoreWrapper(&failingAfterVersion{transitLike: tl})
	if _, err := svc.SweepKeys(context.Background()); !errors.Is(err, secrets.ErrProviderThrottled) {
		t.Fatalf("throttled mid-pass = %v", err)
	}
	// Nothing to do: revoked node, local provider, no client.
	svc.SetKeyStoreWrapper(tl)
	tl.mu.Lock()
	tl.down = true
	tl.mu.Unlock()
	svc.keyCustody.revoked.Store(true)
	if n, err := svc.SweepKeys(context.Background()); n != 0 || err != nil {
		t.Fatal("a revoked node swept")
	}
	svc.keyCustody.revoked.Store(false)
	svc.cfg.SecretProvider = "local"
	if n, err := svc.SweepKeys(context.Background()); n != 0 || err != nil {
		t.Fatal("a local node swept")
	}
}

type failingAfterVersion struct{ *transitLike }

func (f *failingAfterVersion) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, secrets.ErrProviderThrottled
}

// eng D23: the info gauges a PKCS#11 label rotation waits on.
func TestPublishKeyVersions(t *testing.T) {
	svc, _, _, _, _ := revokeHarness(t)
	svc.cfg.SecretProvider = "pkcs11"
	svc.pkcs11Helper = decryptableStub{"p11:kek-b", "p11:kek-a"}
	svc.publishKeyVersions("p11:kek-b")
	inner, ok := keyDecryptableMap.Get("pkcs11").(*expvar.Map)
	if !ok || inner.Get("p11:kek-a") == nil || inner.Get("p11:kek-b") == nil {
		t.Fatalf("aerolvm_key_decryptable = %v", keyDecryptableMap.String())
	}
	svc.pkcs11Helper = nil
	svc.cfg.SecretProvider = "vault"
	svc.publishKeyVersions("vault:v4")
	if inner, ok := keyDecryptableMap.Get("vault").(*expvar.Map); !ok || inner.Get("vault:v4") == nil {
		t.Fatalf("vault decryptable = %v", keyDecryptableMap.String())
	}
}

type decryptableStub []string

func (d decryptableStub) Wrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, nil
}
func (d decryptableStub) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, nil
}
func (d decryptableStub) DecryptableKeyVersions() []string { return d }

// The boot pass runs as soon as the loop starts on an external provider.
func TestStartKeyCustodySweepsAtBoot(t *testing.T) {
	svc, tl, refs := sweepHarness(t, 1)
	tl.rotate(t)
	svc.cfg.CredentialKeyCustody = secrets.CustodyFile
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartKeyCustody(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for rowVersion(t, svc, refs[0]) != "vault:v2" {
		if time.Now().After(deadline) {
			t.Fatal("no boot sweep")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
