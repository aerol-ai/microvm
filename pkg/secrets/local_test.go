package secrets

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

type memBlobStore struct {
	mu    sync.Mutex
	byRef map[string]SecretBlob
}

func newMemBlobStore() *memBlobStore {
	return &memBlobStore{byRef: make(map[string]SecretBlob)}
}

func (m *memBlobStore) Put(_ context.Context, rec SecretBlob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byRef[rec.Ref] = rec
	return nil
}

func (m *memBlobStore) Get(_ context.Context, ref string) (*SecretBlob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byRef[ref]
	if !ok {
		return nil, ErrNotFound
	}
	cp := rec
	return &cp, nil
}

func (m *memBlobStore) DeleteForSandbox(_ context.Context, sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ref, rec := range m.byRef {
		if rec.SandboxID == sandboxID {
			delete(m.byRef, ref)
		}
	}
	return nil
}

func (m *memBlobStore) NextSealGeneration(_ context.Context, sandboxID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var max int64
	for _, rec := range m.byRef {
		if rec.SandboxID == sandboxID && rec.SealGeneration > max {
			max = rec.SealGeneration
		}
	}
	return max + 1, nil
}

type errBlobStore struct {
	putErr error
	getErr error
}

func (e errBlobStore) Put(context.Context, SecretBlob) error { return e.putErr }
func (e errBlobStore) Get(context.Context, string) (*SecretBlob, error) {
	return nil, e.getErr
}
func (e errBlobStore) DeleteForSandbox(context.Context, string) error            { return nil }
func (e errBlobStore) NextSealGeneration(context.Context, string) (int64, error) { return 1, nil }

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	c, err := NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestLocalProviderPutOpenRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := NewLocalProvider(testCipher(t), newMemBlobStore())
	sec := Secrets{
		Registry: &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "supersecret"},
		MountCreds: map[string]map[string]string{
			"/data": {"AWS_SECRET_ACCESS_KEY": "shh"},
		},
	}
	h, err := p.Put(ctx, "sb-1", sec, []string{"node-a"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if h.Ref == "" || h.Version != RefVersion {
		t.Fatalf("handle = %+v", h)
	}

	got, err := p.Open(ctx, "sb-1", h, "node-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Registry == nil || got.Registry.Password != "supersecret" {
		t.Fatalf("registry = %+v", got.Registry)
	}
	if got.MountCreds["/data"]["AWS_SECRET_ACCESS_KEY"] != "shh" {
		t.Fatalf("mount creds = %+v", got.MountCreds)
	}
}

func TestLocalProviderWrongRecipientDenied(t *testing.T) {
	ctx := context.Background()
	p := NewLocalProvider(testCipher(t), newMemBlobStore())
	h, err := p.Put(ctx, "sb-1", Secrets{
		Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, err = p.Open(ctx, "sb-1", h, "node-b")
	if !errors.Is(err, ErrRecipientDenied) {
		t.Fatalf("Open wrong recipient = %v, want ErrRecipientDenied", err)
	}
}

func TestLocalProviderMissingNotFound(t *testing.T) {
	ctx := context.Background()
	p := NewLocalProvider(testCipher(t), newMemBlobStore())
	_, err := p.Open(ctx, "sb-1", Handle{Ref: "cluster-secret://sandbox/missing/v1", Version: 1}, "node-a")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open missing = %v, want ErrNotFound", err)
	}
}

func TestLocalProviderEmptySecretsZeroHandle(t *testing.T) {
	ctx := context.Background()
	store := newMemBlobStore()
	p := NewLocalProvider(testCipher(t), store)
	h, err := p.Put(ctx, "sb-1", Secrets{}, []string{"node-a"})
	if err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	if h != (Handle{}) {
		t.Fatalf("empty Put handle = %+v, want zero", h)
	}
	if len(store.byRef) != 0 {
		t.Fatalf("empty Put wrote %d rows", len(store.byRef))
	}
}

func TestLocalProviderDeleteAndErrorArms(t *testing.T) {
	ctx := context.Background()
	store := newMemBlobStore()
	c := testCipher(t)
	p := NewLocalProvider(c, store)
	h, err := p.Put(ctx, "sb-del", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"node-a"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := p.Delete(ctx, "sb-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Open(ctx, "sb-del", h, "node-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v", err)
	}
	if err := (*LocalProvider)(nil).Delete(ctx, "x"); err != nil {
		t.Fatalf("nil provider Delete = %v", err)
	}

	if _, err := (*LocalProvider)(nil).Put(ctx, "sb", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, nil); err == nil {
		t.Fatal("nil provider Put")
	}
	if _, err := NewLocalProvider(c, nil).Put(ctx, "sb", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, nil); err == nil {
		t.Fatal("nil store Put")
	}
	if _, err := p.Put(ctx, " ", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, nil); err == nil {
		t.Fatal("empty sandbox id")
	}

	h2, err := NewLocalProvider(c, store).Put(ctx, "sb-v2", Secrets{Registry: &models.RegistryAuth{Password: "q"}}, []string{"*"})
	if err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	bad := h2
	bad.Version = h2.Version + 1
	if _, err := NewLocalProvider(c, store).Open(ctx, "sb-v2", bad, ""); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("version mismatch = %v", err)
	}
	if _, err := NewLocalProvider(nil, store).Open(ctx, "sb-v2", h2, ""); err == nil {
		t.Fatal("nil cipher after successful Get should fail")
	}
	if _, err := NewLocalProvider(c, nil).Open(ctx, "sb", Handle{Ref: "x"}, ""); err == nil {
		t.Fatal("nil store Open")
	}
	emptyH, err := p.Open(ctx, "sb", Handle{}, "node-a")
	if err != nil || emptyH.Registry != nil {
		t.Fatalf("empty handle Open = %+v %v", emptyH, err)
	}

	if _, err := NewLocalProvider(c, errBlobStore{putErr: errors.New("put boom")}).Put(ctx, "sb", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"n"}); err == nil {
		t.Fatal("store Put error should surface")
	}
	if _, err := NewLocalProvider(c, errBlobStore{getErr: errors.New("get boom")}).Open(ctx, "sb", Handle{Ref: "r"}, ""); err == nil {
		t.Fatal("store Get error should surface")
	}
}
