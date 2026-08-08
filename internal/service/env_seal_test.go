package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func testEnvService(t *testing.T, sealEnabled bool) (*Service, *store.Store, *memSecretAuditSink) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "svc-env.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetOmitEnvFromScanner(sealEnabled)
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	audit := &memSecretAuditSink{}
	svc := &Service{
		cfg:         config.Config{SecretEnvSealEnabled: sealEnabled},
		store:       st,
		cipher:      cipher,
		secretAudit: audit,
	}
	return svc, st, audit
}

func seedEnvSandbox(t *testing.T, st *store.Store, id string, env map[string]string) {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: id, Image: "alpine:3.19", Status: models.SandboxStatusStarted,
		PublicURL: "http://x/" + id, ContainerID: "c", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", Env: env,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestSealLoadEnvRoundTrip(t *testing.T) {
	svc, st, audit := testEnvService(t, true)
	ctx := context.Background()
	seedEnvSandbox(t, st, "sb-rt", map[string]string{"TOKEN": "secret"})

	sealed, err := svc.sealEnv(map[string]string{"TOKEN": "secret"})
	if err != nil {
		t.Fatalf("sealEnv: %v", err)
	}
	if err := st.PutEnv(ctx, "sb-rt", sealed); err != nil {
		t.Fatalf("PutEnv: %v", err)
	}
	got, err := svc.loadEnv(ctx, "sb-rt")
	if err != nil {
		t.Fatalf("loadEnv: %v", err)
	}
	if got["TOKEN"] != "secret" {
		t.Fatalf("loadEnv = %+v", got)
	}
	evs := audit.Events()
	if len(evs) != 1 || evs[0].Result != secretAuditResultSuccess {
		t.Fatalf("audit = %+v", evs)
	}
}

func TestLoadEnvPlaintextFallbackMetric(t *testing.T) {
	svc, st, _ := testEnvService(t, true)
	ctx := context.Background()
	seedEnvSandbox(t, st, "sb-fb", map[string]string{"LEGACY": "1"})

	before := envPlaintextFallbackTotal.Value()
	got, err := svc.loadEnv(ctx, "sb-fb")
	if err != nil {
		t.Fatalf("loadEnv: %v", err)
	}
	if got["LEGACY"] != "1" {
		t.Fatalf("fallback = %+v", got)
	}
	if envPlaintextFallbackTotal.Value() != before+1 {
		t.Fatalf("fallback metric = %d, want %d", envPlaintextFallbackTotal.Value(), before+1)
	}
}

func TestUpsertPreservesSealedEnv(t *testing.T) {
	svc, st, _ := testEnvService(t, true)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-up", Image: "alpine:3.19", Status: models.SandboxStatusStarted,
		PublicURL: "http://x/sb-up", ContainerID: "c", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		Env:       map[string]string{"KEEP": "me"},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := svc.persistSandboxCreate(ctx, sb); err != nil {
		t.Fatalf("persistSandboxCreate: %v", err)
	}
	// Upsert without Env (scanner-empty shape) must not drop sealed row.
	sb.Env = nil
	sb.MemoryMB = 512
	sb.UpdatedAt = time.Now().UTC()
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := svc.loadEnv(ctx, "sb-up")
	if err != nil {
		t.Fatalf("loadEnv: %v", err)
	}
	if got["KEEP"] != "me" {
		t.Fatalf("sealed env lost after Upsert: %+v", got)
	}
}

func TestGetListOmitEnvIncludeOptIn(t *testing.T) {
	svc, st, audit := testEnvService(t, true)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-api", Image: "alpine:3.19", Status: models.SandboxStatusStarted,
		PublicURL: "http://x/sb-api", ContainerID: "c", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		Env:       map[string]string{"E": "1"},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := svc.persistSandboxCreate(ctx, sb); err != nil {
		t.Fatalf("persist: %v", err)
	}

	got, err := svc.GetSandbox(ctx, "sb-api")
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if len(got.Env) != 0 {
		t.Fatalf("GetSandbox default Env = %+v", got.Env)
	}

	listed, err := svc.ListSandboxes(ctx, nil)
	if err != nil {
		t.Fatalf("ListSandboxes: %v", err)
	}
	if len(listed) != 1 || len(listed[0].Env) != 0 {
		t.Fatalf("ListSandboxes Env = %+v", listed)
	}

	audit.mu.Lock()
	audit.events = nil
	audit.mu.Unlock()

	withEnv, err := svc.GetSandboxWithOptions(ctx, "sb-api", GetSandboxOptions{IncludeEnv: true})
	if err != nil {
		t.Fatalf("GetSandboxWithOptions: %v", err)
	}
	if withEnv.Env["E"] != "1" {
		t.Fatalf("include env = %+v", withEnv.Env)
	}
	evs := audit.Events()
	if len(evs) != 1 || evs[0].Ref != envAuditRef("sb-api") {
		t.Fatalf("include_env audit = %+v", evs)
	}
	_ = st
}

func TestRedactClusterSecretsClearsEnvWhenSealed(t *testing.T) {
	req := models.CreateSandboxRequest{
		Image: "alpine:3.19",
		Env:   map[string]string{"A": "1"},
	}
	kept := RedactClusterSecrets(req)
	if kept.Env["A"] != "1" {
		t.Fatalf("default redact should keep Env: %+v", kept.Env)
	}
	cleared := RedactClusterSecretsOpts(req, true)
	if cleared.Env != nil {
		t.Fatalf("sealEnv redact Env = %+v, want nil", cleared.Env)
	}
}

func TestMergeClusterSecretsRestoresEnv(t *testing.T) {
	redacted := models.CreateSandboxRequest{Image: "alpine:3.19", Env: nil}
	merged := mergeClusterSecrets(redacted, secrets.Secrets{Env: map[string]string{"K": "v"}})
	if merged.Env["K"] != "v" {
		t.Fatalf("merge Env = %+v", merged.Env)
	}
}

func TestSecretsFromRequestIncludesEnvWhenFlagOn(t *testing.T) {
	req := models.CreateSandboxRequest{Env: map[string]string{"A": "1"}}
	off := (&Service{}).secretsFromRequest(req)
	if !off.IsEmpty() {
		t.Fatalf("flag-off bag should be empty, got %+v", off)
	}
	on := (&Service{cfg: config.Config{SecretEnvSealEnabled: true}}).secretsFromRequest(req)
	if on.IsEmpty() || on.Env["A"] != "1" {
		t.Fatalf("flag-on bag = %+v", on)
	}
}

func TestLocalProviderEnvUsesRefVersionEnv(t *testing.T) {
	ctx := context.Background()
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	mem := &memBlobStore{byRef: map[string]secrets.SecretBlob{}}
	p := secrets.NewLocalProvider(cipher, mem)
	h, err := p.Put(ctx, "sb-v2", secrets.Secrets{Env: map[string]string{"E": "1"}}, []string{"n1"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if h.Version != secrets.RefVersionEnv {
		t.Fatalf("version = %d, want %d", h.Version, secrets.RefVersionEnv)
	}
	got, err := p.Open(ctx, "sb-v2", h, "n1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Env["E"] != "1" {
		t.Fatalf("Open env = %+v", got.Env)
	}

	// Loud reject for unsupported future versions.
	if _, err := p.Open(ctx, "sb-v2", secrets.Handle{Ref: h.Ref, Version: secrets.MaxSupportedRefVersion + 1}, "n1"); !errors.Is(err, secrets.ErrVersionMismatch) {
		t.Fatalf("unsupported version err = %v", err)
	}
}

func TestPersistSandboxCreateFlagOffSkipsPutEnv(t *testing.T) {
	svc, st, _ := testEnvService(t, false)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-off", Image: "alpine:3.19", Status: models.SandboxStatusStarted,
		PublicURL: "http://x/sb-off", ContainerID: "c", ContainerIP: "10.0.0.1",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		Env:       map[string]string{"A": "1"},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := svc.persistSandboxCreate(ctx, sb); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if _, err := st.GetEnv(ctx, "sb-off"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("flag-off should not write sandbox_env: %v", err)
	}
}

func TestOpenClusterSecretsMergesEnv(t *testing.T) {
	svc, _, _ := testEnvService(t, true)
	ctx := context.Background()
	req := models.CreateSandboxRequest{
		Image: "alpine:3.19",
		Env:   map[string]string{"RECREATE": "yes"},
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-open", req, []string{"node-a"}, SealStrict)
	if err != nil {
		t.Fatalf("SealAndDistribute: %v", err)
	}
	if handle.Version != secrets.RefVersionEnv {
		t.Fatalf("handle version = %d", handle.Version)
	}
	redacted := svc.redactClusterSecrets(req)
	if redacted.Env != nil {
		t.Fatalf("redacted Env = %+v", redacted.Env)
	}
	opened, err := svc.OpenClusterSecretsForNode(ctx, "sb-open", redacted, handle, "node-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.Env["RECREATE"] != "yes" {
		t.Fatalf("opened Env = %+v", opened.Env)
	}
}

// memBlobStore is a tiny in-memory secrets.BlobStore for provider tests.
type memBlobStore struct {
	byRef map[string]secrets.SecretBlob
}

func (m *memBlobStore) Put(_ context.Context, rec secrets.SecretBlob) error {
	m.byRef[rec.Ref] = rec
	return nil
}
func (m *memBlobStore) Get(_ context.Context, ref string) (*secrets.SecretBlob, error) {
	rec, ok := m.byRef[ref]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	cp := rec
	return &cp, nil
}
func (m *memBlobStore) DeleteForSandbox(_ context.Context, sandboxID string) error {
	for ref, rec := range m.byRef {
		if rec.SandboxID == sandboxID {
			delete(m.byRef, ref)
		}
	}
	return nil
}
