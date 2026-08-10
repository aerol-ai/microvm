package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestClassifySecretAuditReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, secretAuditReasonOK},
		{secrets.ErrNotFound, secretAuditReasonNotFound},
		{fmt.Errorf("%w: ref", secrets.ErrNotFound), secretAuditReasonNotFound},
		{secrets.ErrRecipientDenied, secretAuditReasonRecipientDenied},
		{secrets.ErrVersionMismatch, secretAuditReasonVersionMismatch},
		{secrets.ErrDecryptFailed, secretAuditReasonDecryptFailed},
		{errors.New("decrypt: message authentication failed"), secretAuditReasonDecryptFailed},
		{errors.New("something else"), secretAuditReasonError},
	}
	for _, tc := range cases {
		if got := classifySecretAuditReason(tc.err); got != tc.want {
			t.Fatalf("classifySecretAuditReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestSandboxIDFromSecretRef(t *testing.T) {
	if got := sandboxIDFromSecretRef("cluster-secret://sandbox/sb-1/v1"); got != "sb-1" {
		t.Fatalf("got %q, want sb-1", got)
	}
	if got := sandboxIDFromSecretRef("not-a-ref"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestEmitSecretAuditNilSinkNoPanic(t *testing.T) {
	emitSecretAudit(nil, "sb", "ref", "node-a", "", nil)
	var sink SecretAuditSink
	emitSecretAudit(sink, "sb", "ref", "node-a", "", secrets.ErrNotFound)
	beginSecretAudit(nil, "sb", "ref", "node-a", "")(nil)
}

func TestSecretAuditStrictBootAndUnavailableSink(t *testing.T) {
	s := &Service{cfg: config.Config{SecretAuditStrictBoot: true}}
	if err := s.ValidateSecretAuditSink(); err == nil {
		t.Fatal("ValidateSecretAuditSink error = nil, want missing DBPath failure")
	}
	before := auditEventsDroppedTotal.Value()
	s.secretAuditSink().Emit(SecretAuditEvent{SandboxID: "sb"})
	if got := auditEventsDroppedTotal.Value() - before; got != 1 {
		t.Fatalf("dropped delta = %d, want 1", got)
	}
	if got := secretAuditSinkHealthy.Value(); got != 0 {
		t.Fatalf("sink health = %d, want 0", got)
	}
}

func TestSecretAuditSuccessAndFailureClasses(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mem := &memSecretAuditSink{}
	cipher := newTestCipher(t)
	s := &Service{
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		secretAudit:    mem,
		cluster:        cluster.NewNoop("node-a", "", ""),
	}

	const password = "super-secret-password-value"
	req := models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: password},
	}
	handle, err := s.SealAndDistribute(ctx, "sb-audit", req, []string{"node-a"}, SealStrict)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	redacted := RedactClusterSecrets(req)

	// success
	if _, err := s.OpenClusterSecretsForNode(ctx, "sb-audit", redacted, handle, "node-a"); err != nil {
		t.Fatalf("open success: %v", err)
	}
	// recipient denied
	if _, err := s.OpenClusterSecretsForNode(ctx, "sb-audit", redacted, handle, "node-b"); err == nil {
		t.Fatal("expected recipient denied")
	}
	// version mismatch
	badVer := handle
	badVer.Version++
	if _, err := s.OpenClusterSecretsForNode(ctx, "sb-audit", redacted, badVer, "node-a"); err == nil {
		t.Fatal("expected version mismatch")
	}
	// not found
	missing := cluster.PlacementSecrets{Ref: "cluster-secret://sandbox/missing/v1", Version: 1}
	if _, err := s.OpenClusterSecretsForNode(ctx, "missing", redacted, missing, "node-a"); err == nil {
		t.Fatal("expected not found")
	}

	events := mem.Events()
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4: %+v", len(events), events)
	}
	want := []struct {
		result string
		reason string
	}{
		{secretAuditResultSuccess, secretAuditReasonOK},
		{secretAuditResultFailure, secretAuditReasonRecipientDenied},
		{secretAuditResultFailure, secretAuditReasonVersionMismatch},
		{secretAuditResultFailure, secretAuditReasonNotFound},
	}
	for i, w := range want {
		if events[i].Result != w.result || events[i].Reason != w.reason {
			t.Fatalf("event[%d] = {%s,%s}, want {%s,%s}", i, events[i].Result, events[i].Reason, w.result, w.reason)
		}
		if events[i].SandboxID == "" || events[i].Ref == "" || events[i].Actor == "" {
			t.Fatalf("event[%d] missing fields: %+v", i, events[i])
		}
		raw, err := json.Marshal(events[i])
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if bytes.Contains(raw, []byte(password)) {
			t.Fatalf("event[%d] leaked plaintext password: %s", i, raw)
		}
		if bytes.Contains(raw, []byte("not allowed")) || bytes.Contains(raw, []byte("version mismatch:")) {
			t.Fatalf("event[%d] leaked wrapped error string: %s", i, raw)
		}
	}
}

func TestSecretAuditDecryptFailedClass(t *testing.T) {
	mem := &memSecretAuditSink{}
	s := &Service{
		cipher:      newTestCipher(t),
		secretAudit: mem,
		cluster:     cluster.NewNoop("node-a", "", ""),
	}
	_, err := s.UnsealRegistry("sb-reg", []byte("not-valid-ciphertext"))
	if err == nil {
		t.Fatal("expected decrypt failure")
	}
	if !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("err = %v, want ErrDecryptFailed", err)
	}
	events := mem.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Result != secretAuditResultFailure || events[0].Reason != secretAuditReasonDecryptFailed {
		t.Fatalf("event = %+v", events[0])
	}
	if events[0].Ref != "registry:sb-reg" {
		t.Fatalf("ref = %q", events[0].Ref)
	}
}

func TestSecretAuditLoadMounts(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mem := &memSecretAuditSink{}
	s := &Service{
		cipher:      newTestCipher(t),
		store:       st,
		secretAudit: mem,
		cluster:     cluster.NewNoop("node-a", "", ""),
	}
	const secret = "mount-password-should-not-appear"
	sealed, err := s.sealMounts([]models.MountSpec{{
		Type:        models.MountTypeS3,
		Target:      "/data",
		Source:      "bucket",
		Credentials: map[string]string{"password": secret},
	}})
	if err != nil {
		t.Fatalf("sealMounts: %v", err)
	}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-mnt", Image: "alpine", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.PutMounts(ctx, "sb-mnt", sealed); err != nil {
		t.Fatalf("PutMounts: %v", err)
	}
	got, err := s.loadMounts(ctx, "sb-mnt")
	if err != nil {
		t.Fatalf("loadMounts: %v", err)
	}
	if len(got) != 1 || got[0].Credentials["password"] != secret {
		t.Fatalf("mounts = %+v", got)
	}
	events := mem.Events()
	if len(events) != 1 || events[0].Result != secretAuditResultSuccess {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Ref != "mounts:sb-mnt" {
		t.Fatalf("ref = %q", events[0].Ref)
	}
	raw, _ := json.Marshal(events[0])
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatalf("leaked mount secret: %s", raw)
	}
}

func TestFileAuditSinkOverflowDropsWithGapMarker(t *testing.T) {
	dir := t.TempDir()
	sink, err := newFileAuditSink(dir, 1)
	if err != nil {
		t.Fatalf("newFileAuditSink: %v", err)
	}
	block := make(chan struct{})
	started := make(chan struct{})
	var startOnce sync.Once
	sink.writeHook = func() {
		startOnce.Do(func() { close(started) })
		<-block
	}

	droppedBefore := auditEventsDroppedTotal.Value()
	sink.Emit(SecretAuditEvent{Result: secretAuditResultSuccess, Reason: secretAuditReasonOK, Ref: "a"})
	<-started // writer blocked inside writeHook with channel empty

	sink.Emit(SecretAuditEvent{Result: secretAuditResultSuccess, Reason: secretAuditReasonOK, Ref: "b"}) // fills buffer
	sink.Emit(SecretAuditEvent{Result: secretAuditResultSuccess, Reason: secretAuditReasonOK, Ref: "c"}) // drop
	if got := auditEventsDroppedTotal.Value() - droppedBefore; got != 1 {
		t.Fatalf("dropped delta = %d, want 1", got)
	}

	close(block)
	sink.Sync()
	sink.Close()

	raw, err := os.ReadFile(filepath.Join(dir, secretAuditFileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := nonEmptyLines(string(raw))
	var sawGap bool
	for _, line := range lines {
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		if ev.Result == secretAuditResultGap && ev.Reason == secretAuditReasonOverflow {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected gap marker in stream, got:\n%s", raw)
	}
}

func TestFileAuditSinkEmitAsyncWhenWriterBlocked(t *testing.T) {
	dir := t.TempDir()
	sink, err := newFileAuditSink(dir, 8)
	if err != nil {
		t.Fatalf("newFileAuditSink: %v", err)
	}
	t.Cleanup(sink.Close)

	block := make(chan struct{})
	started := make(chan struct{})
	var startOnce sync.Once
	sink.writeHook = func() {
		startOnce.Do(func() { close(started) })
		<-block
	}

	sink.Emit(SecretAuditEvent{Result: secretAuditResultSuccess, Ref: "first"})
	<-started

	done := make(chan struct{})
	go func() {
		sink.Emit(SecretAuditEvent{Result: secretAuditResultSuccess, Ref: "second"})
		close(done)
	}()
	select {
	case <-done:
		// ok — Emit returned without waiting on the blocked writer
	case <-time.After(500 * time.Millisecond):
		close(block)
		t.Fatal("Emit blocked while writer was stalled")
	}
	close(block)
	sink.Sync()
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
