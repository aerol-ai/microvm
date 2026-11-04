package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestCreateRequestDigests(t *testing.T) {
	c, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{5}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{cipher: c}
	body := []byte(`{"image":"alpine","env":{"K":"v"}}`)
	a, err := s.CreateRequestDigests("v1", body)
	if err != nil || len(a) != 1 || !strings.HasPrefix(a[0], "hmac:0:") || len(a[0]) != len("hmac:0:")+64 {
		t.Fatalf("CreateRequestDigests = %q, %v; want one hmac:0:<64 hex>", a, err)
	}
	if b, _ := s.CreateRequestDigests("v1", body); b[0] != a[0] {
		t.Fatal("the same request digests differently")
	}
	if d, _ := s.CreateRequestDigests("daytona", body); d[0] == a[0] {
		t.Fatal("two facades share a digest for one body")
	}

	// No server key: no digest, so the create replays unchecked as before.
	for name, svc := range map[string]*Service{"nil": nil, "no cipher": {}} {
		if d, err := svc.CreateRequestDigests("v1", body); d != nil || err != nil {
			t.Fatalf("%s: CreateRequestDigests = %q, %v; want none", name, d, err)
		}
	}
	c.Revoke()
	if _, err := s.CreateRequestDigests("v1", body); !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("with the key revoked: %v, want ErrKeyRevoked", err)
	}
}

func TestCreateDigestsMatch(t *testing.T) {
	tests := []struct {
		name    string
		stored  string
		request []string
		want    bool
	}{
		{name: "same request", stored: "hmac:0:aa", request: []string{"hmac:0:aa"}, want: true},
		{name: "different request", stored: "hmac:0:aa", request: []string{"hmac:0:bb"}, want: false},
		{name: "rotated: the old key still held, same request", stored: "hmac:0:aa", request: []string{"hmac:1:cc", "hmac:0:aa"}, want: true},
		{name: "rotated: the old key still held, different request", stored: "hmac:0:aa", request: []string{"hmac:1:cc", "hmac:0:bb"}, want: false},
		{name: "the stored key retired: cannot check", stored: "hmac:0:aa", request: []string{"hmac:1:cc"}, want: true},
		{name: "nothing stored", stored: "", request: []string{"hmac:0:aa"}, want: true},
		{name: "unreadable stored digest", stored: "sha:aa", request: []string{"hmac:0:aa"}, want: true},
		{name: "unreadable request digest", stored: "hmac:0:aa", request: []string{"hmac:0"}, want: true},
		{name: "empty key id", stored: "hmac::aa", request: []string{"hmac::bb"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createDigestsMatch(tt.stored, tt.request); got != tt.want {
				t.Fatalf("createDigestsMatch(%q, %q) = %v, want %v", tt.stored, tt.request, got, tt.want)
			}
		})
	}
}

func keyedCtx(key string) context.Context {
	return WithIdempotencyKey(userCtx("tenant-a"), key)
}

func TestCreateSandboxWithIDReplaysOnlyTheSameRequest(t *testing.T) {
	const id = "sb-keyed-0000001"
	d1 := []string{"hmac:0:1111"}
	d2 := []string{"hmac:0:2222"}
	tests := []struct {
		name      string
		seed      []string // digests the first create was made with; nil = a row from before digests
		retry     []string
		wantReuse bool
	}{
		{name: "same request replays", seed: d1, retry: d1},
		{name: "a different request is refused", seed: d1, retry: d2, wantReuse: true},
		{name: "a row from before digests replays", seed: nil, retry: d2},
		{name: "a retry without digests replays (no server key)", seed: d1, retry: nil},
		{name: "after a key rotation the old key decides: same", seed: d1, retry: []string{"hmac:1:9999", "hmac:0:1111"}},
		{name: "after a key rotation the old key decides: different", seed: d1, retry: []string{"hmac:1:9999", "hmac:0:2222"}, wantReuse: true},
		{name: "the seed's key retired: replays unchecked", seed: d1, retry: []string{"hmac:1:9999"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingRuntime{}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.admitter = nil
			first, err := svc.CreateSandboxWithID(keyedCtx("job-42"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: tt.seed}, id)
			if err != nil {
				t.Fatalf("first create: %v", err)
			}
			wantStored := ""
			if len(tt.seed) > 0 {
				wantStored = tt.seed[0]
			}
			if got, _ := st.GetCreateRequestDigest(t.Context(), id); got != wantStored {
				t.Fatalf("stored digest = %q, want %q", got, wantStored)
			}

			resp, err := svc.CreateSandboxWithID(keyedCtx("job-42"), models.CreateSandboxRequest{Image: "alpine:3.21", CreateRequestDigests: tt.retry}, id)
			if tt.wantReuse {
				if !errors.Is(err, models.ErrIdempotencyKeyReused) || resp != nil {
					t.Fatalf("retry = %+v, %v; want ErrIdempotencyKeyReused and no sandbox", resp, err)
				}
				if want := `Idempotency-Key "job-42" was already used with a different request`; err.Error() != want {
					t.Fatalf("error = %q, want %q", err, want)
				}
			} else if err != nil || resp.Sandbox.ID != first.Sandbox.ID {
				t.Fatalf("retry = %+v, %v; want a replay of %s", resp, err, first.Sandbox.ID)
			}
			if rt.createCalls != 1 {
				t.Fatalf("runtime creates = %d, want 1", rt.createCalls)
			}
		})
	}
}

// The owner check still answers first: another tenant's create of the id is
// "already in use", whatever its digest, so a digest says nothing about
// another tenant's sandbox.
func TestKeyedCreateKeepsTheOwnerCheckFirst(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	const id = "sb-keyed-owner01"
	if _, err := svc.CreateSandboxWithID(keyedCtx("k"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aa"}}, id); err != nil {
		t.Fatal(err)
	}
	_, err := svc.CreateSandboxWithID(userCtx("tenant-b"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:bb"}}, id)
	if !errors.Is(err, models.ErrSandboxExists) || errors.Is(err, models.ErrIdempotencyKeyReused) {
		t.Fatalf("another tenant's create = %v, want ErrSandboxExists only", err)
	}
}

// keyedHoldRuntime holds its first create until released, so a second create
// of the same id runs while the first is in flight.
type keyedHoldRuntime struct {
	*recordingRuntime
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	first   bool
}

func (b *keyedHoldRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	b.mu.Lock()
	first := !b.first
	b.first = true
	b.mu.Unlock()
	if first {
		close(b.entered)
		<-b.release
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.recordingRuntime.Create(ctx, req, id, token, binds)
}

// Two creates of one key reach the node at once with different requests: the
// first in wins, and the second is refused before it touches the runtime,
// while the first is still running and after it has finished alike.
func TestConcurrentKeyedCreatesWithDifferentRequests(t *testing.T) {
	rt := &keyedHoldRuntime{recordingRuntime: &recordingRuntime{}, entered: make(chan struct{}), release: make(chan struct{})}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/state.db", rt)
	svc.admitter = nil
	const id = "sb-keyed-race001"

	type result struct {
		resp *models.CreateSandboxResponse
		err  error
	}
	firstDone := make(chan result, 1)
	go func() {
		resp, err := svc.CreateSandboxWithID(keyedCtx("job-7"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}, id)
		firstDone <- result{resp, err}
	}()
	<-rt.entered

	if _, err := svc.CreateSandboxWithID(keyedCtx("job-7"), models.CreateSandboxRequest{Image: "alpine:3.21", CreateRequestDigests: []string{"hmac:0:bbbb"}}, id); !errors.Is(err, models.ErrIdempotencyKeyReused) {
		t.Fatalf("second create while the first runs = %v, want ErrIdempotencyKeyReused", err)
	}

	close(rt.release)
	first := <-firstDone
	if first.err != nil || first.resp.Sandbox.ID != id {
		t.Fatalf("first create = %+v, %v; want it to win", first.resp, first.err)
	}
	if _, err := svc.CreateSandboxWithID(keyedCtx("job-7"), models.CreateSandboxRequest{Image: "alpine:3.21", CreateRequestDigests: []string{"hmac:0:bbbb"}}, id); !errors.Is(err, models.ErrIdempotencyKeyReused) {
		t.Fatalf("second create after the first = %v, want ErrIdempotencyKeyReused", err)
	}
	if got, _ := st.GetCreateRequestDigest(t.Context(), id); got != "hmac:0:aaaa" {
		t.Fatalf("stored digest = %q, want the first create's", got)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime creates = %d, want 1", rt.createCalls)
	}
}

// A create that only finds the sandbox when its runtime create or row insert
// collides is held to the same rule.
func TestDuplicateCreateReplaysCheckTheDigest(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	const id = "sb-keyed-dup0001"
	if _, err := svc.CreateSandboxWithID(keyedCtx("k"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}, id); err != nil {
		t.Fatal(err)
	}
	same := withCreateRequestDigests(keyedCtx("k"), []string{"hmac:0:aaaa"})
	other := withCreateRequestDigests(keyedCtx("k"), []string{"hmac:0:bbbb"})
	for name, call := range map[string]func(context.Context) (*models.CreateSandboxResponse, error){
		"runtime collision": func(ctx context.Context) (*models.CreateSandboxResponse, error) {
			return svc.handleDuplicateCreateAfterRuntime(ctx, id, docker.ErrSandboxContainerExists)
		},
		"row collision": func(ctx context.Context) (*models.CreateSandboxResponse, error) {
			return svc.handleDuplicateStoreCreate(ctx, id, models.ErrSandboxExists)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if resp, err := call(same); err != nil || resp.Sandbox.ID != id {
				t.Fatalf("same request = %+v, %v; want a replay", resp, err)
			}
			if resp, err := call(other); !errors.Is(err, models.ErrIdempotencyKeyReused) || resp != nil {
				t.Fatalf("different request = %+v, %v; want ErrIdempotencyKeyReused", resp, err)
			}
			if resp, err := call(t.Context()); err != nil || resp.Sandbox.ID != id {
				t.Fatalf("no digests = %+v, %v; want a replay", resp, err)
			}
		})
	}
}

func TestBeginSandboxCreate(t *testing.T) {
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, rt)

	// No id (a generated one): nothing to hold.
	ctx, release, err := svc.BeginSandboxCreate(t.Context(), "", []string{"hmac:0:aa"})
	if err != nil || ctx != t.Context() {
		t.Fatalf("no id = %v", err)
	}
	release()

	// No digests: the lease is held, unchecked.
	ctx, release, err = svc.BeginSandboxCreate(t.Context(), "sb-x", nil)
	if err != nil || createRequestDigestsFrom(ctx) != nil || !svc.createLeases.held("sb-x") {
		t.Fatalf("unkeyed = %v, digests %q, held %v", err, createRequestDigestsFrom(ctx), svc.createLeases.held("sb-x"))
	}
	release()
	if svc.createLeases.held("sb-x") {
		t.Fatal("the lease outlived its release")
	}

	// An outer take and the inner create of the same request share one lease.
	outer, releaseOuter, err := svc.BeginSandboxCreate(keyedCtx("k"), "sb-x", []string{"hmac:0:aa"})
	if err != nil {
		t.Fatal(err)
	}
	if got := createRequestDigestsFrom(outer); len(got) != 1 || got[0] != "hmac:0:aa" {
		t.Fatalf("outer digests = %q", got)
	}
	if _, releaseInner, err := svc.BeginSandboxCreate(outer, "sb-x", []string{"hmac:0:aa"}); err != nil {
		t.Fatalf("inner take = %v", err)
	} else {
		releaseInner()
	}
	if _, releaseInner, err := svc.beginCreateLease(outer, "sb-x", []string{"hmac:0:aa"}); err != nil {
		t.Fatalf("inner lease = %v", err)
	} else {
		releaseInner()
	}
	if !svc.createLeases.held("sb-x") {
		t.Fatal("an inner release gave the outer lease back")
	}
	if _, _, err := svc.BeginSandboxCreate(keyedCtx("k"), "sb-x", []string{"hmac:0:bb"}); !errors.Is(err, models.ErrIdempotencyKeyReused) {
		t.Fatalf("a different request during the outer lease = %v", err)
	}
	releaseOuter()

	// A store that cannot answer fails the create rather than skip the check.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.BeginSandboxCreate(keyedCtx("k"), "sb-y", []string{"hmac:0:aa"}); err == nil {
		t.Fatal("a create was admitted without reading the stored digest")
	}
	if err := svc.checkStoredCreateDigest(withCreateRequestDigests(t.Context(), []string{"hmac:0:aa"}), "sb-y"); err == nil {
		t.Fatal("a duplicate replay was admitted without reading the stored digest")
	}
	// The failed read gave its lease back.
	if svc.createLeases.held("sb-y") {
		t.Fatal("a failed admission kept its lease")
	}
}

func TestKeyReusedErrorWithoutAKey(t *testing.T) {
	if withCreateRequestDigests(t.Context(), nil) != t.Context() {
		t.Fatal("an empty digest list was recorded")
	}
	err := keyReusedError(t.Context())
	if !errors.Is(err, models.ErrIdempotencyKeyReused) || err.Error() != "Idempotency-Key was already used with a different request" {
		t.Fatalf("error = %v", err)
	}
	if WithIdempotencyKey(t.Context(), "  ") != t.Context() {
		t.Fatal("a blank key was recorded")
	}
}
