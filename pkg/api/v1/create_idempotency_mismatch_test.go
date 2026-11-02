package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func postCreate(t *testing.T, h *handlers, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	h.createSandbox(rr, req)
	return rr
}

func createdID(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp models.CreateSandboxResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	return resp.ID
}

// assertKeyReused checks the refusal: 422, the code, the key named, and not
// a field of the sandbox.
func assertKeyReused(t *testing.T, rr *httptest.ResponseRecorder, key string) {
	t.Helper()
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["code"] != models.ErrorCodeIdempotencyKeyReused {
		t.Fatalf("code = %v, want %s", body["code"], models.ErrorCodeIdempotencyKeyReused)
	}
	if want := "Idempotency-Key \"" + key + "\" was already used with a different request"; body["error"] != want {
		t.Fatalf("error = %v, want %q", body["error"], want)
	}
	if len(body) != 2 {
		t.Fatalf("the refusal carries more than the error: %s", rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "" {
		t.Fatal("a refusal that cannot succeed on retry says Retry-After")
	}
}

func TestCreateSandbox_IdempotencyKeyMismatch(t *testing.T) {
	const first = `{"image":"alpine:3.20","env":{"OPENAI_API_KEY":"sk-old","REGION":"eu"},"tags":{"a":"1","b":"2"}}`
	tests := []struct {
		name   string
		retry  string
		replay bool
	}{
		{name: "same request", retry: first, replay: true},
		{name: "reordered map keys and whitespace", retry: `{ "tags":{"b":"2","a":"1"}, "env":{"REGION":"eu","OPENAI_API_KEY":"sk-old"}, "image":"alpine:3.20" }`, replay: true},
		{name: "a client-supplied digest is ignored", retry: `{"image":"alpine:3.20","env":{"OPENAI_API_KEY":"sk-old","REGION":"eu"},"tags":{"a":"1","b":"2"},"create_request_digests":["hmac:0:00"]}`, replay: true},
		{name: "changed env", retry: `{"image":"alpine:3.20","env":{"OPENAI_API_KEY":"sk-new","REGION":"eu"},"tags":{"a":"1","b":"2"}}`},
		{name: "changed image", retry: `{"image":"alpine:3.21","env":{"OPENAI_API_KEY":"sk-old","REGION":"eu"},"tags":{"a":"1","b":"2"}}`},
		{name: "a field added", retry: `{"image":"alpine:3.20","env":{"OPENAI_API_KEY":"sk-old","REGION":"eu"},"tags":{"a":"1","b":"2"},"cpu":2}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &apiRecordingRuntime{}
			h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
			rr := postCreate(t, h, "job-42", first)
			if rr.Code != http.StatusCreated {
				t.Fatalf("first create = %d; body=%s", rr.Code, rr.Body.String())
			}
			id := createdID(t, rr)
			stored, err := st.GetCreateRequestDigest(t.Context(), id)
			if err != nil || !strings.HasPrefix(stored, "hmac:") {
				t.Fatalf("stored digest = %q, %v", stored, err)
			}
			if strings.Contains(stored, "sk-old") {
				t.Fatal("the stored digest holds the env")
			}

			rr = postCreate(t, h, "job-42", tt.retry)
			if tt.replay {
				if rr.Code != http.StatusCreated || createdID(t, rr) != id {
					t.Fatalf("retry = %d %s; want a replay of %s", rr.Code, rr.Body.String(), id)
				}
			} else {
				assertKeyReused(t, rr, "job-42")
			}
			if rt.createCalls != 1 {
				t.Fatalf("runtime creates = %d, want 1", rt.createCalls)
			}
		})
	}
}

// A create without a key stores no digest, and a sandbox made by a server
// that kept none (an upgrade) still replays for its key.
func TestCreateSandbox_IdempotencyKeyLegacyRowReplays(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	rr := postCreate(t, h, "", `{"image":"alpine:3.20"}`)
	if got, _ := st.GetCreateRequestDigest(t.Context(), createdID(t, rr)); got != "" {
		t.Fatalf("an unkeyed create stored digest %q", got)
	}

	id := clustercreate.DeterministicSandboxID("", "old-key")
	if _, err := h.deps.Service.CreateSandboxWithID(t.Context(), models.CreateSandboxRequest{Image: "alpine:3.20"}, id); err != nil {
		t.Fatalf("seed a row without a digest: %v", err)
	}
	rr = postCreate(t, h, "old-key", `{"image":"alpine:3.21"}`)
	if rr.Code != http.StatusCreated || createdID(t, rr) != id {
		t.Fatalf("retry of a pre-digest row = %d %s; want a replay of %s", rr.Code, rr.Body.String(), id)
	}
}

// The router digests the client's request before its defaults and sends the
// digests on: in the forwarded body, and in the reserved spec.
func TestClusterCreateWrap_ForwardsTheClientRequestDigests(t *testing.T) {
	rt := &apiRecordingRuntime{}
	fake := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	h, _ := newClusterCreateHarness(t, rt, fake)
	post := func(body string) []string {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
		req.Header.Set("Idempotency-Key", "job-9")
		h.clusterCreateWrap(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
		}
		var forwarded models.CreateSandboxRequest
		if err := json.Unmarshal([]byte(fake.forwardedBody), &forwarded); err != nil {
			t.Fatalf("forwarded body: %v", err)
		}
		reserved := fake.reserveCalls[len(fake.reserveCalls)-1].redacted
		if len(forwarded.CreateRequestDigests) == 0 || reserved == nil || strings.Join(reserved.CreateRequestDigests, ",") != strings.Join(forwarded.CreateRequestDigests, ",") {
			t.Fatalf("forwarded digests %q, reserved %+v", forwarded.CreateRequestDigests, reserved)
		}
		return forwarded.CreateRequestDigests
	}
	a := post(`{"image":"alpine:3.20","env":{"A":"1","B":"2"}}`)
	b := post(`{"env":{"B":"2","A":"1"},"image":"alpine:3.20"}`)
	c := post(`{"image":"alpine:3.20","env":{"A":"1","B":"3"}}`)
	if a[0] != b[0] || a[0] == c[0] {
		t.Fatalf("digests: same request %q / %q, different %q", a[0], b[0], c[0])
	}
}

// On the owner, a forwarded create keeps the router's digests (its body has
// the router's defaults applied, so it is never digested again), and a
// forwarded retry with a different request is refused without touching the
// first sandbox.
func TestClusterCreateWrap_ForwardedRetryWithAReusedKey(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, st := newClusterCreateHarness(t, rt, stub)
	id := clustercreate.DeterministicSandboxID("", "job-77")
	if _, err := h.deps.Service.CreateSandboxWithID(service.WithIdempotencyKey(t.Context(), "job-77"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}, id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	forward := func(digests string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20","create_request_digests":`+digests+`}`))
		req.Header.Set("Idempotency-Key", "job-77")
		req.Header.Set(clustercreate.HeaderTarget, "node-a")
		req.Header.Set(clustercreate.HeaderID, id)
		h.clusterCreateWrap(rr, req)
		return rr
	}
	if rr := forward(`["hmac:0:aaaa"]`); rr.Code != http.StatusCreated || createdID(t, rr) != id {
		t.Fatalf("forwarded retry, same request = %d %s", rr.Code, rr.Body.String())
	}
	assertKeyReused(t, forward(`["hmac:0:bbbb"]`), "job-77")
	if len(stub.cancelCalls) != 0 || len(stub.deleteCalls) != 0 || len(stub.recordCalls) != 0 {
		t.Fatalf("the refused retry cancelled %v, deleted %v or promoted %v", stub.cancelCalls, stub.deleteCalls, stub.recordCalls)
	}
	if got, _ := st.GetCreateRequestDigest(t.Context(), id); got != "hmac:0:aaaa" {
		t.Fatalf("stored digest = %q, want the first create's", got)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime creates = %d, want 1", rt.createCalls)
	}
}

// With the server key revoked a keyed create cannot be digested, so it fails
// (503 key_revoked) rather than go ahead unchecked; an unkeyed create never
// needs a digest.
func TestCreateSandbox_IdempotencyKeyWithTheServerKeyRevoked(t *testing.T) {
	ciph, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{1}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	ciph.Revoke()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Service: service.New(config.Config{}, logger, nil, nil, nil, nil, ciph, nil, nil), Logger: logger}}
	for name, call := range map[string]http.HandlerFunc{
		"single node": h.createSandbox,
		"cluster":     h.clusterCreateWrap,
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
			req.Header.Set("Idempotency-Key", "job-1")
			call(rr, req)
			if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), models.ErrorCodeKeyRevoked) {
				t.Fatalf("keyed create with the key revoked = %d %s; want 503 %s", rr.Code, rr.Body.String(), models.ErrorCodeKeyRevoked)
			}
		})
	}
}
