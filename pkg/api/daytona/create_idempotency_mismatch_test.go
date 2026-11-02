package daytona

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

func daytonaPost(t *testing.T, h *handlers, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	h.createSandbox(rr, req)
	return rr
}

// A Daytona create reusing its Idempotency-Key with a different request gets
// 422 idempotency_key_reused and no sandbox; the same request, however its
// labels are ordered, replays.
func TestDaytonaCreateSandbox_IdempotencyKeyMismatch(t *testing.T) {
	const first = `{"snapshot":"alpine:3.20","env":{"OPENAI_API_KEY":"sk-old","REGION":"eu"},"labels":{"team":"a","tier":"x"}}`
	tests := []struct {
		name   string
		retry  string
		replay bool
	}{
		{name: "same request", retry: first, replay: true},
		{name: "reordered map keys", retry: `{"labels":{"tier":"x","team":"a"},"env":{"REGION":"eu","OPENAI_API_KEY":"sk-old"},"snapshot":"alpine:3.20"}`, replay: true},
		{name: "changed env", retry: `{"snapshot":"alpine:3.20","env":{"OPENAI_API_KEY":"sk-new","REGION":"eu"},"labels":{"team":"a","tier":"x"}}`},
		{name: "changed image", retry: `{"snapshot":"alpine:3.21","env":{"OPENAI_API_KEY":"sk-old","REGION":"eu"},"labels":{"team":"a","tier":"x"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newDaytonaContractEnv(t)
			h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
			rr := daytonaPost(t, h, "job-42", first)
			if rr.Code != http.StatusCreated {
				t.Fatalf("first create = %d; body=%s", rr.Code, rr.Body.String())
			}
			var created sandboxResponse
			_ = json.Unmarshal(rr.Body.Bytes(), &created)
			if got, err := env.store.GetCreateRequestDigest(t.Context(), created.ID); err != nil || !strings.HasPrefix(got, "hmac:") {
				t.Fatalf("stored digest = %q, %v", got, err)
			}

			rr = daytonaPost(t, h, "job-42", tt.retry)
			if tt.replay {
				var again sandboxResponse
				_ = json.Unmarshal(rr.Body.Bytes(), &again)
				if rr.Code != http.StatusCreated || again.ID != created.ID {
					t.Fatalf("retry = %d %s; want a replay of %s", rr.Code, rr.Body.String(), created.ID)
				}
			} else {
				var body map[string]any
				_ = json.Unmarshal(rr.Body.Bytes(), &body)
				if rr.Code != http.StatusUnprocessableEntity || body["code"] != models.ErrorCodeIdempotencyKeyReused ||
					body["error"] != `Idempotency-Key "job-42" was already used with a different request` || len(body) != 2 {
					t.Fatalf("retry = %d %s; want 422 idempotency_key_reused naming the key", rr.Code, rr.Body.String())
				}
			}
			if n := countSandboxes(t, env); n != 1 {
				t.Fatalf("sandbox count = %d, want 1", n)
			}
		})
	}
}

// The same key through v1 and through Daytona derives one sandbox id, but the
// two facades digest different request shapes, so a key reused across them is
// a different request.
func TestDaytonaCreateSandbox_KeyReusedFromAnotherFacade(t *testing.T) {
	env := newDaytonaContractEnv(t)
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	if rr := daytonaPost(t, h, "shared", `{"snapshot":"alpine:3.20"}`); rr.Code != http.StatusCreated {
		t.Fatalf("first = %d", rr.Code)
	}
	v1Digests, err := env.service.CreateRequestDigests("v1", []byte(`{"snapshot":"alpine:3.20"}`))
	if err != nil {
		t.Fatal(err)
	}
	daytonaDigests, err := env.service.CreateRequestDigests("daytona", []byte(`{"snapshot":"alpine:3.20"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v1Digests[0] == daytonaDigests[0] {
		t.Fatal("v1 and Daytona share a digest for one body")
	}
}

// A forwarded Daytona create carries the client's original body, so the
// owner digests it exactly as the router would: a forwarded retry with a
// different request is refused there, and the same request replays.
func TestDaytonaForwardedRetryWithAReusedKey(t *testing.T) {
	env := newDaytonaContractEnv(t)
	env.service.AttachCluster(&daytonaForwardCluster{Noop: cluster.NewNoop("owner", "http://owner", "")})
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	const id = "sb-0123456789abcdef"
	forward := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
		req.Header.Set("Idempotency-Key", "job-5")
		req.Header.Set(clustercreate.HeaderTarget, "owner")
		req.Header.Set(clustercreate.HeaderID, id)
		h.createSandbox(rr, req)
		return rr
	}
	if rr := forward(`{"snapshot":"alpine:3.20","env":{"K":"1"}}`); rr.Code != http.StatusCreated {
		t.Fatalf("first forwarded create = %d %s", rr.Code, rr.Body.String())
	}
	if rr := forward(`{"env":{"K":"1"},"snapshot":"alpine:3.20"}`); rr.Code != http.StatusCreated {
		t.Fatalf("forwarded retry, same request = %d %s", rr.Code, rr.Body.String())
	}
	rr := forward(`{"snapshot":"alpine:3.20","env":{"K":"2"}}`)
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), models.ErrorCodeIdempotencyKeyReused) {
		t.Fatalf("forwarded retry, different request = %d %s; want 422", rr.Code, rr.Body.String())
	}
	if n := countSandboxes(t, env); n != 1 {
		t.Fatalf("sandbox count = %d, want 1", n)
	}
}

// With the server key revoked a keyed Daytona create fails instead of going
// ahead unchecked.
func TestDaytonaCreateSandbox_IdempotencyKeyWithTheServerKeyRevoked(t *testing.T) {
	ciph, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{1}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	ciph.Revoke()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Service: service.New(config.Config{}, logger, nil, nil, nil, nil, ciph, nil, nil), Logger: logger}}
	rr := daytonaPost(t, h, "job-1", `{"snapshot":"alpine:3.20"}`)
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), models.ErrorCodeKeyRevoked) {
		t.Fatalf("keyed create with the key revoked = %d %s; want 503", rr.Code, rr.Body.String())
	}
}
