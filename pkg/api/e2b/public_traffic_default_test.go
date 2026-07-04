package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// E2B sandboxes are publicly addressable by contract (getHost / per-port
// URLs), so the facade must opt in to allow_public_traffic when the client
// says nothing — the core create default is private — while still honoring an
// explicit network.allowPublicTraffic=false.
func TestE2BCreatePublicTrafficDefaults(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		body       string
		wantPublic bool
	}{
		{
			name:       "omitted network opts in to public",
			body:       `{"templateID":"base","timeout":120}`,
			wantPublic: true,
		},
		{
			name:       "explicit opt-out stays private",
			body:       `{"templateID":"base","timeout":120,"network":{"allowPublicTraffic":false}}`,
			wantPublic: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, st, handler := newE2BHandlerTestEnv(t)

			req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
			}
			var created sandboxResponse
			if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
				t.Fatalf("decode create: %v", err)
			}

			sb, err := st.Get(ctx, created.SandboxID)
			if err != nil {
				t.Fatalf("get sandbox: %v", err)
			}
			if sb.AllowPublicTraffic == nil {
				t.Fatal("stored AllowPublicTraffic is nil; the facade must send an explicit value")
			}
			if *sb.AllowPublicTraffic != tc.wantPublic {
				t.Fatalf("stored AllowPublicTraffic = %v, want %v", *sb.AllowPublicTraffic, tc.wantPublic)
			}
		})
	}
}
