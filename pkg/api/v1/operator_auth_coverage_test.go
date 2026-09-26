package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestWithAuthOperatorNilAuthAndTenant(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := withAuthOperator(Deps{}, next)

	deny := httptest.NewRecorder()
	h.ServeHTTP(deny, httptest.NewRequest(http.MethodGet, "/", nil))
	if deny.Code != http.StatusForbidden {
		t.Fatalf("no access status = %d", deny.Code)
	}

	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	okReq = okReq.WithContext(controlplane.ContextWithAccess(okReq.Context(), controlplane.Access{Operator: true}))
	okRR := httptest.NewRecorder()
	h.ServeHTTP(okRR, okReq)
	if okRR.Code != http.StatusNoContent {
		t.Fatalf("operator status = %d", okRR.Code)
	}
}
