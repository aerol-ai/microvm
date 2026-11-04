package e2b

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The reason field exists only for a D17 401; every other body is byte for
// byte what the E2B SDK has always parsed.
func TestWriteErrorReason(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{"", `{"code":401,"message":"nope"}` + "\n"},
		{"expired", `{"code":401,"message":"nope","reason":"expired"}` + "\n"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		WriteErrorReason(rec, http.StatusUnauthorized, "nope", tc.reason)
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != tc.want || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("reason %q: %d %q", tc.reason, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusNotFound, "missing")
	if rec.Body.String() != `{"code":404,"message":"missing"}`+"\n" {
		t.Fatalf("WriteError body changed: %q", rec.Body.String())
	}
}
