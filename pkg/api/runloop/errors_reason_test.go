package runloop

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The reason field exists only for a D17 401; every other body is byte for
// byte what the Runloop SDKs have always parsed, retry header included.
func TestWriteErrorReason(t *testing.T) {
	cases := []struct {
		status    int
		reason    string
		want      string
		wantRetry string
	}{
		{http.StatusUnauthorized, "", `{"message":"nope"}` + "\n", ""},
		{http.StatusUnauthorized, "expired", `{"message":"nope","reason":"expired"}` + "\n", ""},
		{http.StatusConflict, "", `{"message":"nope"}` + "\n", "false"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		WriteErrorReason(rec, tc.status, "nope", tc.reason)
		if rec.Code != tc.status || rec.Body.String() != tc.want || rec.Header().Get("x-should-retry") != tc.wantRetry {
			t.Errorf("%d %q: %d %q retry=%q", tc.status, tc.reason, rec.Code, rec.Body.String(), rec.Header().Get("x-should-retry"))
		}
	}
}
