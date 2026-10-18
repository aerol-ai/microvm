package apihttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCorrelationID(t *testing.T) {
	cases := []struct {
		name        string
		correlation string
		request     string
		want        string
	}{
		{"none", "", "", ""},
		{"request id only", "", " req-1 ", "req-1"},
		{"correlation id wins", "corr-1", "req-1", "corr-1"},
		{"blank correlation id falls back", "  ", "req-2", "req-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.correlation != "" {
				r.Header.Set("X-Correlation-ID", tc.correlation)
			}
			if tc.request != "" {
				r.Header.Set("X-Request-ID", tc.request)
			}
			if got := CorrelationID(r); got != tc.want {
				t.Fatalf("CorrelationID = %q, want %q", got, tc.want)
			}
		})
	}
	if got := CorrelationID(nil); got != "" {
		t.Fatalf("nil request = %q", got)
	}
}
