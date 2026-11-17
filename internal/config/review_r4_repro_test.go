package config

// Round-4 review repro (issue #1349): LocalAdminURLFromEnv takes
// SB_API_PORT from the env file as written. sandboxd itself reads it with
// getEnvInt, which falls back to 21212 on anything that is not a number,
// so a value such as "21212@collector.example" leaves the node running on
// 21212 while every env-file tool (upgrade stop guard, init, join, adopt)
// builds http://127.0.0.1:21212@collector.example: "127.0.0.1:21212" is
// userinfo, and the request (with the admin token) goes to
// collector.example. FAILS on 72fd0004f. Copy into internal/config/.

import (
	"net/http"
	"testing"
)

func TestReviewR4EnvAPIPortStaysOnLoopback(t *testing.T) {
	base := LocalAdminURLFromEnv(func(k string) string {
		return map[string]string{"SB_API_PORT": "21212@collector.example"}[k]
	})
	req, err := http.NewRequest(http.MethodGet, base+"/v1/cluster/members", nil)
	if err != nil {
		t.Fatalf("%s: %v", base, err)
	}
	if h := req.URL.Hostname(); h != "127.0.0.1" && h != "::1" {
		t.Errorf("the admin token goes to %q (URL %s)", h, req.URL.Redacted())
	}
}
