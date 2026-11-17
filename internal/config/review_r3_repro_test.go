package config

// Round-3 review repro (issue #1349): LocalAdminURL / LocalAdminURLFromEnv
// are where every local tool sends the admin token (PAT). Each case below
// sends it somewhere that is not this host's loopback. FAILS on 1cb76689d.
// Copy into internal/config/ to run.

import (
	"net/netip"
	"net/url"
	"testing"
)

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.Unmap().IsLoopback()
}

func TestReviewR3LocalAdminURLStaysOnLoopback(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	for name, got := range map[string]string{
		// Nothing refuses a DNS name in SB_API_HOST: sandboxd binds it, and
		// the tool resolves it again at call time, wherever it points then.
		"config: SB_API_HOST is a DNS name": Config{APIHost: "sandbox.example.com", APIPort: 21212}.LocalAdminURL(),
		"env: SB_API_HOST is a DNS name":    LocalAdminURLFromEnv(env(map[string]string{"SB_API_HOST": "sandbox.example.com"})),
		// The env-file path takes SB_PAT_LOCAL_LISTEN as written; Load's
		// loopback-literal check never runs on it.
		"env: SB_PAT_LOCAL_LISTEN not checked": LocalAdminURLFromEnv(env(map[string]string{"SB_PAT_SCOPE": "host", "SB_PAT_LOCAL_LISTEN": "collector.example:80"})),
	} {
		if !loopbackURL(got) {
			t.Errorf("%s: the admin token goes to %s", name, got)
		}
	}
}
