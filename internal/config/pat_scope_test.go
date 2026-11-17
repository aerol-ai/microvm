package config

import (
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/volumes"
)

// TestPATScopeConfig is the §10 table for the PAT settings: every default is
// today's behavior (L8), each accepted value loads, and each refusal names
// the setting.
func TestPATScopeConfig(t *testing.T) {
	legacyScope, err := volumes.OperatorScope("", "old-pat-token")
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		scope, socket, previous, volumeScope string
		proxy                                bool
	}
	defaults := want{scope: PATScopeAny, socket: DefaultPublicAPISocket}
	volumesOn := map[string]string{"SB_PLATFORM_VOLUMES_ENABLED": "true", "SB_PLATFORM_VOLUMES_S3_BUCKET": "vols"}
	cases := []struct {
		name       string
		env        map[string]string
		enterprise bool
		want       want
		wantErr    string
	}{
		{name: "defaults are today's behavior", want: defaults},
		{name: "host scope", env: map[string]string{"SB_PAT_SCOPE": " HOST "}, want: want{scope: PATScopeHost, socket: DefaultPublicAPISocket}},
		{name: "host scope with its own socket", env: map[string]string{"SB_PAT_SCOPE": "host", "SB_PUBLIC_API_SOCKET": "/run/x/api.sock"},
			want: want{scope: PATScopeHost, socket: "/run/x/api.sock"}},
		{name: "unknown scope", env: map[string]string{"SB_PAT_SCOPE": "loopback"}, wantErr: "SB_PAT_SCOPE must be"},
		{name: "relative socket under host scope", env: map[string]string{"SB_PAT_SCOPE": "host", "SB_PUBLIC_API_SOCKET": "api.sock"},
			wantErr: "SB_PUBLIC_API_SOCKET must be an absolute path"},
		{name: "a relative socket is ignored under any scope", env: map[string]string{"SB_PUBLIC_API_SOCKET": "api.sock"},
			want: want{scope: PATScopeAny, socket: "api.sock"}},
		{name: "previous PAT", env: map[string]string{"SB_PAT_TOKEN_PREVIOUS": " old-pat-token "},
			want: want{scope: PATScopeAny, socket: DefaultPublicAPISocket, previous: "old-pat-token"}},
		{name: "pinned volume scope", env: map[string]string{"SB_OPERATOR_VOLUME_SCOPE": legacyScope},
			want: want{scope: PATScopeAny, socket: DefaultPublicAPISocket, volumeScope: legacyScope}},
		{name: "a pinned scope must stay out of the tenant namespace", env: map[string]string{"SB_OPERATOR_VOLUME_SCOPE": "t-abc"},
			wantErr: "SB_OPERATOR_VOLUME_SCOPE"},
		{name: "rotating with volumes on and no pinned scope names the value to pin",
			env:     mergeEnv(volumesOn, map[string]string{"SB_PAT_TOKEN_PREVIOUS": "old-pat-token"}),
			wantErr: "SB_OPERATOR_VOLUME_SCOPE=" + legacyScope},
		{name: "rotating with volumes on and a pinned scope loads",
			env:  mergeEnv(volumesOn, map[string]string{"SB_PAT_TOKEN_PREVIOUS": "old-pat-token", "SB_OPERATOR_VOLUME_SCOPE": legacyScope}),
			want: want{scope: PATScopeAny, socket: DefaultPublicAPISocket, previous: "old-pat-token", volumeScope: legacyScope}},
		{name: "PROXY protocol on", env: map[string]string{"SB_L4_FALLBACK_PROXY_PROTOCOL": "true"},
			want: want{scope: PATScopeAny, socket: DefaultPublicAPISocket, proxy: true}},
		{name: "a PROXY protocol typo is refused, not defaulted", env: map[string]string{"SB_L4_FALLBACK_PROXY_PROTOCOL": "on please"},
			wantErr: "SB_L4_FALLBACK_PROXY_PROTOCOL must be true or false"},
		{name: "enterprise refuses a short previous PAT", enterprise: true, env: map[string]string{"SB_PAT_TOKEN_PREVIOUS": "short"},
			wantErr: "SB_PAT_TOKEN_PREVIOUS must contain at least"},
		{name: "enterprise takes a long previous PAT", enterprise: true, env: map[string]string{"SB_PAT_TOKEN_PREVIOUS": strings.Repeat("p", minEnterpriseCredentialBytes)},
			want: want{scope: PATScopeAny, socket: DefaultPublicAPISocket, previous: strings.Repeat("p", minEnterpriseCredentialBytes)}},
	}
	keys := []string{"SB_PAT_SCOPE", "SB_PUBLIC_API_SOCKET", "SB_PAT_TOKEN_PREVIOUS", "SB_OPERATOR_VOLUME_SCOPE",
		"SB_L4_FALLBACK_PROXY_PROTOCOL", "SB_PLATFORM_VOLUMES_ENABLED", "SB_PLATFORM_VOLUMES_S3_BUCKET"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range keys {
				t.Setenv(k, tc.env[k])
			}
			if tc.enterprise {
				setSecureEnterpriseEnv(t)
			} else {
				t.Setenv("SB_ENTERPRISE_MODE", "false")
				t.Setenv("SB_PAT_TOKEN", "pat-token")
			}
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			got := want{cfg.PATScope, cfg.PublicAPISocket, cfg.PATTokenPrevious, cfg.OperatorVolumeScope, cfg.L4FallbackProxyProtocol}
			if got != tc.want {
				t.Fatalf("config = %+v, want %+v", got, tc.want)
			}
			if cfg.PATScopeHostOnly() != (tc.want.scope == PATScopeHost) {
				t.Fatalf("PATScopeHostOnly = %v for scope %q", cfg.PATScopeHostOnly(), cfg.PATScope)
			}
		})
	}
}

// TestPublicAPISocketGroupConfig: the socket's group is Caddy's by default,
// as install.sh's VM has it, and anything else given, a bare gid included
// (a Kubernetes pod's edge has no group name to look up). Blank is the
// default, never an empty group.
func TestPublicAPISocketGroupConfig(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"", DefaultPublicAPISocketGroup},
		{"   ", DefaultPublicAPISocketGroup},
		{" 65532 ", "65532"},
		{"www-data", "www-data"},
	} {
		t.Setenv("SB_ENTERPRISE_MODE", "false")
		t.Setenv("SB_PAT_TOKEN", "pat-token")
		t.Setenv("SB_PAT_SCOPE", "host")
		t.Setenv("SB_PUBLIC_API_SOCKET_GROUP", tc.env)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%q: Load: %v", tc.env, err)
		}
		if cfg.PublicAPISocketGroup != tc.want {
			t.Errorf("SB_PUBLIC_API_SOCKET_GROUP=%q: group %q, want %q", tc.env, cfg.PublicAPISocketGroup, tc.want)
		}
	}
}

// TestPATLocalListenConfig: SB_PAT_LOCAL_LISTEN (review S3) takes only a
// loopback address literal with a port no other listener uses, and only under host
// scope; unset, the API port's loopback counts as this host, as on a VM.
func TestPATLocalListenConfig(t *testing.T) {
	for _, tc := range []struct {
		scope, listen, want, wantErr string
		local                        bool
	}{
		{scope: "host", listen: "", want: ""},
		{scope: "host", listen: " 127.0.0.1:21219 ", want: "127.0.0.1:21219", local: true},
		{scope: "host", listen: "[::1]:21219", want: "[::1]:21219", local: true},
		{scope: "any", listen: "127.0.0.1:21213", wantErr: "needs SB_PAT_SCOPE=host"},
		{scope: "host", listen: "0.0.0.0:21213", wantErr: "must be 127.0.0.1:<port>"},
		{scope: "host", listen: "127.0.0.6:21213", wantErr: "must be 127.0.0.1:<port>"},
		{scope: "host", listen: "localhost:21213", wantErr: "must be 127.0.0.1:<port>"},
		{scope: "host", listen: "10.0.0.5:21213", wantErr: "must be 127.0.0.1:<port>"},
		{scope: "host", listen: "127.0.0.1", wantErr: "must be 127.0.0.1:<port>"},
		{scope: "host", listen: "127.0.0.1:0", wantErr: "must be 127.0.0.1:<port>"},
		{scope: "host", listen: "127.0.0.1:21212", wantErr: "uses the API port"},
		// Another listener's port (the chart's first choice, 21213, was the
		// gateway's ingress proxy), or Caddy's TCP port range.
		{scope: "host", listen: "127.0.0.1:21219", want: "127.0.0.1:21219", local: true},
		{scope: "host", listen: "127.0.0.1:21213", wantErr: "the port of SB_INTERNAL_INGRESS_ADDR"},
		{scope: "host", listen: "[::1]:21214", wantErr: "the port of SB_INTERNAL_L4_WAKE_ADDR"},
		{scope: "host", listen: "127.0.0.1:21215", wantErr: "the port of SB_HOSTPORT_REDIRECT_PORT"},
		{scope: "host", listen: "127.0.0.1:2019", wantErr: "the port of SB_CADDY_ADMIN_URL"},
		{scope: "host", listen: "127.0.0.1:8443", wantErr: "the port of SB_L4_TLS_FALLBACK"},
		{scope: "host", listen: "127.0.0.1:7002", wantErr: "the port of SB_CLUSTER_INTERNAL_LISTEN"},
		{scope: "host", listen: "127.0.0.1:9443", wantErr: "the port of SB_AGENT_SANDBOX_API_ADDR"},
		{scope: "host", listen: "127.0.0.1:22000", wantErr: "inside SB_L4_PORT_RANGE_START/END"},
		{scope: "host", listen: "127.0.0.1:23000", wantErr: "inside SB_L4_PORT_RANGE_START/END"},
		{scope: "host", listen: "127.0.0.1:23001", want: "127.0.0.1:23001", local: true},
	} {
		t.Setenv("SB_ENTERPRISE_MODE", "false")
		t.Setenv("SB_PAT_TOKEN", "pat-token")
		t.Setenv("SB_API_PORT", "21212")
		t.Setenv("SB_PAT_SCOPE", tc.scope)
		t.Setenv("SB_PAT_LOCAL_LISTEN", tc.listen)
		cfg, err := Load()
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s %q: err %v, want %q", tc.scope, tc.listen, err, tc.wantErr)
			}
			continue
		}
		if err != nil || cfg.PATLocalListen != tc.want || cfg.PATLocalOnly() != tc.local {
			t.Errorf("%s %q: %q local=%v %v", tc.scope, tc.listen, cfg.PATLocalListen, cfg.PATLocalOnly(), err)
		}
	}
}

// LocalAdminURL: where this node's own tools send the admin token
// (round-2 review, item 1).
func TestLocalAdminURL(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want string
	}{
		{Config{APIHost: "0.0.0.0", APIPort: 21212}, "http://127.0.0.1:21212"},
		{Config{APIHost: "::", APIPort: 21212}, "http://127.0.0.1:21212"},
		{Config{APIHost: "", APIPort: 9000}, "http://127.0.0.1:9000"},
		// Never off loopback (round 3): another address or a name falls
		// back to 127.0.0.1, so the admin token cannot leave the machine.
		{Config{APIHost: "10.0.0.5", APIPort: 21212}, "http://127.0.0.1:21212"},
		{Config{APIHost: "sandbox.example.com", APIPort: 21212}, "http://127.0.0.1:21212"},
		{Config{APIHost: "127.0.0.2", APIPort: 21212}, "http://127.0.0.1:21212"},
		{Config{APIHost: "127.0.0.1", APIPort: 9000}, "http://127.0.0.1:9000"},
		{Config{APIHost: "[::1]", APIPort: 21212}, "http://[::1]:21212"},
		{Config{APIHost: "::1", APIPort: 21212}, "http://[::1]:21212"},
		{Config{APIHost: "0.0.0.0", APIPort: 21212, PATScope: PATScopeHost, PATLocalListen: "127.0.0.1:21219"}, "http://127.0.0.1:21219"},
		{Config{APIHost: "0.0.0.0", APIPort: 21212, PATScope: PATScopeHost, PATLocalListen: "[::1]:21219"}, "http://[::1]:21219"},
		// A listener without host scope cannot happen (Load refuses it);
		// the API port is then the only place the admin token works.
		{Config{APIHost: "0.0.0.0", APIPort: 21212, PATScope: PATScopeAny, PATLocalListen: "127.0.0.1:21219"}, "http://127.0.0.1:21212"},
	} {
		if got := tc.cfg.LocalAdminURL(); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.cfg, got, tc.want)
		}
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_API_HOST": "[::]", "SB_API_PORT": " 9000 "}, "http://127.0.0.1:9000"},
		{map[string]string{"SB_PAT_SCOPE": " Host ", "SB_PAT_LOCAL_LISTEN": " 127.0.0.1:21219 "}, "http://127.0.0.1:21219"},
		{map[string]string{"SB_PAT_SCOPE": "any", "SB_PAT_LOCAL_LISTEN": "127.0.0.1:21219"}, "http://127.0.0.1:21212"},
		// The env file is read without Load's checks: the listener only as
		// Load would take it (round 3).
		{map[string]string{"SB_PAT_SCOPE": "host", "SB_PAT_LOCAL_LISTEN": "collector.example:80"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_PAT_SCOPE": "host", "SB_PAT_LOCAL_LISTEN": "10.0.0.5:21219"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_PAT_SCOPE": "host", "SB_PAT_LOCAL_LISTEN": "127.0.0.6:21219"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_PAT_SCOPE": "host", "SB_PAT_LOCAL_LISTEN": "127.0.0.1:0"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_PAT_SCOPE": "host", "SB_PAT_LOCAL_LISTEN": "[::1]:21219"}, "http://[::1]:21219"},
		{map[string]string{"SB_API_HOST": "sandbox.example.com", "SB_API_PORT": "9000"}, "http://127.0.0.1:9000"},
		// The port as sandboxd reads it, 1-65535, else 21212 (round 4):
		// nothing after it can make loopback the userinfo of another host.
		{map[string]string{"SB_API_PORT": "21212@collector.example"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_API_PORT": "21212/x@collector.example"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_API_PORT": "0"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_API_PORT": "65536"}, "http://127.0.0.1:21212"},
		{map[string]string{"SB_API_PORT": "65535"}, "http://127.0.0.1:65535"},
		{map[string]string{"SB_API_PORT": "-1"}, "http://127.0.0.1:21212"},
	} {
		if got := LocalAdminURLFromEnv(env(tc.env)); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.env, got, tc.want)
		}
	}
	// The daemon's own config, loaded as the chart sets it, agrees with the
	// env-file reading the node's other tools do.
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	t.Setenv("SB_PAT_SCOPE", "host")
	t.Setenv("SB_PAT_LOCAL_LISTEN", "127.0.0.1:21219")
	t.Setenv("SB_API_HOST", "0.0.0.0")
	t.Setenv("SB_API_PORT", "21212")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, fromEnv := cfg.LocalAdminURL(), LocalAdminURLFromEnv(os.Getenv); got != "http://127.0.0.1:21219" || fromEnv != got {
		t.Fatalf("config %s, env %s", got, fromEnv)
	}
}
