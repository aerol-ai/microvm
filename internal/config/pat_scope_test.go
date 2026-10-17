package config

import (
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
