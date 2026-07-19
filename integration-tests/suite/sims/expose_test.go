//go:build integration

package sims

import (
	"testing"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// TestExposeDialTarget guards the SVC-01 regression: a TLS-SNI exposure carries
// HostPort=0 (multiplexed on :443), so the dial target must come from
// PublicURL, not Host/HostPort — probing the latter dials ":0".
func TestExposeDialTarget(t *testing.T) {
	cases := []struct {
		name     string
		in       sdktypes.ExposeResult
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "tcp uses host and hostport directly",
			in:       sdktypes.ExposeResult{Host: "ingress.example.com", HostPort: 22001, PublicURL: "tcp://ingress.example.com:22001"},
			wantHost: "ingress.example.com", wantPort: 22001,
		},
		{
			name:     "tls parses host and port from public_url",
			in:       sdktypes.ExposeResult{PublicURL: "tls://sb-abc-5432.sandbox.tvar.cc:443"},
			wantHost: "sb-abc-5432.sandbox.tvar.cc", wantPort: 443,
		},
		{
			name:     "https public_url without explicit port defaults to 443",
			in:       sdktypes.ExposeResult{PublicURL: "https://sb-abc-8080.sandbox.tvar.cc"},
			wantHost: "sb-abc-8080.sandbox.tvar.cc", wantPort: 443,
		},
		{
			name:    "no hostport and empty public_url errors",
			in:      sdktypes.ExposeResult{},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := exposeDialTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q:%d", host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("got %q:%d, want %q:%d", host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}
