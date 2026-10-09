package e2b

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
)

// TestNetworkPrecedenceMapping pins the E2B → native mapping of D4/S1.
func TestNetworkPrecedenceMapping(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	cases := []struct {
		name         string
		net          sandboxNetworkRequest
		wantBlockAll bool
		wantAllow    []string
		wantDeny     []string
	}{
		{name: "deny all alone is block-all", net: sandboxNetworkRequest{DenyOut: []string{"0.0.0.0/0"}}, wantBlockAll: true},
		{name: "allow + deny all is an allowlist", net: sandboxNetworkRequest{AllowOut: []string{"pypi.org"}, DenyOut: []string{"0.0.0.0/0"}},
			wantAllow: []string{"pypi.org"}, wantDeny: []string{"0.0.0.0/0"}},
		{name: "mixed partial lists pass through", net: sandboxNetworkRequest{AllowOut: []string{"10.1.0.0/16"}, DenyOut: []string{"10.0.0.0/8"}},
			wantAllow: []string{"10.1.0.0/16"}, wantDeny: []string{"10.0.0.0/8"}},
		{name: "allow alone stays an allowlist", net: sandboxNetworkRequest{AllowOut: []string{"*.github.com"}}, wantAllow: []string{"*.github.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := tc.net
			req, _, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
				TemplateID: "base", Timeout: intPtr(60), Network: &n,
			})
			if err != nil {
				t.Fatal(err)
			}
			if req.NetworkBlockAll != tc.wantBlockAll {
				t.Fatalf("block-all = %v", req.NetworkBlockAll)
			}
			if !slices.Equal(req.NetworkAllowOut, tc.wantAllow) || !slices.Equal(req.NetworkDenyOut, tc.wantDeny) {
				t.Fatalf("lists = %v / %v, want %v / %v", req.NetworkAllowOut, req.NetworkDenyOut, tc.wantAllow, tc.wantDeny)
			}
		})
	}
}
