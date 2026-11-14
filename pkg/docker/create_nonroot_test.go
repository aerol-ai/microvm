package docker

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreate_RequireNonRootUser: with the create policy's require_non_root
// rule on, the image config's USER decides before any container exists; with
// it off, a root image starts as it always has.
func TestCreate_RequireNonRootUser(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		require  bool
		wantDeny bool
	}{
		{"root image, rule off", "", false, false},
		{"root image, rule on", "", true, true},
		{"uid 0 image, rule on", "0:0", true, true},
		{"named user, rule on", "app", true, true},
		{"numeric non-root, rule on", "1000:1000", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDaemon{t: t,
				imageInspect: func() *http.Response {
					return jsonResponse(http.StatusOK, map[string]any{"Id": "sha256:img", "Config": map[string]any{"User": tc.user}})
				},
				create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
				start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
			}
			c := newCreateClient(t, d, true, nil)
			_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "acme/app:1", RequireNonRootUser: tc.require}, "sb-nr", "tok", nil)
			if tc.wantDeny {
				var pe *models.CreatePolicyError
				if !errors.As(err, &pe) || pe.Rule != models.CreatePolicyRuleRequireNonRoot {
					t.Fatalf("Create = %v, want a require_non_root refusal", err)
				}
				if d.createBody != nil {
					t.Fatal("a refused image must not reach POST /containers/create")
				}
				return
			}
			if err != nil {
				t.Fatalf("Create = %v, want success", err)
			}
		})
	}
}

// TestPoolEligible_RequireNonRootUser: a parked container's user was never
// checked, so the rule sends the create down the cold path, which checks it.
func TestPoolEligible_RequireNonRootUser(t *testing.T) {
	if poolEligible(models.CreateSandboxRequest{Image: "alpine:3.20", RequireNonRootUser: true}, nil, 0) {
		t.Fatal("require_non_root must make a create ineligible for a parked slot")
	}
}
