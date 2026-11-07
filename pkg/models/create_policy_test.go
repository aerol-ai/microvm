package models

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckImageUserNonRoot(t *testing.T) {
	cases := []struct {
		user    string
		wantErr string // "" = allowed
	}{
		{"1000", ""},
		{"1000:1000", ""},
		{" 65532 ", ""},
		{"1000:0", ""}, // runAsNonRoot checks the uid only, like Kubernetes
		{"", "no USER"},
		{"0", "USER 0"},
		{"0:0", "USER 0:0"},
		{"root", "a name"},
		{"app", "a name"},
		{"app:app", "a name"},
		{"-1", "a name"},
		{"99999999999", "a name"}, // not a 32-bit uid
	}
	for _, tc := range cases {
		err := CheckImageUserNonRoot("example/app:1", tc.user)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("user %q: want allowed, got %v", tc.user, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("user %q: want error containing %q, got %v", tc.user, tc.wantErr, err)
			continue
		}
		if !errors.Is(err, ErrCreatePolicyDenied) {
			t.Errorf("user %q: error must match ErrCreatePolicyDenied", tc.user)
		}
		var pe *CreatePolicyError
		if !errors.As(err, &pe) || pe.Rule != CreatePolicyRuleRequireNonRoot {
			t.Errorf("user %q: error must name the require_non_root rule, got %#v", tc.user, err)
		}
		if !strings.Contains(err.Error(), `"require_non_root"`) || !strings.Contains(err.Error(), "example/app:1") {
			t.Errorf("user %q: message must name the rule and the image: %v", tc.user, err)
		}
	}
}

func TestCreatePolicyErrorIsOnlyDenied(t *testing.T) {
	err := &CreatePolicyError{Rule: "runtimes", Detail: "x"}
	if errors.Is(err, ErrRuntimeNotImplemented) {
		t.Fatal("a policy refusal must not read as another sentinel")
	}
	if got := err.Error(); got != `create refused by policy rule "runtimes": x` {
		t.Fatalf("Error() = %q", got)
	}
}
