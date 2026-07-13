package containerd

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestValidateSandboxIDRejectsTraversal(t *testing.T) {
	longID := strings.Repeat("a", 129)
	cases := []string{
		"",
		"../etc/passwd",
		"sb/../evil",
		"has space",
		longID,
	}
	for _, id := range cases {
		if err := validateSandboxID(id); err == nil {
			t.Fatalf("id %q should be rejected", id)
		}
	}
}

func TestValidateSandboxIDAcceptsSafeIDs(t *testing.T) {
	longOK := strings.Repeat("x", 64)
	cases := []string{"sb-1", "cluster-create-id", "a_b-c", longOK}
	for _, id := range cases {
		if err := validateSandboxID(id); err != nil {
			t.Fatalf("id %q should be accepted: %v", id, err)
		}
	}
}

func TestBuildEnvStableOrdering(t *testing.T) {
	req := models.CreateSandboxRequest{Env: map[string]string{"Z": "1", "A": "2"}}
	for i := 0; i < 5; i++ {
		env := buildEnv(req, "sb", "tok", 2280)
		prev := ""
		for _, e := range env {
			if e < prev {
				t.Fatalf("env not sorted at iter %d: %v", i, env)
			}
			prev = e
		}
	}
}

func TestSecuritySpecOptsNonEmpty(t *testing.T) {
	opts := securitySpecOpts()
	if len(opts) == 0 {
		t.Fatal("expected security opts")
	}
}

func TestResourceSpecOptsHonorsRequest(t *testing.T) {
	req := models.CreateSandboxRequest{CPU: 2, MemoryMB: 512}
	opts := resourceSpecOpts(req)
	if len(opts) == 0 {
		t.Fatal("expected resource opts")
	}
}

func TestDriverPingWithoutClient(t *testing.T) {
	d := New(Config{}, nil, nil)
	if err := d.Ping(t.Context()); err == nil {
		t.Fatal("ping without socket should fail")
	}
}
