//go:build integration

package suite

// Phase 2 egress use cases (plans/egress-domain-filtering.md P2-1, P2-6,
// P2-7, P2-8): live policy updates, named profiles, learn-then-lock and the
// built-in profiles, each run with its real tool (EF-49).

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// profileName turns a test's unique name into a valid egress profile name.
func profileName(t *testing.T) string {
	t.Helper()
	n := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			return r
		}
		return '-'
	}, harness.UniqueName(sc, t))
	if len(n) > 63 {
		n = n[len(n)-63:]
	}
	return strings.TrimLeft(n, "-._")
}

// putEgressProfile stores a profile and deletes it at the end of the test,
// after the sandboxes that reference it (cleanups run last-in, first-out).
func putEgressProfile(t *testing.T, c *harness.Client, name string, allow ...string) sdktypes.EgressProfile {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := c.SDK().PutEgressProfile(ctx, name, sdktypes.EgressProfileOptions{AllowOut: allow})
	if err != nil {
		t.Fatalf("put profile %s: %v", name, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = c.SDK().DeleteEgressProfile(ctx, name)
	})
	return p
}

func setPolicy(t *testing.T, sb *microvm.Sandbox, opts sdktypes.NetworkPolicyOptions) sdktypes.NetworkPolicy {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pol, err := sb.SetNetworkPolicy(ctx, opts)
	if err != nil {
		t.Fatalf("set network policy: %v", err)
	}
	return pol
}

func fetches(t *testing.T, sb *microvm.Sandbox, url string) bool {
	t.Helper()
	rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null "+url)
	return rc == 0
}

// UC-190 (P2-1) — a running sandbox's policy changes in place: a newly
// allowed name opens, and one the new policy drops is refused.
func TestEgressLivePolicyUpdate(t *testing.T) {
	harness.Require(t, sc, "UC-190")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"pypi.org"}, nil)
	if fetches(t, sb, "https://example.com/") {
		t.Fatal("example.com must be refused before the update")
	}
	pol := setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"example.com"}})
	if pol.EgressStatus != "active" {
		t.Fatalf("egress_status after the update = %q", pol.EgressStatus)
	}
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("the newly allowed name must open without a restart")
	}
	if fetches(t, sb, "https://pypi.org/simple/") {
		t.Fatal("a name the new policy dropped must be refused")
	}
}

// UC-191 (P2-6) — a named profile: a sandbox that references it reaches its
// hosts, a profile change converges (egress_profiles_applied), and a
// referenced profile can't be deleted.
func TestEgressNamedProfile(t *testing.T) {
	harness.Require(t, sc, "UC-191")
	c := client(t)
	name := profileName(t)
	putEgressProfile(t, c, name, "example.com")
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), EgressProfiles: []string{name}})
	waitRunning(t, sb)
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("the profile's host must be reachable")
	}

	changed := putEgressProfile(t, c, name, "pypi.org")
	deadline := time.Now().Add(60 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		got, err := c.SDK().Get(ctx, sb.ID)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(got.EgressProfilesApplied, func(r sdktypes.EgressProfileRef) bool {
			return r.Name == name && r.Generation == changed.Generation
		}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("profile generation %d never applied: %+v", changed.Generation, got.EgressProfilesApplied)
		}
		time.Sleep(2 * time.Second)
	}
	if !fetches(t, sb, "https://pypi.org/simple/") || fetches(t, sb, "https://example.com/") {
		t.Fatal("the changed profile must replace the old hosts")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.SDK().DeleteEgressProfile(ctx, name); !errors.Is(err, microvm.ErrConflict) {
		t.Fatalf("deleting a referenced profile must be 409: %v", err)
	}
}

// UC-192 (EF-48, P2-7) — learn, then lock: a learn-mode run of pip records
// pypi's hosts, and the suggested list alone runs the same install while
// anything else is refused.
func TestEgressLearnThenLock(t *testing.T) {
	harness.Require(t, sc, "UC-192")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:              harness.UniqueName(sc, t),
		Image:             "python:3.12-alpine",
		NetworkEgressMode: sdktypes.NetworkEgressModeLearn,
	})
	waitRunning(t, sb)
	install := "pip install --no-cache-dir --force-reinstall -q requests"
	if rc, _ := timedRC(t, sb, install); rc != 0 {
		t.Fatalf("pip under learn mode failed (rc=%d)", rc)
	}

	var learned sdktypes.NetworkLearned
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var err error
		learned, err = sb.Learned(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(learned.SuggestedAllowOut, "pypi.org") && slices.Contains(learned.SuggestedAllowOut, "files.pythonhosted.org") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("learned list = %+v", learned)
		}
		time.Sleep(2 * time.Second)
	}

	setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: learned.SuggestedAllowOut})
	if rc, _ := timedRC(t, sb, install); rc != 0 {
		t.Fatalf("the same install must pass under the learned list (rc=%d)", rc)
	}
	if fetches(t, sb, "https://example.com/") {
		t.Fatal("a host the run never used must be refused once locked")
	}
}

// runBuiltinProfile runs a built-in profile's real tool with only that
// profile (EF-49, CEO D3), and checks the profile was pinned at create.
func runBuiltinProfile(t *testing.T, profile, image, cmd string) {
	t.Helper()
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:           harness.UniqueName(sc, t),
		Image:          image,
		EgressProfiles: []string{profile},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	got, err := c.SDK().Get(ctx, sb.ID)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EgressProfiles) != 1 || !strings.HasPrefix(got.EgressProfiles[0], profile+"@") {
		t.Fatalf("the profile must be pinned at create: %v", got.EgressProfiles)
	}
	out := egressExec(t, sb, "( "+cmd+" ) >/tmp/out 2>&1; echo rc=$?; tail -5 /tmp/out")
	if !strings.HasPrefix(out, "rc=0") {
		t.Fatalf("%s with only %s failed:\n%s", cmd, profile, out)
	}
}

// UC-193..UC-200 (EF-49, P2-8): each built-in profile with its tool.

func TestEgressBuiltinPypi(t *testing.T) {
	harness.Require(t, sc, "UC-193")
	runBuiltinProfile(t, "builtin:pypi", "python:3.12-alpine", "pip install --no-cache-dir -q requests")
}

func TestEgressBuiltinNpm(t *testing.T) {
	harness.Require(t, sc, "UC-194")
	runBuiltinProfile(t, "builtin:npm", "node:22-slim", "cd /tmp && npm install --no-audit --no-fund left-pad")
}

func TestEgressBuiltinGithub(t *testing.T) {
	harness.Require(t, sc, "UC-195")
	runBuiltinProfile(t, "builtin:github", "alpine/git:latest", "git clone -q --depth 1 https://github.com/octocat/Hello-World /tmp/hw")
}

func TestEgressBuiltinHuggingface(t *testing.T) {
	harness.Require(t, sc, "UC-196")
	runBuiltinProfile(t, "builtin:huggingface", "alpine:3.20",
		"wget -q -O /tmp/config.json https://huggingface.co/openai-community/gpt2/resolve/main/config.json")
}

func TestEgressBuiltinGolangProxy(t *testing.T) {
	harness.Require(t, sc, "UC-197")
	// Absolute paths: exec runs a login shell, and Alpine's /etc/profile
	// drops the image's PATH entries.
	runBuiltinProfile(t, "builtin:golang-proxy", "golang:1.23-alpine",
		"cd /tmp && /usr/local/go/bin/go mod init x >/dev/null 2>&1; /usr/local/go/bin/go mod download golang.org/x/text@v0.14.0")
}

func TestEgressBuiltinCrates(t *testing.T) {
	harness.Require(t, sc, "UC-198")
	runBuiltinProfile(t, "builtin:crates", "rust:1-alpine",
		`export PATH=/usr/local/cargo/bin:$PATH RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo && cd /tmp && cargo new -q c && cd c && echo 'itoa = "1"' >> Cargo.toml && cargo fetch -q`)
}

func TestEgressBuiltinAptUbuntu(t *testing.T) {
	harness.Require(t, sc, "UC-199")
	runBuiltinProfile(t, "builtin:apt-ubuntu", "ubuntu:24.04", "apt-get update -qq && cd /tmp && apt-get download -qq hello")
}

// crane stands in for docker pull, which would need Docker in Docker.
func TestEgressBuiltinDockerHub(t *testing.T) {
	harness.Require(t, sc, "UC-200")
	runBuiltinProfile(t, "builtin:docker-hub", "gcr.io/go-containerregistry/crane:debug", "crane pull alpine:3.20 /tmp/alpine.tar")
}
