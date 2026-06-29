package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// captureCreateEnv runs a Create against fakeCreateDaemon and returns the Env
// slice the daemon actually received in the /containers/create body.
func captureCreateEnv(t *testing.T, mutate func(*Client), req models.CreateSandboxRequest, id string) []string {
	t.Helper()
	var captured map[string]any
	d := fakeCreateDaemon(t)
	base := d.transport()
	wrapped := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/containers/create" && r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &captured)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		return base(r)
	})

	c := newCreateClient(t, d, true, func(c *Client) {
		c.httpClient = &http.Client{Transport: wrapped, Timeout: c.httpClient.Timeout}
		c.streamClient = &http.Client{Transport: wrapped}
		if mutate != nil {
			mutate(c)
		}
	})

	if _, err := c.Create(context.Background(), req, id, "tok", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	out := []string{}
	for _, e := range captured["Env"].([]any) {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func hasEnvPrefix(env []string, prefix string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

// TestCreate_ReadyEnvSurvivesUserEnv is the regression for the slice-aliasing
// bug: envValues is sized to len(req.Env)+3, so appending the two ready vars
// reallocates the backing array. If createRequest["Env"] is not re-stored
// after the append, toolboxd never receives SB_READY_SOCKET/NONCE and the
// push silently degrades to health-poll on every create. User env present
// here exercises the same overflow with a non-trivial base length so the bug
// can't hide behind a lucky capacity.
func TestCreate_ReadyEnvSurvivesUserEnv(t *testing.T) {
	requireLinuxUnix(t)
	readyDir := t.TempDir()
	env := captureCreateEnv(t, func(c *Client) {
		c.readyEnabled = true
		c.readyDir = readyDir
	}, models.CreateSandboxRequest{
		Image: "img",
		Env:   map[string]string{"USER_A": "1", "USER_B": "2"},
	}, "sb-env")

	// All three categories must coexist in the slice the daemon received.
	for _, want := range []string{
		"SB_TOOLBOX_PORT=", "SB_TOOLBOX_TOKEN=", // base
		"USER_A=", "USER_B=", // user
		readySocketEnv + "=", readyNonceEnv + "=", // ready
	} {
		if !hasEnvPrefix(env, want) {
			t.Fatalf("create Env missing %q; got %v", want, env)
		}
	}
}

// TestCreate_DisabledOmitsReadyEnv asserts the inverse: with the push disabled
// no readiness vars leak into the container, and the base/user env is intact.
func TestCreate_DisabledOmitsReadyEnv(t *testing.T) {
	env := captureCreateEnv(t, func(c *Client) {
		c.readyEnabled = false
	}, models.CreateSandboxRequest{
		Image: "img",
		Env:   map[string]string{"USER_A": "1"},
	}, "sb-env-off")

	if hasEnvPrefix(env, readySocketEnv+"=") || hasEnvPrefix(env, readyNonceEnv+"=") {
		t.Fatalf("disabled create leaked ready env: %v", env)
	}
	if !hasEnvPrefix(env, "USER_A=") || !hasEnvPrefix(env, "SB_TOOLBOX_TOKEN=") {
		t.Fatalf("disabled create dropped base/user env: %v", env)
	}
}

// TestCreate_DisabledDoesNotRecordFallbackMetric guards the metric cleanup:
// docker_ready_socket_fallback_health must count only *real* socket losses
// (old toolbox image, gVisor without host-uds) so it stays usable as a
// cluster-mode signal. A non-cluster create (listener == nil) must not bump it.
func TestCreate_DisabledDoesNotRecordFallbackMetric(t *testing.T) {
	before := readySocketFallbackHealth.Value()
	d := fakeCreateDaemon(t)
	c := newCreateClient(t, d, true, func(c *Client) {
		c.readyEnabled = false
	})
	ctx, timing := WithCreateTiming(context.Background())
	if _, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-nofb", "tok", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if timing.Source != "health" {
		t.Fatalf("source = %q, want health", timing.Source)
	}
	if delta := readySocketFallbackHealth.Value() - before; delta != 0 {
		t.Fatalf("fallback metric moved by %d on disabled path, want 0", delta)
	}
}
