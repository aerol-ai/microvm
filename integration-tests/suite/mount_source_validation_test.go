//go:build integration

package suite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Mount sources are passed positionally to mount tools that run on the host as
// the daemon user, so a source shaped like a command-line option must be
// refused at the API, before any tool is spawned. The sources below use an
// inert dummy flag: the point is that validation rejects the shape, not what a
// particular flag would do.
var optionShapedMountSources = []struct {
	name  string
	mount map[string]any
}{
	{"sshfs", map[string]any{
		"type": "sshfs", "source": "-oDummyFlag=1@host:/data", "target": "/mnt/x",
		"credentials": map[string]string{"private_key_pem": "unused"},
	}},
	{"rclone", map[string]any{
		"type": "rclone", "source": "--dummy-flag", "target": "/mnt/x",
		"credentials": map[string]string{"rclone_conf": "[r]\ntype = local\n"},
	}},
	{"nfs", map[string]any{"type": "nfs", "source": "-odummy:/data", "target": "/mnt/x"}},
	{"s3 bucket", map[string]any{"type": "s3", "source": "s3://-dummy-flag/prefix", "target": "/mnt/x"}},
}

// assertMountSourceRefused posts a create for each option-shaped source and
// requires a non-2xx response naming the leading-dash rule, then confirms no
// sandbox with that name exists.
func assertMountSourceRefused(t *testing.T, base map[string]any) {
	t.Helper()
	c := client(t)
	for _, tc := range optionShapedMountSources {
		t.Run(tc.name, func(t *testing.T) {
			name := harness.UniqueName(sc, t)
			body := map[string]any{"name": name, "mounts": []map[string]any{tc.mount}}
			for k, v := range base {
				body[k] = v
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			status, resp, err := c.PostStatus(ctx, "/v1/sandboxes", body)
			if err != nil {
				t.Fatalf("POST /v1/sandboxes: %v", err)
			}
			if status >= 200 && status < 300 {
				t.Fatalf("option-shaped %s source was accepted (status %d): %s", tc.name, status, resp)
			}
			if !strings.Contains(string(resp), "must not start with '-'") {
				t.Fatalf("status %d, body does not name the leading-dash rule: %s", status, resp)
			}
			t.Logf("refused with status %d", status)

			sandboxes, err := c.SDK().List(ctx)
			if err != nil {
				t.Fatalf("list sandboxes: %v", err)
			}
			for _, sb := range sandboxes {
				if sb.Name == name {
					t.Fatalf("a sandbox named %q exists after the refused create (id %s)", name, sb.ID)
				}
			}
		})
	}
}

// UC-174 — container runtimes refuse option-shaped mount sources at create.
func TestMountSourceOptionShapedRefused(t *testing.T) {
	harness.Require(t, sc, "UC-174")
	assertMountSourceRefused(t, map[string]any{"image": harness.DefaultImage})
}

// UC-175 — the WASM create path validates mounts too. It used to hand mounts
// to the host mount manager without MountSpec.Validate. The module must be
// one the scenario actually staged: cluster placement refuses an unknown
// module (503) before the request ever reaches mount validation.
func TestMountSourceOptionShapedRefusedWasm(t *testing.T) {
	harness.Require(t, sc, "UC-175")
	assertMountSourceRefused(t, map[string]any{"runtime": "wasm", "module_ref": stagedWasmModuleRefOrDefault(t)})
}
