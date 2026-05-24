//go:build e2e

// Package caddyfx is the test-side helper that builds a Caddy binary with the
// certmagic-s3 storage plugin (required to exercise the shared-storage cert
// reuse guarantee) and renders the boot JSON the e2e test feeds to it.
//
// We rebuild xcaddy lazily into $TMPDIR/aerolvm-e2e-caddy/caddy and reuse
// the binary across runs: the first invocation pays the ~30s build cost,
// every subsequent invocation reuses the cached artifact.
package caddyfx

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
)

// certmagicS3Module is the storage plugin we link into Caddy. ss098's fork
// is the path Caddy's official JSON-config docs link to; the JSON shape
// (host/bucket/access_id/secret_key/prefix/insecure) is fixed here too.
const certmagicS3Module = "github.com/ss098/certmagic-s3"

//go:embed config.json.tmpl
var configTmpl string

// Config is the template input for the embedded Caddy JSON.
type Config struct {
	S3Endpoint   string // e.g. "localstack:4566"
	S3Bucket     string
	AKID, Secret string
	UpstreamAddr string // e.g. "127.0.0.1:8080" — the in-test backend
}

// Render expands the embedded template with cfg. Returned bytes are the JSON
// body to load via POST /load on Caddy's admin API.
func Render(t testing.TB, cfg Config) []byte {
	t.Helper()
	tmpl, err := template.New("caddy").Parse(configTmpl)
	if err != nil {
		t.Fatalf("caddyfx: parse template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		t.Fatalf("caddyfx: execute template: %v", err)
	}
	return buf.Bytes()
}

// Build returns a path to a Caddy binary linked with certmagic-s3. The binary
// is cached in $TMPDIR/aerolvm-e2e-caddy/caddy and only rebuilt on absence.
// xcaddy itself is fetched via `go run` so no global install is required.
// On any toolchain / network failure the test is skipped — this is an
// operator-runnable path, not a CI gate.
func Build(t testing.TB) string {
	t.Helper()
	cacheDir := filepath.Join(os.TempDir(), "aerolvm-e2e-caddy")
	binPath := filepath.Join(cacheDir, "caddy")
	if _, err := os.Stat(binPath); err == nil {
		return binPath
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("caddyfx: mkdir cache: %v", err)
	}
	args := []string{
		"run", "github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
		"build",
		"--output", binPath,
		"--with", certmagicS3Module,
	}
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Dir = cacheDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("caddyfx: xcaddy build failed (%v); needs Go toolchain + network\n%s", err, out)
	}
	if _, err := os.Stat(binPath); err != nil {
		t.Skipf("caddyfx: xcaddy produced no binary at %s: %v\n%s", binPath, err, out)
	}
	return binPath
}

// HostMount returns a docker bind spec (`hostPath:containerPath:ro`) that
// mounts the built Caddy binary into a busybox/alpine container at /usr/bin/caddy.
// The container's CMD is set to `/usr/bin/caddy run --resume`.
func HostMount(binPath string) string {
	return fmt.Sprintf("%s:/usr/bin/caddy:ro", binPath)
}
