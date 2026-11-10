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
	"runtime"
	"strings"
	"testing"
	"text/template"
)

// certmagicS3Module is the storage plugin we link into Caddy. ss098's fork
// is the path Caddy's official JSON-config docs link to; the JSON shape
// (host/bucket/access_id/secret_key/prefix/insecure) is fixed here too.
const certmagicS3Module = "github.com/ss098/certmagic-s3@v0.0.0-20250922022452-8af482af5f39"

// caddyVersion is the Caddy core the fixture builds: the one scripts/install.sh
// pins for custom builds (CADDY_BUILD_VERSION), so the e2e tests run the
// Caddy a release ships.
// integration-tests/safety/caddy_version_test.go keeps the two in step.
const caddyVersion = "v2.11.8-0.20261106223313-31f9f0cb9949"

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

// xcaddyModule is the xcaddy the fixture builds Caddy with, as release.yml.
const xcaddyModule = "github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6"

// Build returns a path to a Linux Caddy binary linked with certmagic-s3, for
// HostMount: it always runs inside a Linux container, so it is built for
// linux whatever the host is, on the host's CPU (Docker on a Mac runs a Linux
// VM of the same architecture). It used to be built for the host, so on a Mac
// the container could not start it. The binary is cached in
// $TMPDIR/aerolvm-e2e-caddy-<version>-linux-<arch>/caddy and only rebuilt on
// absence; the version in the path means a bump never reuses an old build.
// On any toolchain / network failure the test is skipped — this is an
// operator-runnable path, not a CI gate.
func Build(t testing.TB) string {
	t.Helper()
	cacheDir := filepath.Join(os.TempDir(), "aerolvm-e2e-caddy-"+caddyVersion+"-linux-"+runtime.GOARCH)
	binPath := filepath.Join(cacheDir, "caddy")
	if _, err := os.Stat(binPath); err == nil {
		return binPath
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("caddyfx: mkdir cache: %v", err)
	}
	// xcaddy runs on this host, so it is installed for the host. `go run`
	// with GOOS=linux would build a Linux xcaddy that a Mac cannot start.
	gobin := filepath.Join(cacheDir, "bin")
	install := exec.Command("go", "install", xcaddyModule)
	install.Env = append(hostEnv(), "GOBIN="+gobin)
	if out, err := install.CombinedOutput(); err != nil {
		t.Skipf("caddyfx: go install %s failed (%v); needs Go toolchain + network\n%s", xcaddyModule, err, out)
	}
	cmd := exec.Command(filepath.Join(gobin, "xcaddy"), "build", caddyVersion, "--output", binPath, "--with", certmagicS3Module)
	cmd.Env = append(hostEnv(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
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

// hostEnv is this process's environment without GOOS and GOARCH, so a
// caller's cross-compile settings reach neither the xcaddy install nor
// override the target set above.
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GOOS=") || strings.HasPrefix(kv, "GOARCH=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// HostMount returns a docker bind spec (`hostPath:containerPath:ro`) that
// mounts the built Caddy binary into a busybox/alpine container at /usr/bin/caddy.
// The container's CMD is set to `/usr/bin/caddy run --resume`.
func HostMount(binPath string) string {
	return fmt.Sprintf("%s:/usr/bin/caddy:ro", binPath)
}
