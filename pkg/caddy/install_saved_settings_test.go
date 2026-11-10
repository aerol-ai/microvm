package caddy

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// install.sh remembers its answers (plans/kubectl-style-cluster-ops.md D7):
// every non-secret setting goes to /etc/sandboxd/node.json, secrets stay in
// the env files and are read back, and a re-run with no flags rebuilds the
// same node. Before this, a re-run without --pat-token made a new PAT (every
// client and cluster peer then got 401s) and a re-run without the original
// flags silently dropped them.
//
// These tests run the real install.sh from the top, with every /etc, /var
// and /run path moved under a temp dir, uname and hostname stubbed, and its
// two "must run as root" checks replaced by a dump of the settings it
// resolved. That is the point where every flag, saved setting and default
// has passed every check and nothing has been written yet. Files an install
// would have written are rendered with install.sh's own writers.

// savedSettingsVars are the variables a run's result is compared on: every
// NODE_SETTINGS variable, the secrets, and what install.sh derives from them.
func savedSettingsVars(t *testing.T, src string) []string {
	t.Helper()
	vars := []string{"PAT_TOKEN", "DNS_API_TOKEN", "CADDY_STORAGE_S3_ACCESS_KEY", "CADDY_STORAGE_S3_SECRET_KEY",
		"CADDY_STORAGE_S3_ENCRYPTION_KEY", "L4_TLS_LISTEN_DEFAULT", "TOOLBOX_BINARY_PATH", "PUBLIC_HOST_DETECTED"}
	for _, e := range nodeSettingsEntries(t, src) {
		vars = append(vars, e.variable)
	}
	return vars
}

type nodeSettingsEntry struct{ variable, flag, kind string }

// nodeSettingsEntries parses install.sh's NODE_SETTINGS array.
func nodeSettingsEntries(t *testing.T, src string) []nodeSettingsEntry {
	t.Helper()
	m := regexp.MustCompile(`(?s)\nNODE_SETTINGS=\(\n(.*?)\n\)\n`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("install.sh has no NODE_SETTINGS=( ... ) array")
	}
	var out []nodeSettingsEntry
	for _, line := range strings.Split(m[1], "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) != 3 {
			t.Fatalf("NODE_SETTINGS entry %q is not VARIABLE:--flag:type", line)
		}
		out = append(out, nodeSettingsEntry{parts[0], parts[1], parts[2]})
	}
	return out
}

// installRig runs install.sh with its paths under one temp dir. Every run of
// a rig shares that dir, as runs on one machine share /etc.
type installRig struct {
	t      *testing.T
	bash   string
	dir    string // the "machine": out/sandboxd is /etc/sandboxd, and so on
	script string // the transformed install.sh
	src    string // the transformed source, for writer functions
	vars   []string
}

func newInstallRig(t *testing.T) *installRig {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := strings.NewReplacer("/run/sandboxd-public", "/run/sandboxd-public",
		"/etc/default/caddy", dir+"/default-caddy", "/etc/caddy", dir+"/caddy", "/etc/sandboxd", dir+"/sandboxd",
		"/var/lib/sandboxd", dir+"/varlib", "/run/sandboxd", dir+"/run").Replace(string(raw))

	vars := savedSettingsVars(t, string(raw))
	// The dump: NAME, NUL, value, NUL for Go, and declare -p for a shell that
	// renders the files this run would write. Where the key-store settings
	// came from differs between a first run and a re-run by design, so those
	// two only go to the shell; the rendered env file compares the result.
	// INGRESS_PROXY_ROUTING_AUTO differs the same way: a value read back from
	// an older node's env file counts as given.
	shellOnly := []string{"SECRET_PROVIDER_ENV", "SAVED_SECRET_PROVIDER_LINES", "INGRESS_PROXY_ROUTING_AUTO"}
	dump := "aerol_test_dump() {\n\tlocal v\n\tfor v in " + strings.Join(vars, " ") + "; do printf '%s\\0%s\\0' \"$v\" \"${!v}\"; done >\"$AEROL_DUMP\"\n" +
		"\tdeclare -p " + strings.Join(append(slices.Clone(vars), shellOnly...), " ") + " >\"$AEROL_DUMP.sh\"\n}\n"
	stubs := "uname() { case \"${1:-}\" in -m) echo x86_64 ;; *) echo Linux ;; esac; }\n" +
		"hostname() { [[ \"${1:-}\" == -I ]] && echo '10.0.0.7 fd00::7'; }\n" + dump

	script := src
	for _, check := range []string{
		"\tif [[ $EUID -ne 0 ]]; then\n\t\techo \"install.sh must run as root (use sudo)\" >&2\n\t\texit 1\n\tfi\n",
		"\nif [[ $EUID -ne 0 ]]; then\n\techo \"install.sh must run as root\" >&2\n\texit 1\nfi\n",
	} {
		if strings.Count(script, check) != 1 {
			t.Fatalf("install.sh no longer has exactly one root check %q; update this rig", check)
		}
		script = strings.Replace(script, check, "\naerol_test_dump\nexit 0\n", 1)
	}
	const head = "#!/usr/bin/env bash\n\nset -euo pipefail\n"
	if !strings.HasPrefix(script, head) {
		t.Fatalf("install.sh does not start with %q", head)
	}
	script = head + stubs + strings.TrimPrefix(script, head)
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &installRig{t: t, bash: bash, dir: dir, script: path, src: src, vars: vars}
}

func (r *installRig) path(rel string) string { return filepath.Join(r.dir, rel) }

// run runs install.sh with args. It returns the settings at the root check,
// the path of their declare -p dump, and the output; err is the exit error.
func (r *installRig) run(args ...string) (got map[string]string, dumpSh, out string, err error) {
	r.t.Helper()
	dump := filepath.Join(r.t.TempDir(), "dump")
	cmd := exec.Command(r.bash, append([]string{r.script}, args...)...)
	cmd.Dir = r.t.TempDir() // no go.mod here, so it never builds from source
	cmd.Env = append(os.Environ(), "AEROL_DUMP="+dump)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	if err != nil {
		return nil, "", buf.String(), err
	}
	raw, rerr := os.ReadFile(dump)
	if rerr != nil {
		r.t.Fatalf("install.sh exited 0 without reaching the root check:\n%s", buf.String())
	}
	got = map[string]string{}
	parts := strings.Split(string(raw), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		got[parts[i]] = parts[i+1]
	}
	return got, dump + ".sh", buf.String(), nil
}

func (r *installRig) mustRun(args ...string) (map[string]string, string, string) {
	r.t.Helper()
	got, dumpSh, out, err := r.run(args...)
	if err != nil {
		r.t.Fatalf("install.sh %q: %v\n%s", args, err, out)
	}
	return got, dumpSh, out
}

// shell runs body after install.sh's writer functions and the settings in
// dumpSh, with the commands they call on a real host stubbed.
func (r *installRig) shell(dumpSh, body string) string {
	r.t.Helper()
	fns := ""
	for _, name := range []string{"write_environment", "firecracker_environment", "write_caddy_env", "write_caddyfile",
		"write_local_environment", "secret_provider_lines", "node_setting_answer", "json_string", "write_node_settings"} {
		fns += installShFunc(r.t, r.src, name)
	}
	array := regexp.MustCompile(`(?s)\nNODE_SETTINGS=\(\n.*?\n\)\n`).FindString(r.src)
	// Top-level defaults the writers read and the dump does not carry.
	defaults := r.src[strings.Index(r.src, "\nDOMAIN=\"\"\n"):strings.Index(r.src, "\nusage() {\n")]
	script := "set -euo pipefail\n" + defaults + array + fns +
		"id() { echo 990; }\ngetent() { return 0; }\nuseradd() { :; }\ninstall() { :; }\nchown() { :; }\n" +
		"source '" + dumpSh + "'\n" +
		// register_isolate_runtime resolves this from --workerd-path.
		"WORKERD_BIN_RESOLVED=\"$WORKERD_PATH\"\n" + body
	cmd := exec.Command(r.bash, "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("shell: %v\n%s", err, out)
	}
	return string(out)
}

// render writes the files an install with these settings writes, the way an
// install from before node.json left them, and returns them by name.
func (r *installRig) render(got map[string]string, dumpSh string) map[string]string {
	r.t.Helper()
	body := "write_environment\nwrite_caddy_env\nwrite_caddyfile\n"
	if got["LOCAL_MODE"] == "true" {
		body = "write_local_environment\n"
	}
	r.shell(dumpSh, body)
	files := map[string]string{}
	for _, rel := range []string{"sandboxd/sandboxd.env", "default-caddy", "caddy/Caddyfile"} {
		if b, err := os.ReadFile(r.path(rel)); err == nil {
			files[rel] = string(b)
		}
	}
	return files
}

func diffSettings(t *testing.T, what string, want, got map[string]string, except ...string) {
	t.Helper()
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if slices.Contains(except, k) {
			continue
		}
		if got[k] != want[k] {
			t.Errorf("%s: %s = %q, want %q", what, k, got[k], want[k])
		}
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A node installed before node.json existed is re-run with no flags: it
// must come back with the same settings, the same PAT and the same secrets,
// write node.json, and a second re-run must read node.json to the same
// result. The files are compared byte for byte, since they are what sandboxd
// and Caddy actually read.
func TestInstallRerunWithNoFlagsRebuildsTheSameNode(t *testing.T) {
	caRoot := writeTemp(t, "ca.pem", "-----BEGIN CERTIFICATE-----\n")
	providerEnv := writeTemp(t, "provider.env", "SB_SECRET_PROVIDER=awskms\nSB_SECRET_AWS_KMS_KEY_ID=arn:aws:kms:eu-west-1:1:key/k\nAWS_REGION=eu-west-1\nIGNORED=1\n")
	cases := []struct {
		name string
		args []string
	}{
		{"IP mode, every default", nil},
		{"IP mode, a given address", []string{"--public-host", "203.0.113.42", "--pat-token", "given-pat", "--node-name", `node "one" \ two`}},
		{"local mode", []string{"--local", "--node-name", "dev", "--idle-timeout-min", "5"}},
		{"internal CA", []string{"--domain", "lab.example.com", "--tls-issuer", "internal", "--pat-scope", "host"}},
		{"domain mode, every recoverable setting", []string{
			"--domain", "sb.example.com", "--dns-provider", "cloudflare", "--dns-api-token", "cf-token",
			"--acme-email", "ops@example.com", "--acme-ca", "https://ca.example.com/acme/directory", "--acme-ca-root", caRoot,
			"--public-host", "198.51.100.4", "--node-name", "edge-1", "--idle-timeout-min", "30", "--install-prefix", "/opt/aerolvm/bin",
			"--ingress-proxy-routing", "--with-gvisor", "--with-containerd-engine", "--with-isolate", "--workerd-path", "/opt/workerd",
			"--with-firecracker",
			"--caddy-storage-s3", "--caddy-storage-s3-bucket", "certs", "--caddy-storage-s3-region", "eu-west-1",
			"--caddy-storage-s3-prefix", "edge", "--caddy-storage-s3-access-key", "AKIA1", "--caddy-storage-s3-secret-key", "s3-secret",
			"--caddy-storage-s3-encryption-key", "enc-key",
			"--pat-scope", "host", "--l4-proxy-protocol", "--lb-health-port", "21280",
			"--key-custody", "wrapped", "--secret-provider-env", providerEnv,
		}},
		{"domain mode, S3 on a custom endpoint", []string{
			"--domain", "sb.example.com", "--dns-provider", "cloudflare", "--dns-api-token", "cf-token",
			"--caddy-storage-s3", "--caddy-storage-s3-bucket", "certs", "--caddy-storage-s3-region", "auto",
			"--caddy-storage-s3-endpoint", "abc.r2.cloudflarestorage.com", "--caddy-storage-s3-encryption-key", "enc-key",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newInstallRig(t)
			first, firstSh, _ := rig.mustRun(tc.args...)
			if !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(first["PAT_TOKEN"]) && first["PAT_TOKEN"] != "given-pat" {
				t.Fatalf("a first install made PAT %q, want 48 hex characters", first["PAT_TOKEN"])
			}
			before := rig.render(first, firstSh)

			// The older node's first re-run: no node.json yet.
			if _, err := os.Stat(rig.path("sandboxd/node.json")); !os.IsNotExist(err) {
				t.Fatalf("node.json exists before any run wrote it: %v", err)
			}
			again, againSh, out := rig.mustRun()
			if !strings.Contains(out, "reading this node's settings back from") {
				t.Errorf("the re-run did not say it read the settings back:\n%s", out)
			}
			diffSettings(t, "re-run of an older node", first, again)
			after := rig.render(again, againSh)
			if !mapsEqual(before, after) {
				for name := range before {
					if before[name] != after[name] {
						t.Errorf("%s changed on a re-run with no flags:\n--- before\n%s\n--- after\n%s", name, before[name], after[name])
					}
				}
				if len(before) != len(after) {
					t.Errorf("files before %v, after %v", keysOf(before), keysOf(after))
				}
			}

			// That re-run writes node.json; the next one reads it.
			rig.shell(againSh, "write_node_settings\n")
			checkNodeJSON(t, rig, nodeSettingsEntries(t, rig.src), first)
			third, _, out := rig.mustRun()
			if !strings.Contains(out, "Using the settings saved in") {
				t.Errorf("the second re-run did not use node.json:\n%s", out)
			}
			diffSettings(t, "re-run from node.json", first, third)

			// A flag given on a re-run wins over the saved value; the rest
			// stays.
			override, _, _ := rig.mustRun("--node-name", "renamed", "--pat-token", "rotated")
			if override["NODE_NAME"] != "renamed" || override["PAT_TOKEN"] != "rotated" {
				t.Fatalf("flags did not win: NODE_NAME=%q PAT_TOKEN=%q", override["NODE_NAME"], override["PAT_TOKEN"])
			}
			diffSettings(t, "re-run with two flags", first, override, "NODE_NAME", "PAT_TOKEN")
		})
	}
}

// checkNodeJSON checks node.json is root-only JSON holding every saved
// setting by its flag's name, and no secret.
func checkNodeJSON(t *testing.T, rig *installRig, entries []nodeSettingsEntry, settings map[string]string) {
	t.Helper()
	path := rig.path("sandboxd/node.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("node.json mode %v, want 0600", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("node.json is not JSON: %v\n%s", err, raw)
	}
	if doc["format"] != float64(1) {
		t.Errorf("node.json format = %v, want 1", doc["format"])
	}
	for _, e := range entries {
		key := strings.ReplaceAll(strings.TrimPrefix(e.flag, "--"), "-", "_")
		v, ok := doc[key]
		if !ok {
			t.Errorf("node.json has no %q (for %s)", key, e.flag)
			continue
		}
		_, isBool := v.(bool)
		if e.kind == "auto" && (isBool || v == "auto") {
			continue
		}
		if isBool != (e.kind == "bool") {
			t.Errorf("node.json %q = %#v, want a %s", key, v, e.kind)
		}
	}
	if len(doc) != len(entries)+1 {
		t.Errorf("node.json has %d keys, want %d (format + NODE_SETTINGS)", len(doc), len(entries)+1)
	}
	for _, secret := range []string{"PAT_TOKEN", "DNS_API_TOKEN", "CADDY_STORAGE_S3_ACCESS_KEY", "CADDY_STORAGE_S3_SECRET_KEY", "CADDY_STORAGE_S3_ENCRYPTION_KEY"} {
		if v := settings[secret]; v != "" && strings.Contains(string(raw), v) {
			t.Errorf("node.json holds the secret %s", secret)
		}
	}
	for _, leak := range []string{"SB_SECRET_", "arn:aws:kms"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("node.json holds key-store settings (%s)", leak)
		}
	}
}

// Settings no older install recorded anywhere (the GPU switches,
// --runsc-path, --github-repo) round-trip through node.json, and a value
// with quotes and backslashes comes back exactly.
func TestInstallNodeJSONKeepsEverySetting(t *testing.T) {
	rig := newInstallRig(t)
	args := []string{"--domain", "sb.example.com", "--dns-provider", "cloudflare", "--dns-api-token", "t",
		"--node-name", `a "quoted\" name\\ é`, "--github-repo", "fork/microvm", "--runsc-path", "/opt/runsc",
		"--with-gvisor", "--with-nvidia-gpu", "--with-amd-gpu", "--acme-email", "x@example.com"}
	first, firstSh, _ := rig.mustRun(args...)
	rig.render(first, firstSh)
	rig.shell(firstSh, "write_node_settings\n")
	again, _, _ := rig.mustRun()
	diffSettings(t, "re-run from node.json", first, again)
	if again["NODE_NAME"] != `a "quoted\" name\\ é` {
		t.Fatalf("NODE_NAME came back as %q", again["NODE_NAME"])
	}
}

// --ingress-proxy-routing is on by default only where it applies (a
// --domain install), so node.json keeps the operator's answer, not what one
// run derived: no flag saves "auto" and the next run derives it again, so a
// node that gets a --domain later turns routing on. An explicit
// --no-ingress-proxy-routing is saved and wins over a saved true, and the
// flag wins over a saved false.
func TestInstallRoutingSavesOnlyAGivenAnswer(t *testing.T) {
	domain := []string{"--domain", "sb.example.com", "--dns-provider", "cloudflare", "--dns-api-token", "t"}
	saved := func(t *testing.T, rig *installRig) any {
		t.Helper()
		raw, err := os.ReadFile(rig.path("sandboxd/node.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("node.json: %v\n%s", err, raw)
		}
		return doc["ingress_proxy_routing"]
	}
	step := func(t *testing.T, rig *installRig, want string, wantSaved any, args ...string) {
		t.Helper()
		got, dumpSh, _ := rig.mustRun(args...)
		if got["INGRESS_PROXY_ROUTING"] != want {
			t.Fatalf("install.sh %q: INGRESS_PROXY_ROUTING = %q, want %q", args, got["INGRESS_PROXY_ROUTING"], want)
		}
		// The files an install writes, so the next run reads the DNS token
		// back from them, then node.json.
		rig.render(got, dumpSh)
		rig.shell(dumpSh, "write_node_settings\n")
		if v := saved(t, rig); v != wantSaved {
			t.Fatalf("install.sh %q: node.json ingress_proxy_routing = %#v, want %#v", args, v, wantSaved)
		}
	}

	t.Run("derived on a --domain install, kept as auto", func(t *testing.T) {
		rig := newInstallRig(t)
		step(t, rig, "true", "auto", domain...)
		step(t, rig, "true", "auto")
	})
	t.Run("an explicit off is kept and the flag turns it back on", func(t *testing.T) {
		rig := newInstallRig(t)
		step(t, rig, "true", "auto", domain...)
		step(t, rig, "false", false, "--no-ingress-proxy-routing")
		step(t, rig, "false", false)
		step(t, rig, "true", true, "--ingress-proxy-routing")
		step(t, rig, "false", false, "--no-ingress-proxy-routing")
	})
	t.Run("an IP-mode node that gets a domain later turns routing on", func(t *testing.T) {
		rig := newInstallRig(t)
		step(t, rig, "false", "auto")
		step(t, rig, "true", "auto", domain...)
	})
}

// A saved setting is checked exactly like the flag, and a node.json that
// install.sh cannot read fails the run instead of being half applied.
func TestInstallRefusesABadSavedSetting(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lines    []string // node.json between its braces, one setting per line
		caddyEnv string   // /etc/default/caddy, where the DNS token is read back from
		want     string
	}{
		{"a port the node already uses",
			[]string{`"format": 1,`, `"domain": "x.example.com",`, `"dns_provider": "cloudflare",`, `"lb_health_port": "21212"`},
			"SB_DNS_API_TOKEN=t\n", "--lb-health-port 21212 is already used on this node"},
		{"a domain with no DNS token to read back", []string{`"format": 1,`, `"domain": "x.example.com",`, `"dns_provider": "cloudflare"`},
			"", "--dns-provider requires --dns-api-token"},
		{"a broken line", []string{`"format": 1,`, `"domain" "x"`}, "", `line 3 is not one "key": value setting`},
		{"a switch that is not a boolean", []string{`"format": 1,`, `"with_gvisor": "yes"`}, "", "with_gvisor must be true or false"},
		{"an auto switch that is neither", []string{`"format": 1,`, `"ingress_proxy_routing": "maybe"`}, "",
			"ingress_proxy_routing must be true, false or auto"},
		{"a newer format", []string{`"format": 2`}, "", "has format '2'"},
		{"an escape install.sh never writes", []string{`"format": 1,`, `"node_name": "a\nb"`}, "", "unsupported escape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newInstallRig(t)
			if tc.caddyEnv != "" {
				if err := os.WriteFile(rig.path("default-caddy"), []byte(tc.caddyEnv), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(rig.path("sandboxd"), 0o755); err != nil {
				t.Fatal(err)
			}
			body := "{\n  " + strings.Join(tc.lines, "\n  ") + "\n}\n"
			if err := os.WriteFile(rig.path("sandboxd/node.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, out, err := rig.run()
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("install.sh = %v, want refusal %q:\n%s", err, tc.want, out)
			}
		})
	}
}

// --cli-only installs no node: a laptop with an old node.json (or a node
// where someone installs the CLI) must not have node settings applied and
// checked against a CLI install.
func TestInstallCLIOnlyIgnoresSavedSettings(t *testing.T) {
	src, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	loop := strings.Index(s, "\nwhile [[ $# -gt 0 ]]; do\n")
	load := strings.Index(s, "\nif [[ \"$CLI_ONLY\" != \"true\" ]]; then\n\tload_saved_node_settings\nfi\n")
	cli := strings.Index(s, "\nif [[ \"$CLI_ONLY\" == \"true\" ]]; then\n\tinstall_cli\n")
	pat := strings.Index(s, "\nif [[ -z \"$PAT_TOKEN\" ]]; then\n")
	if loop < 0 || load < 0 || cli < 0 || pat < 0 {
		t.Fatalf("install.sh lost a landmark: loop=%d load=%d cli=%d pat=%d", loop, load, cli, pat)
	}
	// After the flags are parsed, before any check, the CLI branch and the
	// PAT a fresh install makes.
	if !(loop < load && load < cli && cli < pat) {
		t.Fatalf("load_saved_node_settings must run after the flag loop and before the checks: loop=%d load=%d cli=%d pat=%d", loop, load, cli, pat)
	}
}

// Every flag install.sh takes is either saved in node.json, a secret read
// back from an env file, or a choice for one run. A new flag nobody sorts
// here would be dropped by the next re-run with no flags, which is the bug
// node.json exists to fix.
func TestInstallSortsEveryFlag(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	saved := map[string]bool{}
	for _, e := range nodeSettingsEntries(t, src) {
		saved[e.flag] = true
		// --no-<flag> turns a saved switch off; load_saved_node_settings
		// treats it as that setting given.
		if e.kind != "string" {
			saved["--no-"+strings.TrimPrefix(e.flag, "--")] = true
		}
	}
	secrets := []string{"--pat-token", "--dns-api-token", "--caddy-storage-s3-access-key", "--caddy-storage-s3-secret-key",
		"--caddy-storage-s3-encryption-key", "--secret-provider-env"}
	perRun := []string{"--version", "--sandboxd-url", "--toolboxd-url", "--checksums-url", "--caddy-binary-url",
		"--build-from-source", "--no-start", "--cli-only", "--cli-url", "--config-only", "--print-join-version", "--download-mirror", "--help"}
	start := strings.Index(src, "\nwhile [[ $# -gt 0 ]]; do\n")
	end := strings.Index(src[start:], "\ndone\n")
	if start < 0 || end < 0 {
		t.Fatal("install.sh has no flag loop")
	}
	arms := regexp.MustCompile(`(?m)^\t\t(--[a-z0-9-]+)\)$`).FindAllStringSubmatch(src[start:start+end], -1)
	if len(arms) < 40 {
		t.Fatalf("found only %d flag arms; the pattern no longer matches the loop", len(arms))
	}
	for _, m := range arms {
		f := m[1]
		n := 0
		for _, in := range []bool{saved[f], slices.Contains(secrets, f), slices.Contains(perRun, f)} {
			if in {
				n++
			}
		}
		if n != 1 {
			t.Errorf("install.sh flag %s is in %d of NODE_SETTINGS / secrets / per-run (want exactly 1)", f, n)
		}
	}
	// Every secret has a read-back in load_saved_node_settings.
	load := installShFunc(t, src, "load_saved_node_settings")
	for _, f := range secrets {
		if !strings.Contains(load, "flag_given "+f) {
			t.Errorf("load_saved_node_settings never reads %s back", f)
		}
	}
}

// json_string and json_unescape round-trip awkward values under every bash
// on the machine: macOS --local runs on /bin/bash 3.2, and bash 5.2 changed
// how a backslash in ${v//pat/rep} is treated.
func TestInstallJSONStringRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	fns := installShFunc(t, string(raw), "json_string") + installShFunc(t, string(raw), "json_unescape")
	var shells []string
	if p, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, p)
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		shells = append(shells, "/bin/bash")
	}
	if len(shells) == 0 {
		t.Skip("bash not found")
	}
	values := []string{"", "plain", `a"b`, `a\b`, `a\"b`, `\\`, `"\`, `\"`, `trailing\`, "é ü 漢", "a b  c", `$HOME`, "`x`", `/x/y`}
	for _, sh := range shells {
		for _, v := range values {
			script := "set -euo pipefail\nNODE_SETTINGS_FILE=node.json\n" + fns +
				"enc=\"$(json_string \"$1\" --x)\"\nprintf '%s\\n' \"$enc\"\nenc=\"${enc#\\\"}\"\nenc=\"${enc%\\\"}\"\njson_unescape \"$enc\"\n"
			out, err := exec.Command(sh, "-c", script, "bash", v).CombinedOutput()
			if err != nil {
				t.Fatalf("%s %q: %v\n%s", sh, v, err, out)
			}
			enc, dec, _ := strings.Cut(string(out), "\n")
			var viaJSON string
			if err := json.Unmarshal([]byte(enc), &viaJSON); err != nil || viaJSON != v {
				t.Errorf("%s: json_string(%q) = %s, which JSON reads as %q (%v)", sh, v, enc, viaJSON, err)
			}
			if dec != v {
				t.Errorf("%s: json_unescape(json_string(%q)) = %q", sh, v, dec)
			}
		}
		// A control character is refused, not written.
		script := "set -euo pipefail\n" + fns + "json_string \"$(printf 'a\\tb')\" --node-name\n"
		if out, err := exec.Command(sh, "-c", script).CombinedOutput(); err == nil || !strings.Contains(string(out), "control character") {
			t.Errorf("%s: a tab was not refused: %v %s", sh, err, out)
		}
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
