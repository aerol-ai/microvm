package caddy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// renderInstall runs install.sh's write_environment and write_caddyfile
// for a domain-mode install with vars applied, with /etc and /run paths
// moved under a temp dir, and returns the env file and the Caddyfile.
func renderInstall(t *testing.T, installSh string, vars map[string]string) (env, caddyfile string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile(installSh)
	if err != nil {
		t.Fatal(err)
	}
	// A function runs to the next top-level function definition: its
	// heredocs hold Caddyfile lines that are a lone "}".
	nextFunc := regexp.MustCompile(`\n[a-z_]+\(\) \{\n`)
	fn := func(name string) string {
		src := string(raw)
		start := strings.Index(src, "\n"+name+"() {\n")
		if start < 0 {
			t.Fatalf("install.sh has no %s()", name)
		}
		body := src[start+1:]
		if loc := nextFunc.FindStringIndex(body[len(name)+5:]); loc != nil {
			body = body[:len(name)+5+loc[0]+1]
		}
		return body
	}
	out := t.TempDir()
	script := fn("write_environment") + fn("write_caddyfile")
	// Replacements are tried in argument order: the public socket's path
	// is kept, so the rendered Caddyfile names the real one.
	script = strings.NewReplacer("/run/sandboxd-public", "/run/sandboxd-public",
		"/etc/caddy", out+"/caddy", "/etc/sandboxd", out+"/sandboxd",
		"/var/lib/sandboxd", out+"/varlib", "/run/sandboxd", out+"/run").Replace(script)
	defaults := map[string]string{
		"DOMAIN": "sandbox.example.com", "DNS_PROVIDER": "cloudflare", "TLS_ISSUER": "acme", "CADDY_STORAGE_S3": "false",
		"PAT_TOKEN": "pat", "NODE_NAME": "n1", "PUBLIC_HOST": "203.0.113.1", "INSTALL_PREFIX": "/usr/local/bin",
		"IDLE_TIMEOUT_MIN": "0", "L4_TLS_LISTEN_DEFAULT": ":443", "INGRESS_PROXY_ROUTING": "false",
		"ROUTE_DNS_ADDR": "127.0.0.1:53053", "WITH_GVISOR": "false", "WITH_ISOLATE": "false", "WITH_CONTAINERD_ENGINE": "false",
		"PAT_SCOPE": "any", "PUBLIC_API_SOCKET": "/run/sandboxd-public/api.sock", "L4_PROXY_PROTOCOL": "false",
		"ACME_CA": "", "ACME_CA_ROOT": "", "ACME_EMAIL": "", "CADDY_STORAGE_S3_ACCESS_KEY": "",
	}
	for k, v := range vars {
		defaults[k] = v
	}
	var prelude strings.Builder
	for k, v := range defaults {
		prelude.WriteString(k + "='" + v + "'\n")
	}
	cmd := exec.Command(bash, "-c", "set -euo pipefail\n"+prelude.String()+script+"write_environment\nwrite_caddyfile\n")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render: %v\n%s", err, b)
	}
	envRaw, err := os.ReadFile(filepath.Join(out, "sandboxd", "sandboxd.env"))
	if err != nil {
		t.Fatal(err)
	}
	cf, err := os.ReadFile(filepath.Join(out, "caddy", "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	return string(envRaw), string(cf)
}

// TestInstallWritesPATScopeAndProxyProtocolTogether renders install.sh's
// domain-mode env file and Caddyfile (plans/identity-and-access.md §5.11,
// CEO review D4, D12). A default install writes none of the new settings.
// --pat-scope host points Caddy at the public socket and sets the scope;
// --l4-proxy-protocol writes the 8443 listener wrapper, the client-address
// header and SB_L4_FALLBACK_PROXY_PROTOCOL in one step, because the flag
// without the wrapper fails every HTTPS handshake.
func TestInstallWritesPATScopeAndProxyProtocolTogether(t *testing.T) {
	const wrapper = "\tservers 127.0.0.1:8443 {\n\t\tlistener_wrappers {\n\t\t\tproxy_protocol {\n\t\t\t\tallow 127.0.0.1/32\n\t\t\t}\n\t\t\ttls\n\t\t}\n\t}\n"
	const clientIP = "\t\t\theader_up X-AerolVM-Client-IP {remote_host}\n"
	cases := []struct {
		name      string
		vars      map[string]string
		upstream  string
		proxy     bool
		wantEnv   []string
		absentEnv []string
	}{
		{name: "default install", upstream: "127.0.0.1:21212",
			absentEnv: []string{"SB_PAT_SCOPE", "SB_PUBLIC_API_SOCKET", "SB_L4_FALLBACK_PROXY_PROTOCOL"}},
		{name: "--pat-scope host", vars: map[string]string{"PAT_SCOPE": "host"}, upstream: "unix//run/sandboxd-public/api.sock",
			wantEnv: []string{"SB_PAT_SCOPE=host\n", "SB_PUBLIC_API_SOCKET=/run/sandboxd-public/api.sock\n"}, absentEnv: []string{"SB_L4_FALLBACK_PROXY_PROTOCOL"}},
		{name: "--l4-proxy-protocol", vars: map[string]string{"L4_PROXY_PROTOCOL": "true"}, upstream: "127.0.0.1:21212", proxy: true,
			wantEnv: []string{"SB_L4_FALLBACK_PROXY_PROTOCOL=true\n"}, absentEnv: []string{"SB_PAT_SCOPE"}},
		{name: "both", vars: map[string]string{"PAT_SCOPE": "host", "L4_PROXY_PROTOCOL": "true"}, upstream: "unix//run/sandboxd-public/api.sock", proxy: true,
			wantEnv: []string{"SB_PAT_SCOPE=host\n", "SB_L4_FALLBACK_PROXY_PROTOCOL=true\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, cf := renderInstall(t, "../../scripts/install.sh", tc.vars)
			for _, want := range tc.wantEnv {
				if !strings.Contains(env, want) {
					t.Errorf("env misses %q", want)
				}
			}
			for _, absent := range tc.absentEnv {
				if strings.Contains(env, absent) {
					t.Errorf("env carries %q", absent)
				}
			}
			proxyBlock := "\t\treverse_proxy " + tc.upstream + " {\n\t\t\tstream_close_delay 10m\n"
			if tc.proxy {
				proxyBlock += clientIP
			}
			proxyBlock += "\t\t}\n"
			if strings.Count(cf, proxyBlock) != 1 {
				t.Errorf("Caddyfile API proxy is not\n%s\ngot:\n%s", proxyBlock, cf)
			}
			if got := strings.Contains(cf, wrapper); got != tc.proxy {
				t.Errorf("listener wrapper present = %v, want %v:\n%s", got, tc.proxy, cf)
			}
			if got := strings.Contains(cf, "X-AerolVM-Client-IP"); got != tc.proxy {
				t.Errorf("client-address header present = %v, want %v", got, tc.proxy)
			}
			// Both HTTPS sites bind 127.0.0.1:8443, the one listener the
			// wrapper names, so preview sites get the client address too.
			if strings.Count(cf, ":8443 {\n\tbind 127.0.0.1\n") != 2 {
				t.Errorf("both sites must bind 127.0.0.1:8443:\n%s", cf)
			}
		})
	}
}
