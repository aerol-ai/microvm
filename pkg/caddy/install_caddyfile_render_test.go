package caddy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// installShFunc returns one top-level function of install.sh, source and
// all. A function runs to the next top-level function definition: its
// heredocs hold Caddyfile lines that are a lone "}".
func installShFunc(t *testing.T, src, name string) string {
	t.Helper()
	nextFunc := regexp.MustCompile(`\n[a-z_]+\(\) \{\n`)
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
	fn := func(name string) string { return installShFunc(t, string(raw), name) }
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
		"ROUTE_DNS_ADDR": "127.0.0.1:53053", "ROUTE_DNS_LINK_ADDR": "169.254.53.53:53053", "WITH_GVISOR": "false", "WITH_ISOLATE": "false", "WITH_CONTAINERD_ENGINE": "false",
		"PAT_SCOPE": "any", "PUBLIC_API_SOCKET": "/run/sandboxd-public/api.sock", "L4_PROXY_PROTOCOL": "false",
		"ACME_CA": "", "ACME_CA_ROOT": "", "ACME_EMAIL": "", "CADDY_STORAGE_S3_ACCESS_KEY": "",
		// --lb-health-port: empty writes no health listener.
		"LB_HEALTH_PORT": "",
		// install.sh's default; write_environment adds the key-store lines
		// only for "wrapped" (plans/customer-key-custody.md §3).
		"KEY_CUSTODY": "file",
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

// TestInstallWritesLBHealthListener: --lb-health-port adds the plain-HTTP
// /health site a load balancer's health check probes (Terraform
// api_load_balancer = "nlb"). The probe must fail whenever a client would:
// it goes through caddy-l4 on :443 and the HTTPS API site to sandboxd, and it
// names the API site in both SNI and Host, because a balancer's probe sends
// neither and an unmatched Host gets Caddy's empty 200 (a node with sandboxd
// down would then stay in rotation). A default install writes no listener.
func TestInstallWritesLBHealthListener(t *testing.T) {
	health := "http://:21280 {\n\thandle /health {\n\t\treverse_proxy https://127.0.0.1:443 {\n"
	for _, tc := range []struct {
		name string
		vars map[string]string
		want bool
	}{
		{name: "default install", want: false},
		{name: "--lb-health-port", vars: map[string]string{"LB_HEALTH_PORT": "21280"}, want: true},
		// The listener rides the same path whatever upstream the API site uses.
		{name: "--lb-health-port with host scope and PROXY protocol", vars: map[string]string{"LB_HEALTH_PORT": "21280", "PAT_SCOPE": "host", "L4_PROXY_PROTOCOL": "true"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cf := renderInstall(t, "../../scripts/install.sh", tc.vars)
			if got := strings.Count(cf, health); got != map[bool]int{false: 0, true: 1}[tc.want] {
				t.Fatalf("health site count = %d, want present=%v:\n%s", got, tc.want, cf)
			}
			if !tc.want {
				if strings.Contains(cf, "tls_insecure_skip_verify") || strings.Contains(cf, "http://:") {
					t.Fatalf("a default install writes a health listener:\n%s", cf)
				}
				return
			}
			lines := strings.Split(cf, "\n")
			var block []string
			for i, l := range lines {
				if l == "http://:21280 {" {
					block = caddyfileBlock(lines[i+1:])
				}
			}
			for _, want := range []string{
				"header_up Host sandbox.example.com",
				"tls_server_name sandbox.example.com",
				"tls_insecure_skip_verify",
				"respond 404",
			} {
				if !slices.Contains(block, want) {
					t.Errorf("health site lacks %q:\n%s", want, strings.Join(block, "\n"))
				}
			}
			// Bound to every address so it sorts after 127.0.0.1:8443 and
			// the API site stays srv0 (see caddyAdaptServers below).
			for _, l := range block {
				if strings.HasPrefix(l, "bind ") {
					t.Errorf("health site binds %q; a bound address can sort before 127.0.0.1:8443 and take srv0", l)
				}
			}
			if strings.Count(cf, ":8443 {\n\tbind 127.0.0.1\n") != 2 {
				t.Errorf("the HTTPS sites moved off 127.0.0.1:8443:\n%s", cf)
			}
			caddyAdaptServers(t, cf)
		})
	}
}

// caddyAdaptServers adapts the rendered Caddyfile with a real Caddy, when one
// is on PATH, and checks the server sandboxd writes routes into: srv0
// (SB_CADDY_SERVER_ID) must still be the HTTPS API site, and the health site
// a server of its own on :21280. Caddy numbers servers by their sorted listen
// addresses, which is what a static check cannot prove.
func caddyAdaptServers(t *testing.T, caddyfile string) {
	t.Helper()
	bin, err := exec.LookPath("caddy")
	if err != nil {
		t.Log("caddy not on PATH; skipping the adapt check")
		return
	}
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(caddyfile), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "adapt", "--config", path, "--adapter", "caddyfile").Output()
	if err != nil {
		t.Fatalf("caddy adapt: %v", err)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen []string `json:"listen"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("decode adapted config: %v", err)
	}
	servers := cfg.Apps.HTTP.Servers
	if got := servers["srv0"].Listen; !slices.Equal(got, []string{"127.0.0.1:8443"}) {
		t.Errorf("srv0 listens on %v, want the API site on 127.0.0.1:8443 (servers: %+v)", got, servers)
	}
	found := false
	for _, srv := range servers {
		found = found || slices.Equal(srv.Listen, []string{":21280"})
	}
	if !found {
		t.Errorf("no server listens on :21280: %+v", servers)
	}
}
