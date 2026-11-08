package caddy

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// renderRouteDNSUnit runs install.sh's route_dns_network_unit with the
// script's own defaults and returns the aerolvm-rt .network file.
func renderRouteDNSUnit(t *testing.T, installSh string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile(installSh)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	// The defaults, exactly as install.sh sets them.
	var prelude strings.Builder
	for _, name := range []string{"ROUTE_DNS_ADDR", "ROUTE_DNS_LINK_IP", "ROUTE_DNS_LINK_ADDR"} {
		i := strings.Index(src, "\n"+name+"=")
		if i < 0 {
			t.Fatalf("install.sh sets no %s", name)
		}
		line := src[i+1:]
		prelude.WriteString(line[:strings.Index(line, "\n")+1])
	}
	cmd := exec.Command(bash, "-c", "set -euo pipefail\n"+prelude.String()+installShFunc(t, src, "route_dns_network_unit")+"route_dns_network_unit\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	return string(out)
}

func unitValue(t *testing.T, unit, key string) string {
	t.Helper()
	for _, line := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	t.Fatalf("no %s= in\n%s", key, unit)
	return ""
}

// The cluster-bank-flagship UC-171 drops (2026-11-01). systemd-resolved
// pins its socket for a link's DNS server to that link, so the aerolvm-rt
// link's DNS server must be an address ON that link: a loopback server is
// unreachable over UDP from the pinned socket, and resolved then stalls
// lookups for ~20s at a time while it falls back to TCP. The env must point
// sandboxd's second listener at that same address, and only when routing is
// on.
func TestInstallRoutesTheZoneToTheLinkAddress(t *testing.T) {
	unit := renderRouteDNSUnit(t, "../../scripts/install.sh")
	dns := unitValue(t, unit, "DNS")
	host, port, err := net.SplitHostPort(dns)
	if err != nil {
		t.Fatalf("DNS=%q: %v", dns, err)
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsLoopback() {
		t.Fatalf("DNS=%s: the link's DNS server must be the link's own address, never loopback", dns)
	}
	if addr := unitValue(t, unit, "Address"); addr != host+"/32" {
		t.Fatalf("DNS=%s is not on the link (Address=%s)", dns, addr)
	}
	if port != "53053" || unitValue(t, unit, "Domains") != "~rt.internal" || unitValue(t, unit, "DNSDefaultRoute") != "false" {
		t.Fatalf("unit lost the responder port or the zone scoping:\n%s", unit)
	}

	for _, tc := range []struct {
		routing string
		want    string
	}{
		{"true", "SB_ROUTE_DNS_LINK_ADDR=" + dns + "\n"},
		{"false", "SB_ROUTE_DNS_LINK_ADDR=\n"},
	} {
		env, _ := renderInstall(t, "../../scripts/install.sh", map[string]string{"INGRESS_PROXY_ROUTING": tc.routing, "ROUTE_DNS_LINK_ADDR": dns})
		if !strings.Contains(env, tc.want) {
			t.Fatalf("routing=%s: env lacks %q:\n%s", tc.routing, tc.want, env)
		}
	}
}

// install.sh turns routing on by default for a --domain install
// (plans/cluster-phase-2.md §4.3), and only there: it routes names under the
// domain, so IP mode and --local get it off. An explicit flag always wins,
// --no-ingress-proxy-routing being the way to keep a domain install on
// per-sandbox Caddy routes.
func TestInstallIngressProxyRoutingDefault(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	fn := installShFunc(t, string(raw), "resolve_ingress_proxy_routing")
	for _, tc := range []struct {
		name, explicit, domain, local, want string
	}{
		{"--domain: on", "", "sandbox.example.com", "false", "true"},
		{"--domain --no-ingress-proxy-routing: off", "false", "sandbox.example.com", "false", "false"},
		{"IP mode: off", "", "", "false", "false"},
		{"--local: off", "", "", "true", "false"},
		{"--local with a domain: off (no Caddy)", "", "sandbox.example.com", "true", "false"},
		{"IP mode --ingress-proxy-routing: as asked", "true", "", "false", "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "set -euo pipefail\nINGRESS_PROXY_ROUTING='" + tc.explicit + "'\nDOMAIN='" + tc.domain + "'\nLOCAL_MODE='" + tc.local + "'\n" +
				fn + "resolve_ingress_proxy_routing\nprintf '%s' \"$INGRESS_PROXY_ROUTING\"\n"
			out, err := exec.Command(bash, "-c", script).CombinedOutput()
			if err != nil || string(out) != tc.want {
				t.Fatalf("INGRESS_PROXY_ROUTING = %q (%v), want %q", out, err, tc.want)
			}
		})
	}

	// The default is settled after the flags are parsed and before anything
	// reads it (write_environment, write_route_dns_resolver).
	src := string(raw)
	call := strings.Index(src, "\nresolve_ingress_proxy_routing\n")
	parsed := strings.Index(src, "\n\t\t--no-ingress-proxy-routing)\n")
	firstUse := strings.Index(src, "\nwrite_environment\n")
	if call < 0 || parsed < 0 || firstUse < 0 {
		t.Fatalf("install.sh lost the call (%d), the flag (%d) or the env write (%d)", call, parsed, firstUse)
	}
	if !(parsed < call && call < firstUse) {
		t.Fatalf("resolve_ingress_proxy_routing must run after the flag loop and before write_environment (flag %d, call %d, write %d)", parsed, call, firstUse)
	}
	if !strings.Contains(src, "\nINGRESS_PROXY_ROUTING=\"\"\n") {
		t.Fatal(`INGRESS_PROXY_ROUTING must start empty ("not chosen"), or the default can never apply`)
	}
}
