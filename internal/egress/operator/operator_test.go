package operator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

const full = `version: 1
internal_zone:
  suffixes: [corp.bank.internal]
  cidrs: [10.0.0.0/8]
  isolate: false
default_policy:
  mode: allowlist
  allow_out: [org:baseline, artifactory.corp.bank.internal]
ceiling:
  allow_out: ["*.corp.bank.internal", artifactory.corp.bank.internal, pypi.org, 10.0.0.0/8]
deny_cidrs: [10.99.0.0/16]
node_control_port_guard: false
builtin_profiles: false
org_profiles:
  baseline:
    allow_out: [git.corp.bank.internal, "git.corp.bank.internal:22"]
    description: internal git
upstream_proxy:
  url: http://proxy.corp.bank.internal:8080
  auth_file: /etc/sandboxd/egress-proxy-auth
  no_proxy: [corp.bank.internal]
`

func TestParseFull(t *testing.T) {
	op, err := Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if op.Hash() == "" || op.DefaultMode() != ModeAllowlist || len(op.DefaultAllowOut()) != 2 {
		t.Fatalf("default policy: %s %v", op.DefaultMode(), op.DefaultAllowOut())
	}
	if op.NodeControlPortGuard() || op.BuiltinProfiles() {
		t.Fatal("explicit false switches must be honored")
	}
	if names := op.OrgProfileNames(); len(names) != 1 || names[0] != "org:baseline" {
		t.Fatalf("org profiles = %v", names)
	}
	pol, ok := op.OrgProfile("org:baseline")
	if !ok {
		t.Fatal("org:baseline missing")
	}
	if allowed, _ := pol.MatchHostPort("git.corp.bank.internal", 22); !allowed {
		t.Fatal("org profile host:port not compiled")
	}
	if op.Ceiling() == nil || op.InternalZone() == nil || len(op.DenyFloor()) != 1 {
		t.Fatal("ceiling, zone and floor must be set")
	}
	up := op.Upstream()
	if up == nil || up.URL.Host != "proxy.corp.bank.internal:8080" || up.Synthetic.String() != "198.18.0.0/15" {
		t.Fatalf("upstream = %+v", up)
	}
	g := op.Guard()
	if g.Zone == nil || len(g.DenyFloor) != 1 || g.Strict {
		t.Fatalf("guard = %+v", g)
	}
	ig := op.IsolateGuard()
	if !ig.Strict || ig.ZoneInStrict {
		t.Fatalf("isolate guard = %+v (zone must stay off without the opt-in, D15)", ig)
	}
	// The zone opens an internal name's IP; the floor wins over it.
	if err := g.Check(nil, egresspolicy.DialTarget{Name: "artifactory.corp.bank.internal", NameAllowed: true, Addr: netip.MustParseAddrPort("10.1.2.3:443")}); err != nil {
		t.Fatalf("zone must open the internal name: %v", err)
	}
	if err := g.Check(nil, egresspolicy.DialTarget{Name: "artifactory.corp.bank.internal", NameAllowed: true, Addr: netip.MustParseAddrPort("10.99.0.5:443")}); err == nil {
		t.Fatal("deny_cidrs must win over the zone")
	}
}

func TestNilOperatorDefaults(t *testing.T) {
	var op *Operator
	if op.DefaultMode() != ModeOpen || !op.NodeControlPortGuard() || !op.BuiltinProfiles() {
		t.Fatal("nil operator must mean today's behavior")
	}
	if op.Ceiling() != nil || op.Upstream() != nil || op.InternalZone() != nil || op.DenyFloor() != nil || op.DefaultAllowOut() != nil || op.OrgProfileNames() != nil {
		t.Fatal("nil operator accessors")
	}
	if _, ok := op.OrgProfile("org:x"); ok {
		t.Fatal("nil operator has no profiles")
	}
	if g := op.Guard(); g.Zone != nil || g.Strict {
		t.Fatal("nil guard")
	}
	if !op.IsolateGuard().Strict {
		t.Fatal("isolate stays strict")
	}
	op2, err := Parse([]byte("version: 1\nisolate_typo: true\n"))
	if err == nil || op2 != nil {
		t.Fatal("unknown keys must be rejected")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"version":            "version: 2\n",
		"unknown key":        "version: 1\nfoo: bar\n",
		"zone public cidr":   "version: 1\ninternal_zone: {suffixes: [corp.x], cidrs: [8.8.8.0/24]}\n",
		"bad floor":          "version: 1\ndeny_cidrs: [not-a-cidr]\n",
		"v6 floor":           "version: 1\ndeny_cidrs: [\"fd00::/8\"]\n",
		"bad ceiling":        "version: 1\nceiling: {allow_out: [\"*.com\"]}\ndefault_policy: {mode: block_all}\n",
		"open with ceiling":  "version: 1\nceiling: {allow_out: [pypi.org]}\n",
		"open with allow":    "version: 1\ndefault_policy: {allow_out: [pypi.org]}\n",
		"block with allow":   "version: 1\ndefault_policy: {mode: block_all, allow_out: [pypi.org]}\n",
		"allowlist empty":    "version: 1\ndefault_policy: {mode: allowlist}\n",
		"unknown org ref":    "version: 1\ndefault_policy: {mode: allowlist, allow_out: [org:nope]}\n",
		"default over ceil":  "version: 1\nceiling: {allow_out: [pypi.org]}\ndefault_policy: {mode: allowlist, allow_out: [github.com]}\n",
		"bad default entry":  "version: 1\ndefault_policy: {mode: allowlist, allow_out: [\"*.com\"]}\n",
		"weird mode":         "version: 1\ndefault_policy: {mode: sometimes}\n",
		"bad profile name":   "version: 1\norg_profiles: {\"Bad Name\": {allow_out: [pypi.org]}}\n",
		"bad profile entry":  "version: 1\norg_profiles: {p: {allow_out: [\"*.com\"]}}\n",
		"profile over ceil":  "version: 1\nceiling: {allow_out: [pypi.org]}\ndefault_policy: {mode: block_all}\norg_profiles: {p: {allow_out: [github.com]}}\n",
		"bad upstream url":   "version: 1\nupstream_proxy: {url: \"socks5://x:1\"}\n",
		"bad synthetic cidr": "version: 1\nupstream_proxy: {url: \"http://p:8080\", synthetic_dns_cidr: 198.18.0.0/30}\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestWatcherLastGoodAndBootError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "egress-policy.yaml")
	if w := NewWatcher("", nil, nil); w.Current() != nil || w.BootError() != nil {
		t.Fatal("no path = no operator")
	}
	if w := NewWatcher(path, nil, nil); w.Current() != nil || w.BootError() != nil {
		t.Fatal("a missing file is not a boot error")
	}
	if err := os.WriteFile(path, []byte("version: 1\nnope: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := NewWatcher(path, nil, nil); !errors.Is(w.BootError(), ErrInvalidAtBoot) {
		t.Fatalf("invalid at boot: %v", w.BootError())
	}
	if err := os.WriteFile(path, []byte("version: 1\ndefault_policy: {mode: block_all}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var changes atomic.Int32
	w := NewWatcher(path, nil, func(*Operator) { changes.Add(1) })
	if w.Current() == nil || w.Current().DefaultMode() != ModeBlockAll || changes.Load() != 1 {
		t.Fatalf("load: %v changes=%d", w.Current(), changes.Load())
	}
	// An invalid edit keeps the last good file and counts a failure.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("version: 1\ndefault_policy: {mode: sometimes}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.Reload(); err == nil {
		t.Fatal("invalid reload must error")
	}
	if w.Current().DefaultMode() != ModeBlockAll || w.Failures() == 0 {
		t.Fatal("last good file must survive an invalid reload")
	}
	// The poll does not re-parse the same broken version every tick.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := w.Failures()
	go w.Run(ctx, 20*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	if w.Failures() != failed {
		t.Fatalf("one broken edit counted %d failures", w.Failures()-failed)
	}
	// The mtime poll picks up a valid edit.
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for w.Current().DefaultMode() != ModeOpen && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if w.Current().DefaultMode() != ModeOpen || changes.Load() < 2 {
		t.Fatalf("poll did not reload: mode=%s changes=%d", w.Current().DefaultMode(), changes.Load())
	}
	_ = os.Remove(path)
	if err := w.Reload(); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("reload of a removed file: %v", err)
	}
	var nilW *Watcher
	if nilW.Current() != nil || nilW.BootError() != nil {
		t.Fatal("nil watcher")
	}
	nilW.Run(ctx, time.Millisecond)
}

// TestUpstreamDialer (§5.10 PC-4): credentials come from a 0600 auth_file;
// a looser mode or a missing file is refused; ProxiesName answers without
// reading them.
func TestUpstreamDialer(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "proxy-auth")
	if err := os.WriteFile(auth, []byte("aerol:s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "version: 1\ninternal_zone: {suffixes: [corp.bank.internal], cidrs: [10.0.0.0/8]}\nupstream_proxy: {url: \"http://10.1.1.1:3128\", auth_file: \"" + auth + "\", no_proxy: [mirror.example]}\n"
	op, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	up, err := op.UpstreamDialer()
	if err != nil || up.ProxyHeader().Get("Proxy-Authorization") == "" {
		t.Fatalf("dialer: %v", err)
	}
	if !op.ProxiesName("pypi.org") || op.ProxiesName("git.corp.bank.internal") || op.ProxiesName("mirror.example") {
		t.Fatal("ProxiesName must honor the zone and no_proxy")
	}
	if err := os.Chmod(auth, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := op.UpstreamDialer(); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("a world-readable auth_file must be refused: %v", err)
	}
	_ = os.Remove(auth)
	if _, err := op.UpstreamDialer(); err == nil {
		t.Fatal("a missing auth_file must be refused")
	}
	if _, err := Parse([]byte("version: 1\nupstream_proxy: {url: \"http://p:3128\", no_proxy: [\"bad host!\"]}\n")); err == nil {
		t.Fatal("a bad no_proxy entry must fail the load")
	}
	none, _ := Parse([]byte("version: 1\n"))
	if up, err := none.UpstreamDialer(); up != nil || err != nil || none.ProxiesName("pypi.org") {
		t.Fatal("no upstream configured")
	}
	noAuth, _ := Parse([]byte("version: 1\nupstream_proxy: {url: \"http://p:3128\"}\n"))
	if up, err := noAuth.UpstreamDialer(); err != nil || up.ProxyHeader() != nil {
		t.Fatalf("no auth_file: %v", err)
	}
}

// TestParseLargeOrgProfile: an org profile is held to the profile cap (512),
// not the 64-entry inline cap a create gets.
func TestParseLargeOrgProfile(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\norg_profiles:\n  big:\n    allow_out:\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "      - h%d.example.com\n", i)
	}
	if _, err := Parse([]byte(b.String())); err != nil {
		t.Fatalf("a 100-host org profile must parse: %v", err)
	}
	for i := 100; i < 513; i++ {
		fmt.Fprintf(&b, "      - h%d.example.com\n", i)
	}
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Fatal("a profile over 512 hostnames must be refused")
	}
}
