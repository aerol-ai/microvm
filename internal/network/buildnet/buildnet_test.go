package buildnet

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeHost records what Up and Down ask of the namespace host.
type fakeHost struct {
	addrs      []string
	addrsErr   error
	realizeIP  string
	realizeErr error
	removeErr  error
	realized   []netns.Slot
	removed    []netns.Slot
}

func (f *fakeHost) Realize(_ context.Context, s netns.Slot) (string, string, error) {
	f.realized = append(f.realized, s)
	if f.realizeErr != nil {
		return "", "", f.realizeErr
	}
	return "/run/netns/" + s.NetnsName(), f.realizeIP, nil
}

func (f *fakeHost) Remove(_ context.Context, s netns.Slot) error {
	f.removed = append(f.removed, s)
	return f.removeErr
}

func (f *fakeHost) IPv4Addrs(context.Context, netns.Slot) ([]string, error) {
	return f.addrs, f.addrsErr
}

var sandboxes = netip.MustParsePrefix("10.88.0.0/16")

// testConfig is a Config whose files live in a temp folder; present says
// whether the namespace is already there.
func testConfig(t *testing.T, h Host, present bool) Config {
	t.Helper()
	dir := t.TempDir()
	host := filepath.Join(dir, "host-resolv.conf")
	if err := os.WriteFile(host, []byte("nameserver 127.0.0.53\nnameserver 10.0.0.2\nsearch ec2.internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Config{Host: h, Subnet: sandboxes, NetnsRoot: "/run/netns", HostResolvConf: host,
		ResolvConf: filepath.Join(dir, "out", "resolv.conf"), exists: func(string) bool { return present }}
}

// The name can never be a sandbox's or a pool slot's: a sandbox namespace
// is named by its ID.
func TestNameIsNoSandboxID(t *testing.T) {
	if err := models.ValidateSandboxID(Name); err == nil {
		t.Fatalf("%q is a valid sandbox ID; a sandbox could take the build's namespace", Name)
	}
}

func TestUpBuildsTheNamespace(t *testing.T) {
	h := &fakeHost{realizeIP: "10.88.0.9"}
	cfg := testConfig(t, h, false)
	res, err := Up(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if !res.Built || res.Path != "/run/netns/"+Name || res.IP != netip.MustParseAddr("10.88.0.9") {
		t.Fatalf("result %+v", res)
	}
	if len(h.realized) != 1 || h.realized[0].SandboxID != Name || len(h.removed) != 0 {
		t.Fatalf("realized %v removed %v", h.realized, h.removed)
	}
	body, err := os.ReadFile(cfg.ResolvConf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "127.0.0.53") || !strings.Contains(string(body), "nameserver 10.0.0.2") || !strings.Contains(string(body), "search ec2.internal") {
		t.Fatalf("resolv.conf %q: want the host's upstream resolvers, no loopback stub", body)
	}
	if info, err := os.Stat(cfg.ResolvConf); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("resolv.conf mode %v, %v; the build user must read it", info.Mode(), err)
	}
}

// A namespace already there with an address in range is kept: a running
// buildkitd is in it.
func TestUpKeepsAHealthyNamespace(t *testing.T) {
	h := &fakeHost{addrs: []string{"10.88.3.4"}}
	cfg := testConfig(t, h, true)
	res, err := Up(context.Background(), cfg)
	if err != nil || res.Built || res.IP != netip.MustParseAddr("10.88.3.4") {
		t.Fatalf("Up = %+v, %v", res, err)
	}
	if len(h.realized) != 0 || len(h.removed) != 0 {
		t.Fatalf("realized %v removed %v, want the namespace left alone", h.realized, h.removed)
	}
	if _, err := os.Stat(cfg.ResolvConf); err != nil {
		t.Fatalf("resolv.conf not refreshed: %v", err)
	}
}

// A namespace from another range (the operator moved the sandboxes), one
// with no address, or one that cannot be read is replaced: an address
// outside the sandboxes' range gets none of their firewall rules.
func TestUpReplacesAStaleNamespace(t *testing.T) {
	for name, h := range map[string]*fakeHost{
		"another range":   {addrs: []string{"10.200.0.5"}, realizeIP: "10.88.0.7"},
		"no address":      {realizeIP: "10.88.0.7"},
		"the network id":  {addrs: []string{"10.88.0.0"}, realizeIP: "10.88.0.7"},
		"unreadable":      {addrsErr: errors.New("not a namespace"), realizeIP: "10.88.0.7"},
		"an IPv6 address": {addrs: []string{"fd00::1"}, realizeIP: "10.88.0.7"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := Up(context.Background(), testConfig(t, h, true))
			if err != nil || !res.Built || res.IP != netip.MustParseAddr("10.88.0.7") {
				t.Fatalf("Up = %+v, %v", res, err)
			}
			if len(h.removed) != 1 || h.removed[0].NetnsPath != "/run/netns/"+Name || len(h.realized) != 1 {
				t.Fatalf("removed %v realized %v", h.removed, h.realized)
			}
		})
	}
}

func TestUpFailures(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name    string
		h       *fakeHost
		present bool
		edit    func(*Config)
		want    string
		removed int
	}{
		{name: "no host", h: nil, edit: func(c *Config) { c.Host = nil }, want: "netns host is required"},
		{name: "no range", h: &fakeHost{}, edit: func(c *Config) { c.Subnet = netip.Prefix{} }, want: "not an IPv4 range"},
		{name: "an IPv6 range", h: &fakeHost{}, edit: func(c *Config) { c.Subnet = netip.MustParsePrefix("fd00::/64") }, want: "not an IPv4 range"},
		{name: "a stale one that will not go", h: &fakeHost{addrs: []string{"10.1.0.1"}, removeErr: boom}, present: true, want: "remove the namespace", removed: 1},
		{name: "CNI fails", h: &fakeHost{realizeErr: boom}, want: "boom"},
		{name: "CNI hands out another range", h: &fakeHost{realizeIP: "192.168.1.5"}, want: "not in the sandboxes' range", removed: 1},
		{name: "resolv.conf cannot be written", h: &fakeHost{realizeIP: "10.88.0.2"}, edit: func(c *Config) {
			blocker := filepath.Join(filepath.Dir(c.ResolvConf), "..", "blocker")
			_ = os.WriteFile(blocker, nil, 0o644)
			c.ResolvConf = filepath.Join(blocker, "resolv.conf")
		}, want: "resolv.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h Host
			if tc.h != nil {
				h = tc.h
			}
			cfg := testConfig(t, h, tc.present)
			if tc.edit != nil {
				tc.edit(&cfg)
			}
			_, err := Up(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.h != nil && len(tc.h.removed) != tc.removed {
				t.Fatalf("removed %v, want %d", tc.h.removed, tc.removed)
			}
		})
	}
}

func TestDown(t *testing.T) {
	h := &fakeHost{addrs: []string{"10.88.0.9"}}
	if err := Down(context.Background(), testConfig(t, h, true)); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if len(h.removed) != 1 || h.removed[0].ContainerIP != "10.88.0.9" || h.removed[0].NetnsPath != "/run/netns/"+Name {
		t.Fatalf("removed %v, want the namespace and its address", h.removed)
	}
	// Not there: nothing to do.
	h = &fakeHost{}
	if err := Down(context.Background(), testConfig(t, h, false)); err != nil || len(h.removed) != 0 {
		t.Fatalf("Down of nothing: %v, removed %v", err, h.removed)
	}
	// An unreadable one still goes, without its address.
	h = &fakeHost{addrsErr: errors.New("no")}
	if err := Down(context.Background(), testConfig(t, h, true)); err != nil || len(h.removed) != 1 || h.removed[0].ContainerIP != "" {
		t.Fatalf("Down: %v, removed %v", err, h.removed)
	}
	h = &fakeHost{removeErr: errors.New("busy")}
	if err := Down(context.Background(), testConfig(t, h, true)); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("Down = %v", err)
	}
	if err := Down(context.Background(), Config{}); err == nil {
		t.Fatal("Down with no host")
	}
}

// The defaults: /run/netns, the real lstat, and the fixed resolv.conf path.
func TestConfigDefaults(t *testing.T) {
	var c Config
	if c.netnsRoot() != "/run/netns" {
		t.Fatalf("root %q", c.netnsRoot())
	}
	if c.present(filepath.Join(t.TempDir(), "none")) {
		t.Fatal("a missing path is present")
	}
	if !c.present(t.TempDir()) {
		t.Fatal("a folder that is there is not present")
	}
	if DefaultResolvConf != "/run/aerolvm-build-net/resolv.conf" {
		t.Fatalf("DefaultResolvConf = %q: install.sh's unit binds this path", DefaultResolvConf)
	}
}
