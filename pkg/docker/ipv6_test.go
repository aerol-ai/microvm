package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

func noHostIPv6(t *testing.T) {
	t.Helper()
	orig := sandboxIPv6Sysctls
	sandboxIPv6Sysctls = func() map[string]string { return nil }
	t.Cleanup(func() { sandboxIPv6Sysctls = orig })
}

func ipv6Off(sysctls map[string]string) bool {
	return sysctls[hostnet.SysctlAllDisableIPv6] == "1" && sysctls[hostnet.SysctlDefaultDisableIPv6] == "1"
}

func TestSetSandboxIPv6Off(t *testing.T) {
	for _, network := range []string{"", "bridge", "aerolvm-sandboxes", "none"} {
		hc := map[string]any{}
		setSandboxIPv6Off(hc, network)
		got, _ := hc["Sysctls"].(map[string]string)
		if !ipv6Off(got) {
			t.Fatalf("network %q: Sysctls = %v", network, hc["Sysctls"])
		}
	}
	// docker refuses net.* sysctls in the host's namespace.
	hc := map[string]any{}
	setSandboxIPv6Off(hc, "host")
	if _, ok := hc["Sysctls"]; ok {
		t.Fatal("host network got sysctls")
	}
	t.Run("host_without_ipv6", func(t *testing.T) {
		noHostIPv6(t)
		hc := map[string]any{}
		setSandboxIPv6Off(hc, "bridge")
		if _, ok := hc["Sysctls"]; ok {
			t.Fatal("a host without IPv6 got sysctls runc would fail on")
		}
		if !hasSandboxIPv6Off(nil) {
			t.Fatal("nothing to turn off on a host without IPv6")
		}
	})
}

func TestHasSandboxIPv6Off(t *testing.T) {
	if hasSandboxIPv6Off(nil) || hasSandboxIPv6Off(map[string]string{hostnet.SysctlAllDisableIPv6: "1"}) {
		t.Fatal("a container without both sysctls reads as IPv6 off")
	}
	if hasSandboxIPv6Off(map[string]string{hostnet.SysctlAllDisableIPv6: "0", hostnet.SysctlDefaultDisableIPv6: "1"}) {
		t.Fatal("all=0 reads as IPv6 off")
	}
	if !hasSandboxIPv6Off(sandboxIPv6Sysctls()) {
		t.Fatal("the sysctls setSandboxIPv6Off sends must read as IPv6 off")
	}
}

// TestCreateOwnNetnsTurnsIPv6Off is the regression test for the docker side
// of the link-local hole: a sandbox that gets its own network namespace
// (no warm pause slot, or gVisor, which never adopts one) is created with
// IPv6 off.
func TestCreateOwnNetnsTurnsIPv6Off(t *testing.T) {
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor} {
		t.Run(rt, func(t *testing.T) {
			d := newNetnsFakeDaemon()
			c := newNetnsCreateClient(t, d, true)
			if rt == models.RuntimeDocker {
				if _, ok := c.netnsPool.Adopt(context.Background(), "sb-drain"); !ok {
					t.Fatal("drain adopt should have hit")
				}
			}
			c.toolboxWaitTimeout = 50 * time.Millisecond
			_, _ = c.Create(context.Background(), models.CreateSandboxRequest{Image: "img", Runtime: rt}, "sb-own", "tok", nil)
			var sb *netnsFakeContainer
			for i := range d.created {
				if d.created[i].name == "sb-own" {
					sb = &d.created[i]
				}
			}
			if sb == nil {
				t.Fatal("sandbox container was never created")
			}
			if strings.HasPrefix(sb.netMode, "container:") {
				t.Fatalf("expected an own netns, got %q", sb.netMode)
			}
			if !ipv6Off(sb.sysctls) {
				t.Fatalf("sandbox created with Sysctls %v, want IPv6 off", sb.sysctls)
			}
		})
	}
}

// A sandbox that joins a warm pause's namespace inherits IPv6 off from the
// pause (which owns the namespace) and sends no net.* sysctls of its own.
func TestCreateAdoptedNetnsInheritsIPv6Off(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsCreateClient(t, d, true)
	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-join", "tok", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	pause := d.byRef(netnsAdoptedName("sb-join"))
	joiner := d.byRef("sb-join")
	if pause == nil || joiner == nil {
		t.Fatalf("pause=%v joiner=%v", pause, joiner)
	}
	if !ipv6Off(pause.sysctls) {
		t.Fatalf("pause created with Sysctls %v, want IPv6 off", pause.sysctls)
	}
	if !strings.HasPrefix(joiner.netMode, "container:") || len(joiner.sysctls) != 0 {
		t.Fatalf("joiner netMode=%q sysctls=%v, want a joined netns with no sysctls", joiner.netMode, joiner.sysctls)
	}
}

// On upgrade, a free pause an older daemon started has IPv6 on in its
// namespace: the boot reconcile replaces it instead of letting a sandbox
// join it. One started by this daemon is kept.
func TestNetnsPoolReconcileReplacesPausesWithIPv6On(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	d.add(&netnsFakeContainer{
		id: "pre-fix", name: netnsFreePrefix + "bbbb", running: true, ip: "172.30.9.5",
		labels: map[string]string{netnsPauseLabelKey: "true"},
	})
	d.add(&netnsFakeContainer{
		id: "post-fix", name: netnsFreePrefix + "cccc", running: true, ip: "172.30.9.6",
		labels: map[string]string{netnsPauseLabelKey: "true"}, sysctls: sandboxIPv6Sysctls(),
	})
	p := newTestNetnsPool(c, 4)
	p.reconcile(context.Background())
	if d.byRef("pre-fix") != nil {
		t.Fatal("a free pause with IPv6 on survived the reconcile")
	}
	if d.byRef("post-fix") == nil || p.size() != 1 {
		t.Fatalf("the IPv6-off survivor must be kept: size=%d", p.size())
	}
	// Refill replaces it with pauses that have IPv6 off.
	p.refill(context.Background())
	for _, cont := range d.created {
		if !ipv6Off(cont.sysctls) {
			t.Fatalf("refilled pause %s has Sysctls %v", cont.name, cont.sysctls)
		}
	}
}

// On a host without IPv6 there is nothing to turn off, so survivors stay.
func TestNetnsPoolReconcileNoIPv6KeepsSurvivors(t *testing.T) {
	noHostIPv6(t)
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	d.add(&netnsFakeContainer{
		id: "old", name: netnsFreePrefix + "dddd", running: true, ip: "172.30.9.7",
		labels: map[string]string{netnsPauseLabelKey: "true"},
	})
	p := newTestNetnsPool(c, 4)
	p.reconcile(context.Background())
	if p.size() != 1 {
		t.Fatalf("size = %d, want the survivor kept", p.size())
	}
}

// Warm parks become sandboxes on adopt, so they are created with IPv6 off.
func TestParkTurnsIPv6Off(t *testing.T) {
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor} {
		t.Run(rt, func(t *testing.T) {
			d := &poolFakeDaemon{t: t}
			c := newPoolClient(t, d, func(c *Client) {
				c.readyDir = coverageReadyDir(t)
				c.network = "custom"
			})
			// The body is all this test needs; stop the park at start.
			d.start = func() *http.Response { return textResponse(http.StatusInternalServerError, "stop here") }
			if _, err := c.parkContainer(context.Background(), "park-v6", dockerpool.Key{Image: "alpine:3.20", Runtime: rt}); err == nil {
				t.Fatal("park should fail at start")
			}
			if len(d.createBodies) == 0 {
				t.Fatal("no park create was sent")
			}
			var req struct {
				HostConfig struct {
					Sysctls map[string]string `json:"Sysctls"`
				} `json:"HostConfig"`
			}
			if err := json.Unmarshal(d.createBodies[len(d.createBodies)-1], &req); err != nil {
				t.Fatal(err)
			}
			if !ipv6Off(req.HostConfig.Sysctls) {
				t.Fatalf("park created with Sysctls %v, want IPv6 off", req.HostConfig.Sysctls)
			}
		})
	}
}
