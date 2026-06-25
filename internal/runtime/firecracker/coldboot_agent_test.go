package firecracker

import (
	"strings"
	"testing"
)

// TestColdBootInjectFiles_PutsAgentInGuest is the regression guard for the
// cold-boot exec failure (single-node-fc UC-44): a plain OCI image has no
// agent, so the guest must have toolboxd + its init shim + the per-sandbox
// token baked in, or Create's vsock handshake has no peer.
func TestColdBootInjectFiles_PutsAgentInGuest(t *testing.T) {
	slot := &TapSlot{GuestIP: "172.16.0.2", HostIP: "172.16.0.1", CIDR: "172.16.0.0/30"}
	files := coldBootInjectFiles("/opt/aerolvm/toolboxd", "tok-123", slot)
	if len(files) != 3 {
		t.Fatalf("want 3 injected files, got %d", len(files))
	}
	byPath := map[string]InjectFile{}
	for _, f := range files {
		byPath[f.GuestPath] = f
	}

	bin, ok := byPath[guestToolboxPath]
	if !ok || bin.HostPath != "/opt/aerolvm/toolboxd" || bin.Mode != 0o755 {
		t.Errorf("toolboxd inject wrong: %+v", bin)
	}
	init, ok := byPath[guestInitPath]
	if !ok || len(init.Content) == 0 || init.Mode != 0o755 {
		t.Errorf("init shim inject wrong: %+v", init)
	}
	if !strings.Contains(string(init.Content), "exec /usr/local/bin/toolboxd") {
		t.Errorf("init shim does not exec the agent:\n%s", init.Content)
	}
	if !strings.Contains(string(init.Content), "configure_network") {
		t.Errorf("init shim does not configure guest networking:\n%s", init.Content)
	}
	env, ok := byPath[guestEnvPath]
	if !ok || env.Mode != 0o600 {
		t.Errorf("env inject wrong mode: %+v", env)
	}
	if !strings.Contains(string(env.Content), "SB_TOOLBOX_TOKEN='tok-123'") {
		t.Errorf("env file missing token: %q", env.Content)
	}
	for _, want := range []string{
		"SB_TOOLBOX_GUEST_IP='172.16.0.2'",
		"SB_TOOLBOX_GATEWAY_IP='172.16.0.1'",
		"SB_TOOLBOX_NETMASK='255.255.255.252'",
		"SB_TOOLBOX_PREFIX_LEN='30'",
	} {
		if !strings.Contains(string(env.Content), want) {
			t.Errorf("env file missing %s: %q", want, env.Content)
		}
	}
}

func TestShellSingleQuote(t *testing.T) {
	if got := shellSingleQuote("tok'123"); got != `'tok'\''123'` {
		t.Fatalf("shellSingleQuote escaped token as %q", got)
	}
}

// TestColdBootInjectFiles_NoBinaryIsNil: with no toolbox binary configured
// the injector returns nil so the caller cold-boots an agent-less guest
// (and warns) rather than panicking on an empty HostPath.
func TestColdBootInjectFiles_NoBinaryIsNil(t *testing.T) {
	if files := coldBootInjectFiles("", "tok", nil); files != nil {
		t.Errorf("want nil with no binary, got %+v", files)
	}
}

// TestColdBootArgs covers the boot-args contract: base args always present;
// ip= autoconfig and init= override added only when their inputs are.
func TestColdBootArgs(t *testing.T) {
	slot := &TapSlot{GuestIP: "172.16.0.2", HostIP: "172.16.0.1", CIDR: "172.16.0.0/30"}

	full := coldBootArgs(slot, true)
	if !strings.Contains(full, "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off") {
		t.Errorf("missing/wrong ip= clause: %q", full)
	}
	if !strings.Contains(full, "init="+guestInitPath) {
		t.Errorf("missing init= clause: %q", full)
	}
	if !strings.Contains(full, "panic=1") {
		t.Errorf("base args dropped: %q", full)
	}

	// No agent injected -> no init= (fall back to the image's own init).
	if got := coldBootArgs(slot, false); strings.Contains(got, "init=") {
		t.Errorf("init= must be absent when agent not injected: %q", got)
	}
	// No/blank slot -> no ip= clause, but still boots.
	if got := coldBootArgs(nil, true); strings.Contains(got, "ip=") {
		t.Errorf("ip= must be absent for nil slot: %q", got)
	}
}

func TestNetmaskFromCIDR(t *testing.T) {
	for _, tc := range []struct{ cidr, want string }{
		{"172.16.0.0/30", "255.255.255.252"},
		{"10.0.0.0/24", "255.255.255.0"},
		{"192.168.1.0/16", "255.255.0.0"},
		{"2001:db8::/32", ""},
		{"bogus", ""},
		{"", ""},
	} {
		if got := netmaskFromCIDR(tc.cidr); got != tc.want {
			t.Errorf("netmaskFromCIDR(%q) = %q, want %q", tc.cidr, got, tc.want)
		}
	}
}

func TestPrefixLenFromCIDR(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want int
	}{
		{"172.16.0.0/30", 30},
		{"10.0.0.0/24", 24},
		{"2001:db8::/32", -1},
		{"bogus", -1},
	} {
		if got := prefixLenFromCIDR(tc.cidr); got != tc.want {
			t.Errorf("prefixLenFromCIDR(%q) = %d, want %d", tc.cidr, got, tc.want)
		}
	}
}

func TestKernelIPArg(t *testing.T) {
	full := &TapSlot{GuestIP: "172.16.0.2", HostIP: "172.16.0.1", CIDR: "172.16.0.0/30"}
	want := "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off"
	if got := kernelIPArg(full); got != want {
		t.Fatalf("kernelIPArg(full) = %q, want %q", got, want)
	}
	for _, slot := range []*TapSlot{
		nil,
		{},
		{GuestIP: "172.16.0.2"},
		{GuestIP: "172.16.0.2", HostIP: "172.16.0.1"},
		{GuestIP: "172.16.0.2", HostIP: "172.16.0.1", CIDR: "not-a-cidr"},
	} {
		if got := kernelIPArg(slot); got != "" {
			t.Errorf("kernelIPArg(%+v) = %q, want empty", slot, got)
		}
	}
}

func TestToolboxNetworkPayload(t *testing.T) {
	slot := &TapSlot{GuestIP: "172.16.0.6", HostIP: "172.16.0.5", CIDR: "172.16.0.4/30"}
	payload := toolboxNetworkPayload(slot)
	if payload["guest_ip"] != "172.16.0.6" || payload["gateway_ip"] != "172.16.0.5" || payload["netmask"] != "255.255.255.252" || payload["prefix_len"] != 30 {
		t.Fatalf("toolboxNetworkPayload = %+v", payload)
	}
}
