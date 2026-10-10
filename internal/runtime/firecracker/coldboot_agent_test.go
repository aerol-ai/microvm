package firecracker

import (
	"os"
	"os/exec"
	"path/filepath"
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
	if len(files) != 4 {
		t.Fatalf("want 4 injected files, got %d", len(files))
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

// TestToolboxdInitMountsDevpts guards terminals in Firecracker guests.
// Nothing but this shim mounts devpts in a VM, and without it opening
// /dev/ptmx fails with ENODEV: no `aerolvm shell`, `exec -t` or SSH (UC-231).
// The mount must follow the devtmpfs mount on /dev, which would hide it,
// and precede the exec of toolboxd.
func TestToolboxdInitMountsDevpts(t *testing.T) {
	script := string(toolboxdInitScript)
	at := func(needle string) int {
		t.Helper()
		i := strings.Index(script, needle)
		if i < 0 {
			t.Fatalf("toolboxd-init.sh has no %q", needle)
		}
		return i
	}
	dev := at("mount -t devtmpfs dev  /dev")
	pts := at("mount -t devpts -o newinstance,ptmxmode=0666,mode=0620,gid=5 devpts /dev/pts")
	mkdir := at("mkdir -p /dev/pts")
	agent := at("exec /usr/local/bin/toolboxd")
	if !(dev < mkdir && mkdir < pts && pts < agent) {
		t.Fatalf("toolboxd-init.sh order: devtmpfs@%d mkdir@%d devpts@%d exec@%d", dev, mkdir, pts, agent)
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("toolboxd-init.sh doesn't parse: %v\n%s", err, out)
		}
	}
}

// TestColdBootInjectsTheHostResolvers is the UC-204 regression guard. A guest
// built from a stock image has no resolv.conf (alpine ships none), so musl
// asked 127.0.0.1 and no lookup reached the egress gateway's DNS redirect on
// the TAP. The host's upstream resolvers are injected, loopback stubs
// dropped, with or without a slot (the template builder passes none).
func TestColdBootInjectsTheHostResolvers(t *testing.T) {
	old := guestResolvConf
	t.Cleanup(func() { guestResolvConf = old })
	guestResolvConf = func() []byte { return []byte("search ec2.internal\nnameserver 10.0.0.2\n") }

	for _, slot := range []*TapSlot{{GuestIP: "172.16.0.2", HostIP: "172.16.0.1", CIDR: "172.16.0.0/30"}, nil} {
		var resolv *InjectFile
		for _, f := range coldBootInjectFiles("/opt/aerolvm/toolboxd", "tok", slot) {
			if f.GuestPath == guestResolvPath {
				resolv = &f
			}
		}
		if resolv == nil || string(resolv.Content) != "search ec2.internal\nnameserver 10.0.0.2\n" || resolv.Mode != 0o644 {
			t.Fatalf("slot %v: resolv inject = %+v", slot, resolv)
		}
	}

	// The real generator never hands a guest a loopback resolver.
	guestResolvConf = old
	if body := string(guestResolvConf()); !strings.Contains(body, "nameserver ") || strings.Contains(body, "nameserver 127.") {
		t.Fatalf("guest resolv.conf = %q", body)
	}

	// A host file that can't be read still leaves the guest a resolver.
	oldPath := hostResolvConfPath
	t.Cleanup(func() { hostResolvConfPath = oldPath })
	hostResolvConfPath = t.TempDir() // a directory: opens, then fails to read
	if body := string(guestResolvConf()); body != "nameserver 8.8.8.8\n" {
		t.Fatalf("guest resolv.conf from an unreadable host file = %q", body)
	}
}

// TestToolboxdInitInstallsResolvConf runs the shim's name-resolution block
// against a scratch /etc: it replaces the image's resolv.conf, including one
// that is a symlink to nowhere, and leaves an image alone when nothing was
// injected.
func TestToolboxdInitInstallsResolvConf(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := string(toolboxdInitScript)
	start := strings.Index(script, "if [ -f /etc/toolboxd.resolv.conf ]; then")
	end := strings.Index(script[start:], "\nfi\n")
	if start < 0 || end < 0 {
		t.Fatal("toolboxd-init.sh has no resolv.conf block")
	}
	if strings.Index(script, "configure_network\n\n") > start || strings.Index(script, "exec /usr/local/bin/toolboxd") < start {
		t.Fatal("the resolv.conf block must run after configure_network and before the agent")
	}
	block := script[start : start+end+len("\nfi\n")]

	run := func(t *testing.T, etc string) {
		t.Helper()
		cmd := exec.Command(sh, "-c", strings.ReplaceAll(block, "/etc/", etc+"/"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("resolv.conf block: %v\n%s", err, out)
		}
	}
	read := func(t *testing.T, path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const injected = "search ec2.internal\nnameserver 10.0.0.2"

	t.Run("image ships none", func(t *testing.T) {
		etc := t.TempDir()
		mustWrite(t, filepath.Join(etc, "toolboxd.resolv.conf"), injected) // no trailing newline
		run(t, etc)
		if got := read(t, filepath.Join(etc, "resolv.conf")); got != injected+"\n" {
			t.Fatalf("resolv.conf = %q", got)
		}
	})
	t.Run("image ships a dangling symlink", func(t *testing.T) {
		etc := t.TempDir()
		mustWrite(t, filepath.Join(etc, "toolboxd.resolv.conf"), injected+"\n")
		if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(etc, "resolv.conf")); err != nil {
			t.Fatal(err)
		}
		run(t, etc)
		if fi, err := os.Lstat(filepath.Join(etc, "resolv.conf")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("resolv.conf is still a symlink: %v %v", fi, err)
		}
		if got := read(t, filepath.Join(etc, "resolv.conf")); got != injected+"\n" {
			t.Fatalf("resolv.conf = %q", got)
		}
	})
	t.Run("nothing injected", func(t *testing.T) {
		etc := t.TempDir()
		mustWrite(t, filepath.Join(etc, "resolv.conf"), "nameserver 1.1.1.1\n")
		run(t, etc)
		if got := read(t, filepath.Join(etc, "resolv.conf")); got != "nameserver 1.1.1.1\n" {
			t.Fatalf("an image's resolv.conf was touched with nothing injected: %q", got)
		}
	})
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
