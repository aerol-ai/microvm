package rootpolicy

import (
	"strings"
	"testing"
)

func TestCheckFirecrackerFile(t *testing.T) {
	for _, ok := range []string{FirecrackerRootfs, FirecrackerOverlay} {
		if err := CheckFirecrackerFile(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", FirecrackerKernel, "firecracker", "api.socket", "vsock.sock", "../rootfs.ext4",
		"stage/rootfs.ext4", "rootfs.ext4/", "snapshot.memory", "dev"} {
		if err := CheckFirecrackerFile(bad); err == nil || RuleOf(err) != RuleHost {
			t.Errorf("%q: %v, want a %s refusal", bad, err, RuleHost)
		}
	}
}

func TestFirecrackerJail(t *testing.T) {
	dir, root, stage, err := FirecrackerJail("/srv/jailer", "sb-1")
	if err != nil || dir != "/srv/jailer/firecracker/sb-1" || root != dir+"/root" || stage != dir+"/stage" {
		t.Fatalf("jail = %q %q %q, %v", dir, root, stage, err)
	}
	for _, tc := range []struct{ base, id string }{
		{"/srv/jailer", "../../etc"}, {"/srv/jailer", "aerolvm-x"}, {"relative", "sb-1"}, {"/", "sb-1"},
		{"/srv/jailer/", "sb-1"}, {"/srv/jailer", strings.Repeat("a", 90)},
	} {
		if _, _, _, err := FirecrackerJail(tc.base, tc.id); err == nil || RuleOf(err) != RuleHost {
			t.Errorf("FirecrackerJail(%q, %q) = %v, want a %s refusal", tc.base, tc.id, err, RuleHost)
		}
	}
}

func TestCheckTap(t *testing.T) {
	s, err := CheckTap("fctap3", "172.16.0.0/20", 256)
	if err != nil || s.TapName != "fctap3" || s.HostIP != "172.16.0.13" || s.GuestIP != "172.16.0.14" || s.CIDR != "172.16.0.12/30" || s.VsockCID != 6 {
		t.Fatalf("CheckTap = %+v, %v", s, err)
	}
	for _, tc := range []struct {
		name, base string
		size       int
	}{
		{"eth0", "172.16.0.0/20", 256}, {"lo", "172.16.0.0/20", 256}, {"fctap256", "172.16.0.0/20", 256},
		{"fctap01", "172.16.0.0/20", 256}, {"fctap3", "172.16.0.0/28", 256}, {"fctap3", "fd00::/64", 256},
	} {
		if _, err := CheckTap(tc.name, tc.base, tc.size); err == nil || RuleOf(err) != RuleTap {
			t.Errorf("CheckTap(%q, %q, %d) = %v, want a %s refusal", tc.name, tc.base, tc.size, err, RuleTap)
		}
	}
}

func TestCheckTapBase(t *testing.T) {
	if err := CheckTapBase("172.16.0.0/20", 256); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		base string
		size int
	}{{"172.16.0.9/20", 256}, {"172.16.0.0/24", 256}, {"fd00::/64", 4}, {"x", 4}, {"172.16.0.0/16", 0}} {
		if err := CheckTapBase(tc.base, tc.size); err == nil || RuleOf(err) != RuleTap {
			t.Errorf("CheckTapBase(%q, %d) = %v, want a %s refusal", tc.base, tc.size, err, RuleTap)
		}
	}
}

func TestCheckFilesystemSize(t *testing.T) {
	for _, ok := range []uint64{1, 1024, 1024 << 10} {
		if err := CheckFilesystemSize(ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
	for _, bad := range []uint64{0, 1024<<10 + 1, 1 << 62} {
		if err := CheckFilesystemSize(bad); err == nil || RuleOf(err) != RuleHost {
			t.Errorf("%d: %v", bad, err)
		}
	}
}

// TestCheckGuestAddress (M1 PR 14): a guest's rules are keyed by the guest
// end of one of the pool's /30s, and by nothing else: never a TAP's host
// end, a /30's network or broadcast address, an address past the pool or
// outside the base, nor anything that is not a plain IPv4 address.
func TestCheckGuestAddress(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want string
	}{{"172.16.0.2", "fctap0"}, {"172.16.0.14", "fctap3"}, {"172.16.3.254", "fctap255"}} {
		s, err := CheckGuestAddress("172.16.0.0/20", 256, tc.ip)
		if err != nil || s.TapName != tc.want || s.GuestIP != tc.ip {
			t.Errorf("CheckGuestAddress(%s) = %+v, %v; want %s", tc.ip, s, err, tc.want)
		}
	}
	for _, tc := range []struct {
		name, base string
		size       int
		ip         string
	}{
		{"a TAP's host end", "172.16.0.0/20", 256, "172.16.0.13"},
		{"a /30's network address", "172.16.0.0/20", 256, "172.16.0.12"},
		{"a /30's broadcast address", "172.16.0.0/20", 256, "172.16.0.15"},
		{"past the pool", "172.16.0.0/20", 256, "172.16.4.2"},
		{"past a small pool", "172.16.0.0/20", 4, "172.16.0.18"},
		{"outside the base", "172.16.0.0/20", 256, "10.88.0.2"},
		{"the node", "172.16.0.0/20", 256, "127.0.0.1"},
		{"IPv6", "172.16.0.0/20", 256, "fe80::2"},
		{"a zone", "172.16.0.0/20", 256, "172.16.0.2%eth0"},
		{"a network", "172.16.0.0/20", 256, "172.16.0.2/32"},
		{"rule text", "172.16.0.0/20", 256, "172.16.0.2 -j ACCEPT"},
		{"empty", "172.16.0.0/20", 256, ""},
		{"a bad base", "172.16.0.9/20", 256, "172.16.0.2"},
		{"no pool", "172.16.0.0/20", 0, "172.16.0.2"},
	} {
		if _, err := CheckGuestAddress(tc.base, tc.size, tc.ip); err == nil || RuleOf(err) != RuleAddress {
			t.Errorf("%s: CheckGuestAddress(%q, %d, %q) = %v, want a %s refusal", tc.name, tc.base, tc.size, tc.ip, err, RuleAddress)
		}
	}
}

// TestFirecrackerFileNames (M1 PR 14b): the files shared into a VM
// read-only and the files handed out of one, each from its own fixed list.
func TestFirecrackerFileNames(t *testing.T) {
	for _, tc := range []struct {
		check   func(string) error
		ok, bad []string
	}{
		{CheckFirecrackerShare, []string{FirecrackerMemory, FirecrackerState, FirecrackerRootfs},
			[]string{FirecrackerOverlay, FirecrackerSavedMemory, FirecrackerSavedState, FirecrackerKernel, "", "api.socket", "vsock.sock", "firecracker", "dev", "../snapshot.memory",
				"stage/snapshot.state", "/etc/shadow", "snapshot.memory/"}},
		{CheckFirecrackerHandOut, []string{FirecrackerSavedMemory, FirecrackerSavedState, FirecrackerMemory, FirecrackerState, FirecrackerRootfs, FirecrackerOverlay},
			[]string{FirecrackerKernel, "", "api.socket", "vsock.sock", "firecracker", "dev/kvm", "../rootfs.ext4", "/etc/shadow", "."}},
	} {
		for _, n := range tc.ok {
			if err := tc.check(n); err != nil {
				t.Errorf("%q: %v", n, err)
			}
		}
		for _, n := range tc.bad {
			if err := tc.check(n); err == nil || RuleOf(err) != RuleHost {
				t.Errorf("%q: %v, want a %s refusal", n, err, RuleHost)
			}
		}
	}
	if err := CheckFirecrackerNames([]string{FirecrackerMemory, FirecrackerState}, CheckFirecrackerShare); err != nil {
		t.Fatal(err)
	}
	for _, names := range [][]string{nil, {FirecrackerMemory, FirecrackerMemory}, {FirecrackerMemory, FirecrackerKernel}} {
		if err := CheckFirecrackerNames(names, CheckFirecrackerShare); err == nil || RuleOf(err) != RuleHost {
			t.Errorf("%q: %v, want a %s refusal", names, err, RuleHost)
		}
	}
	if MaxFirecrackerFileBytes != 1<<40 {
		t.Fatalf("the cap is %d, want a disk's cap, 1 TiB", MaxFirecrackerFileBytes)
	}
}

func TestCheckSnapshotCID(t *testing.T) {
	for _, ok := range []uint32{3, 4, 258, 1<<24 - 1} {
		if err := CheckSnapshotCID(ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
	for _, bad := range []uint32{0, 1, 2, 1 << 24, 1<<32 - 1} {
		if err := CheckSnapshotCID(bad); err == nil || RuleOf(err) != RuleTap {
			t.Errorf("%d: %v, want a %s refusal", bad, err, RuleTap)
		}
	}
}
