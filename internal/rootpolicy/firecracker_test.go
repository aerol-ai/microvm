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
