package nodejoin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The worker pod's preflight (P10): cgroup v2, the kernel and br_netfilter
// are hard requirements in a pod; /dev/kvm only on a Firecracker pool.
func TestPodPreflight(t *testing.T) {
	type machine struct {
		cgroupV2, bridgeNF, kvm bool
		release                 string // "" = no osrelease file
	}
	good := machine{cgroupV2: true, bridgeNF: true, release: "6.1.102-108.177.amzn2023.aarch64\n"}
	cases := []struct {
		name     string
		m        machine
		kvm      bool
		wantFail []string // failed check names, in order
	}{
		{name: "a good machine", m: good},
		{name: "kernel 5.10 exactly", m: machine{cgroupV2: true, bridgeNF: true, release: "5.10.226-214.880.amzn2.x86_64"}},
		{name: "kernel with a suffix on the minor", m: machine{cgroupV2: true, bridgeNF: true, release: "5.15+deb12"}},
		{name: "cgroup v1", m: machine{bridgeNF: true, release: "6.1.0"}, wantFail: []string{"cgroup v2"}},
		{name: "an old kernel", m: machine{cgroupV2: true, bridgeNF: true, release: "5.4.0-1103-aws"}, wantFail: []string{"kernel"}},
		{name: "an old major", m: machine{cgroupV2: true, bridgeNF: true, release: "4.19.0"}, wantFail: []string{"kernel"}},
		{name: "an unreadable kernel version", m: machine{cgroupV2: true, bridgeNF: true}, wantFail: []string{"kernel"}},
		{name: "a kernel version that does not parse", m: machine{cgroupV2: true, bridgeNF: true, release: "six"}, wantFail: []string{"kernel"}},
		{name: "a kernel version with no minor", m: machine{cgroupV2: true, bridgeNF: true, release: "6.x"}, wantFail: []string{"kernel"}},
		{name: "no br_netfilter (F2)", m: machine{cgroupV2: true, release: "6.1.0"}, wantFail: []string{"br_netfilter"}},
		{name: "a Firecracker pool without /dev/kvm", m: good, kvm: true, wantFail: []string{"kvm"}},
		{name: "a Firecracker pool with /dev/kvm", m: machine{cgroupV2: true, bridgeNF: true, kvm: true, release: "6.1.0"}, kvm: true},
		{name: "everything wrong", m: machine{release: "4.14.0"}, kvm: true, wantFail: []string{"cgroup v2", "kernel", "br_netfilter", "kvm"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := Paths{CgroupRoot: dir, KVMSysfs: filepath.Join(dir, "kvm"), OSRelease: filepath.Join(dir, "osrelease"),
				BridgeNF: filepath.Join(dir, "bridge-nf-call-iptables")}
			write := func(path, body string) {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.m.cgroupV2 {
				write(filepath.Join(dir, "cgroup.controllers"), "cpu memory\n")
			}
			if tc.m.bridgeNF {
				write(p.BridgeNF, "1\n")
			}
			if tc.m.kvm {
				write(p.KVMSysfs, "")
			}
			if tc.m.release != "" {
				write(p.OSRelease, tc.m.release)
			}
			backend := ""
			if tc.kvm {
				backend = PodFirecrackerKVM
			}
			r := PodPreflight(p, backend)
			var failed []string
			for _, c := range r.Checks {
				if c.Status == StatusFail {
					failed = append(failed, c.Name)
					if c.Detail == "" {
						t.Fatalf("%s failed with no detail", c.Name)
					}
				}
			}
			if strings.Join(failed, ",") != strings.Join(tc.wantFail, ",") {
				t.Fatalf("failed = %v, want %v\n%+v", failed, tc.wantFail, r.Checks)
			}
			if r.OK() != (len(tc.wantFail) == 0) {
				t.Fatalf("OK = %v with failures %v", r.OK(), failed)
			}
			var out bytes.Buffer
			r.PrintPodSummary(&out)
			if len(tc.wantFail) == 0 {
				if out.Len() != 0 {
					t.Fatalf("a summary with nothing failed: %q", out.String())
				}
				return
			}
			line := strings.TrimSpace(out.String())
			if strings.Count(line, "\n") != 0 || !strings.HasPrefix(line, "preflight failed: ") {
				t.Fatalf("summary = %q, want one line", line)
			}
			for _, name := range tc.wantFail {
				if !strings.Contains(line, name+": ") {
					t.Fatalf("summary %q does not name %s", line, name)
				}
			}
		})
	}
}

// The pod preflight reads the kvm device from the machine's sysfs.
func TestDefaultPathsKVMSysfs(t *testing.T) {
	if p := DefaultPaths(); p.KVMSysfs != "/sys/class/misc/kvm" || p.KVMDevice != "/dev/kvm" {
		t.Fatalf("kvm paths = %q, %q", p.KVMSysfs, p.KVMDevice)
	}
}

// A Nitro pool's preflight (plans/security-gaps-m1-m4.md §4.3): the Nitro
// Enclaves device with PCIe slots, a reserved memory pool, and an Amazon
// Linux 2023 kernel with the Nitro Sandboxes driver. No kvm check: a Nitro
// machine has no /dev/kvm.
func TestPodPreflightNitro(t *testing.T) {
	type machine struct {
		device      bool
		slots, pool string // "" = no file
		release     string
	}
	good := machine{device: true, slots: "20\n", pool: "6442450944\n", release: "6.18.62-127.179.amzn2023.x86_64\n"}
	cases := []struct {
		name     string
		m        machine
		wantFail []string
	}{
		{"SP-B's machine", good, nil},
		{"the oldest kernel with the driver", machine{device: true, slots: "4", pool: "1073741824", release: "6.18.51-120.162.amzn2023.x86_64"}, nil},
		{"no Nitro device (launched without enclaves)", machine{release: good.release}, []string{"nitro enclaves", "nitro memory pool"}},
		{"no PCIe slots (an older driver)", machine{device: true, slots: "0", pool: good.pool, release: good.release}, []string{"nitro enclaves"}},
		{"no memory pool (no kernel argument)", machine{device: true, slots: good.slots, pool: "0", release: good.release}, []string{"nitro memory pool"}},
		{"a kernel before the driver", machine{device: true, slots: good.slots, pool: good.pool, release: "6.18.51-120.161.amzn2023.x86_64"}, []string{"nitro kernel"}},
		{"a 6.1 Amazon Linux kernel", machine{device: true, slots: good.slots, pool: good.pool, release: "6.1.158-180.294.amzn2023.x86_64"}, []string{"nitro kernel"}},
		{"mainline 6.19 (no patches)", machine{device: true, slots: good.slots, pool: good.pool, release: "6.19.3"}, []string{"nitro kernel"}},
		{"a newer major", machine{device: true, slots: good.slots, pool: good.pool, release: "7.0.1-1.1.amzn2023.aarch64"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := Paths{CgroupRoot: dir, OSRelease: filepath.Join(dir, "osrelease"), BridgeNF: filepath.Join(dir, "bridge-nf"),
				KVMSysfs: filepath.Join(dir, "kvm"), NitroSysfs: filepath.Join(dir, "nitro_enclaves")}
			write := func(path, body string) {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(dir, "cgroup.controllers"), "cpu memory\n")
			write(p.BridgeNF, "1\n")
			write(p.OSRelease, tc.m.release)
			if tc.m.device {
				if err := os.MkdirAll(p.NitroSysfs, 0o755); err != nil {
					t.Fatal(err)
				}
				if tc.m.slots != "" {
					write(filepath.Join(p.NitroSysfs, "pcie_slots_total"), tc.m.slots)
				}
				if tc.m.pool != "" {
					write(filepath.Join(p.NitroSysfs, "mem_pool", "total"), tc.m.pool)
				}
			}
			r := PodPreflight(p, PodFirecrackerNitro)
			var failed []string
			for _, c := range r.Checks {
				if c.Name == "kvm" {
					t.Fatal("a Nitro pool ran the kvm check")
				}
				if c.Status == StatusFail {
					failed = append(failed, c.Name)
					if c.Detail == "" || c.Fix == "" {
						t.Fatalf("%s failed with no detail or fix: %+v", c.Name, c)
					}
				}
			}
			if strings.Join(failed, ",") != strings.Join(tc.wantFail, ",") {
				t.Fatalf("failed = %v, want %v\n%+v", failed, tc.wantFail, r.Checks)
			}
		})
	}
}

// The pod preflight reads the Nitro driver from the machine's sysfs.
func TestDefaultPathsNitroSysfs(t *testing.T) {
	if p := DefaultPaths(); p.NitroSysfs != "/sys/class/misc/nitro_enclaves" {
		t.Fatalf("NitroSysfs = %q", p.NitroSysfs)
	}
}
