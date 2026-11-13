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
			r := PodPreflight(p, tc.kvm)
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
