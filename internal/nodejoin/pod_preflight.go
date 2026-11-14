package nodejoin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The worker pod's preflight (plans/kubernetes-v2-architecture.md P10): an
// init container in every worker pod checks the machine the pod landed on,
// so a machine added later is checked too. A failure keeps the worker out
// of service, and the operator puts the reason on its AerolNode. Unlike the
// VM preflight these are hard requirements: sandboxd in a pod has no
// fallback for any of them.

// MinKernel is the oldest kernel a worker runs on: the oldest long-term
// kernel past 5.3, where pidfd_open arrived (pkg/mounts holds mount helpers
// by pidfd). Every node image we support is newer: Amazon Linux 2023 and
// Bottlerocket ship 6.1, Azure Linux 6.6, Ubuntu 22.04 5.15.
var MinKernel = [2]int{5, 10}

// PodPreflight runs the worker pod's checks. kvm adds the kvm check, for a
// Firecracker pool.
func PodPreflight(p Paths, kvm bool) Report {
	var r Report
	r.add(checkCgroupRequired(p), checkKernel(p), checkBridgeNF(p))
	if kvm {
		r.add(checkKVMSysfs(p))
	}
	return r
}

// checkKVMSysfs fails on a machine without the kvm device. The preflight
// container is not privileged, so it has no /dev/kvm even on a machine that
// does; it reads the machine's sysfs instead, and asks for no host folder
// (the worker pod has none, EVIDENCE.md).
func checkKVMSysfs(p Paths) Check {
	c := Check{Name: "kvm", Status: StatusOK}
	if _, err := os.Stat(p.KVMSysfs); err != nil {
		c.Status, c.Detail = StatusFail, "this machine has no /dev/kvm ("+p.KVMSysfs+" is missing), and this worker pool runs Firecracker"
		c.Fix = "use a metal machine or one with nested virtualization on (on EKS: m7i, c7i, r7i, m8i, c8i or r8i), or turn worker.firecracker off for this pool"
		return c
	}
	c.Detail = "/dev/kvm is present (" + p.KVMSysfs + ")"
	return c
}

// checkCgroupRequired fails without cgroup v2: every sandbox runs in a
// child of the pod's own cgroup (C7), which needs the unified hierarchy.
func checkCgroupRequired(p Paths) Check {
	c := checkCgroup(p, false)
	if c.Status == StatusWarn {
		c.Status = StatusFail
		c.Fix = "use a node image with cgroup v2 (Amazon Linux 2023, Bottlerocket, Azure Linux, Ubuntu 22.04 or later)"
	}
	return c
}

func checkKernel(p Paths) Check {
	c := Check{Name: "kernel", Status: StatusOK}
	raw, err := os.ReadFile(p.OSRelease)
	if err != nil {
		c.Status, c.Detail = StatusFail, "cannot read the kernel version: "+err.Error()
		return c
	}
	release := strings.TrimSpace(string(raw))
	major, minor, ok := parseKernel(release)
	switch {
	case !ok:
		c.Status, c.Detail = StatusFail, fmt.Sprintf("cannot parse the kernel version %q", release)
	case major < MinKernel[0] || major == MinKernel[0] && minor < MinKernel[1]:
		c.Status, c.Detail = StatusFail, fmt.Sprintf("kernel %s is older than %d.%d", release, MinKernel[0], MinKernel[1])
		c.Fix = "use a newer node image"
	default:
		c.Detail = "kernel " + release
	}
	return c
}

// parseKernel reads "6.1.102-108.177.amzn2023.aarch64" as 6, 1.
func parseKernel(release string) (int, int, bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	digits := parts[1]
	if i := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = digits[:i]
	}
	minor, err := strconv.Atoi(digits)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// checkBridgeNF fails without br_netfilter. sandboxd refuses to start
// without it, rightly: traffic between sandboxes on one bridge would skip
// the firewall. A pod cannot load a kernel module, so the machine must
// (Phase 0 finding F2: stock EKS Amazon Linux 2023 does not).
func checkBridgeNF(p Paths) Check {
	c := Check{Name: "br_netfilter", Status: StatusOK, Detail: "loaded"}
	if _, err := os.Stat(p.BridgeNF); err != nil {
		c.Status, c.Detail = StatusFail, "the br_netfilter kernel module is not loaded ("+filepath.Base(p.BridgeNF)+" is missing)"
		c.Fix = "load it in the node image or its user data: modprobe br_netfilter, and list it in /etc/modules-load.d"
	}
	return c
}

// PrintPodSummary writes one line naming every failed check with its fix,
// or nothing when all passed. It is printed last, so it is the last line
// of the container's log, which the kubelet keeps as the termination
// message (FallbackToLogsOnError) and the operator shows on the AerolNode.
func (r Report) PrintPodSummary(w io.Writer) {
	var failed []string
	for _, c := range r.Checks {
		if c.Status != StatusFail {
			continue
		}
		s := c.Name + ": " + c.Detail
		if c.Fix != "" {
			s += " (fix: " + c.Fix + ")"
		}
		failed = append(failed, s)
	}
	if len(failed) > 0 {
		fmt.Fprintln(w, "preflight failed: "+strings.Join(failed, "; "))
	}
}
