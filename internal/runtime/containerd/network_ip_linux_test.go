//go:build linux

package containerd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netns"
)

// ipLookupTask fakes only what containerIPv4FromTask reads: the OCI spec and
// the task pids. Everything else panics through the nil embedded interface,
// which is the point — the lookup must not need more.
type ipLookupTask struct {
	cntr.Task
	spec    *oci.Spec
	specErr error
	pids    []cntr.ProcessInfo
	pidsErr error
}

func (t ipLookupTask) Spec(context.Context) (*oci.Spec, error) { return t.spec, t.specErr }
func (t ipLookupTask) Pids(context.Context) ([]cntr.ProcessInfo, error) {
	return t.pids, t.pidsErr
}

func netnsSpec(path string) *oci.Spec {
	return &oci.Spec{Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{{Type: specs.NetworkNamespace, Path: path}}}}
}

// The pid fallback must refuse an answer from the daemon's own network
// namespace: under gVisor the task pid lives there, and the first address
// found was the node's own IP (T18, UC-44). The test process's pid is, by
// construction, in the test's own netns — exactly that situation.
func TestContainerIPv4RefusesTheHostNetns(t *testing.T) {
	self := []cntr.ProcessInfo{{Pid: uint32(os.Getpid())}}
	_, err := containerIPv4FromTask(context.Background(), ipLookupTask{specErr: errors.New("no spec"), pids: self})
	if err == nil || !strings.Contains(err.Error(), "host network namespace") {
		t.Fatalf("pid in the host netns = %v, want a refusal naming the host network namespace", err)
	}
}

// A netns the spec pins is read directly. Entering a namespace (even our
// own) needs CAP_SYS_ADMIN, which an unprivileged CI runner lacks; there the
// lookup falls through to the pids, and the positive half is skipped after
// the code has run.
func TestContainerIPv4ReadsTheSpecNetns(t *testing.T) {
	ip, err := containerIPv4FromTask(context.Background(), ipLookupTask{
		spec:    netnsSpec("/proc/self/ns/net"),
		pidsErr: errors.New("pids consulted"),
	})
	if err == nil {
		if ip == "" {
			t.Fatal("spec netns lookup returned no error and no address")
		}
		return
	}
	self, _ := netns.Get()
	defer self.Close()
	if _, perr := firstIPv4InNetns(self); perr != nil && strings.Contains(perr.Error(), "not permitted") {
		t.Skipf("entering a network namespace needs CAP_SYS_ADMIN here (%v); the spec path ran and fell through as designed", perr)
	}
	t.Fatalf("spec netns lookup failed with namespace access available: %v", err)
}

func TestContainerIPv4Errors(t *testing.T) {
	for _, tc := range []struct {
		name string
		task cntr.Task
		want string
	}{
		{"nil task", nil, "task is nil"},
		{"no pids", ipLookupTask{specErr: errors.New("x")}, "no running pid"},
		{"pids error", ipLookupTask{specErr: errors.New("x"), pidsErr: errors.New("boom")}, "no running pid"},
		{"dead pid", ipLookupTask{specErr: errors.New("x"), pids: []cntr.ProcessInfo{{Pid: 1<<31 - 2}}}, "netns from pid"},
		{"unopenable spec path falls back to pids", ipLookupTask{spec: netnsSpec("/nonexistent/netns"), pidsErr: errors.New("x")}, "no running pid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var task cntr.Task
			if tc.task != nil {
				task = tc.task
			}
			_, err := containerIPv4FromTask(context.Background(), task)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
