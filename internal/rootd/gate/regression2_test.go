package gate

import (
	"math"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The second review's proofs of concept against ac2d0aef, through the gate.
// Finding 1 (a host file linked to /) needs real files: binds_linux_test.go.

// Finding 3: a second sysfs, read-only but with none of /sys's masks.
func TestRegression2SecondSysfs(t *testing.T) {
	r := newRig(t, testPolicy())
	s := goodSpec(t)
	s.Mounts = append(s.Mounts, specs.Mount{Destination: "/s2", Type: "sysfs", Source: "sysfs", Options: []string{"ro", "nosuid", "noexec", "nodev"}})
	c := goodContainer(t)
	c.Spec = specAny(t, s)
	_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c})
	r.wantRefused(err, cCreate, string(rootpolicy.RuleMount))
}

// Finding 2: with the bounds opt-in, MaxInt64 limits were as good as none.
func TestRegression2HugeResize(t *testing.T) {
	r := newRig(t, testPolicy())
	big, period := int64(math.MaxInt64), uint64(1000)
	_, err := r.invoke(nsCtx(), tUpdate, &tasksapi.UpdateTaskRequest{ContainerID: testID, Resources: resourcesAny(t, specs.LinuxResources{
		Memory: &specs.LinuxMemory{Limit: &big}, Pids: &specs.LinuxPids{Limit: &big}, CPU: &specs.LinuxCPU{Quota: &big, Period: &period},
	})})
	r.wantRefused(err, tUpdate, string(rootpolicy.RuleResources))
}

// Finding 2: a create with no limits at all (SB_RESOURCE_LIMITS_OFF's
// spec) is refused.
func TestRegression2CreateWithoutLimits(t *testing.T) {
	for name, mutate := range map[string]func(*specs.Spec){
		"no resources":    func(s *specs.Spec) { s.Linux.Resources = nil },
		"no memory limit": func(s *specs.Spec) { s.Linux.Resources.Memory = nil },
		"no pids limit":   func(s *specs.Spec) { s.Linux.Resources.Pids = nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, testPolicy())
			s := goodSpec(t)
			mutate(s)
			c := goodContainer(t)
			c.Spec = specAny(t, s)
			_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c})
			r.wantRefused(err, cCreate, string(rootpolicy.RuleResources))
		})
	}
}
