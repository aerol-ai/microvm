package gate

import (
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestGateBindsOnlyTheContainersOwnMounts (M1 PR 8): with the helper's
// mounts folder in its policy, the gate lets a container bind only its own
// mount points: never another sandbox's mount, its folder or a tool's log.
// containerd hears of none of them.
func TestGateBindsOnlyTheContainersOwnMounts(t *testing.T) {
	p := testPolicy()
	p.MountsRoot = testMounts
	const create = "/containerd.services.containers.v1.Containers/Create"
	withSource := func(src string) *containersapi.Container {
		c := goodContainer(t)
		s := specFor(t, testID)
		s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: src, Destination: "/data", Options: []string{"rbind"}})
		c.Spec = specAny(t, s)
		return c
	}
	r := newRig(t, p)
	if _, err := r.invoke(nsCtx(), create, &containersapi.CreateContainerRequest{Container: withSource(testMounts + "/" + testID + "/0")}); err != nil {
		t.Fatalf("its own mount: %v", err)
	}
	for _, src := range []string{
		testMounts + "/sb-other/0", // another sandbox's mount
		testMounts + "/" + testID,  // its folder, with its tools' logs
		testMounts + "/" + testID + "/0.log",
		testMounts + "/" + testID + "/0/../../sb-other/0",
	} {
		r := newRig(t, p)
		_, err := r.invoke(nsCtx(), create, &containersapi.CreateContainerRequest{Container: withSource(src)})
		r.wantRefused(err, create, string(rootpolicy.RuleMount))
		if seen := r.fake.methodsSeen(); len(seen) != 0 {
			t.Fatalf("%s reached containerd: %v", src, seen)
		}
	}
}
