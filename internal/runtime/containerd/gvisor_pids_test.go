package containerd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/models"
)

func specPidsLimit(s *specs.Spec) int64 {
	if s.Linux == nil || s.Linux.Resources == nil || s.Linux.Resources.Pids == nil || s.Linux.Resources.Pids.Limit == nil {
		return 0
	}
	return *s.Linux.Resources.Pids.Limit
}

func specEnv(s *specs.Spec, key string) []string {
	var out []string
	for _, kv := range s.Process.Env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			out = append(out, v)
		}
	}
	return out
}

func specHasCgroupMount(s *specs.Spec) bool {
	return slices.ContainsFunc(s.Mounts, func(m specs.Mount) bool {
		return m.Destination == "/sys/fs/cgroup" && m.Type == "cgroup"
	})
}

// UC-320: a gVisor sandbox's cap goes into the sentry (toolboxd applies the
// env), its host cgroup holds two host tasks per sandbox task, and it gets a
// cgroup mount so the sentry gives it a pids.max at all. runc keeps the
// node's limit, enforced by the host cgroup itself.
func TestCreateSandboxPidsLimitsByRuntime(t *testing.T) {
	cases := []struct {
		name          string
		runtime       string
		memoryMB      int
		userEnv       map[string]string
		limitsOff     bool
		wantHostPids  int64
		wantSentryEnv []string
		wantCgroupMnt bool
	}{
		{name: "gvisor default sandbox", runtime: models.RuntimeGvisor, memoryMB: 1024,
			wantHostPids: 3072, wantSentryEnv: []string{"1024"}, wantCgroupMnt: true},
		{name: "gvisor large sandbox keeps the node limit", runtime: models.RuntimeGvisor, memoryMB: 8192,
			wantHostPids: 9216, wantSentryEnv: []string{"4096"}, wantCgroupMnt: true},
		{name: "gvisor ignores a create's own value", runtime: models.RuntimeGvisor, memoryMB: 1024,
			userEnv:      map[string]string{gvisorpids.EnvVar: "0", "KEEP": "1"},
			wantHostPids: 3072, wantSentryEnv: []string{"1024"}, wantCgroupMnt: true},
		{name: "gvisor with resource limits off", runtime: models.RuntimeGvisor, memoryMB: 1024, limitsOff: true,
			wantHostPids: 0, wantSentryEnv: nil, wantCgroupMnt: true},
		{name: "runc keeps the node limit", runtime: models.RuntimeDocker, memoryMB: 1024,
			wantHostPids: 4096, wantSentryEnv: nil, wantCgroupMnt: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubToolboxProbe(t)
			var capture specCapture
			capture.install(t)
			d := newTestDriver(t)
			d.cfg.PidsLimit = 4096
			d.cfg.ResourceLimitsOff = tc.limitsOff

			const id = "sb-pids"
			if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, Runtime: tc.runtime, MemoryMB: tc.memoryMB, CPU: 1, Env: tc.userEnv,
			}, id, "tok", nil); err != nil {
				t.Fatalf("Create: %v", err)
			}
			spec := capture.last(t)
			if got := specPidsLimit(spec); got != tc.wantHostPids {
				t.Errorf("host pids limit = %d, want %d", got, tc.wantHostPids)
			}
			if got := specEnv(spec, gvisorpids.EnvVar); !slices.Equal(got, tc.wantSentryEnv) {
				t.Errorf("%s = %v, want %v", gvisorpids.EnvVar, got, tc.wantSentryEnv)
			}
			if got := specHasCgroupMount(spec); got != tc.wantCgroupMnt {
				t.Errorf("cgroup mount = %v, want %v", got, tc.wantCgroupMnt)
			}
			if tc.userEnv != nil && !slices.Contains(spec.Process.Env, "KEEP=1") {
				t.Errorf("the create's other env was dropped: %v", spec.Process.Env)
			}
			if tc.runtime == models.RuntimeGvisor && spec.Annotations[criContainerTypeAnnotation] != criContainerTypeSandbox {
				t.Errorf("runsc sandbox annotation missing: %v", spec.Annotations)
			}
		})
	}
}

// A parked gVisor toolboxd applies the cap at park time; adopt does not
// restart it, so the park must carry the env, the host budget and the mount.
func TestParkGvisorCarriesPidsLimits(t *testing.T) {
	for _, rt := range []string{models.RuntimeGvisor, models.RuntimeDocker} {
		t.Run(rt, func(t *testing.T) {
			stubToolboxProbe(t)
			origWait := parkReadyWaitFn
			parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
			t.Cleanup(func() { parkReadyWaitFn = origWait })

			var capture specCapture
			capture.install(t)
			provider, img := newTestImageProvider(t)
			tr := newFakeTransport()
			tr.provider = provider
			tr.image = img
			tmp := t.TempDir()
			toolbox := filepath.Join(tmp, "toolboxd")
			if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
				t.Fatal(err)
			}
			d := New(Config{
				ToolboxBinaryPath:  toolbox,
				ToolboxMountPath:   "/.aerol/toolboxd",
				ToolboxPort:        2280,
				ToolboxWaitTimeout: 2 * time.Second,
				LogDir:             filepath.Join(tmp, "logs"),
				RunDir:             filepath.Join(tmp, "run"),
				ReadyEnabled:       true,
				ReadyDir:           shortReadyDir(t),
				PidsLimit:          4096,
			}, nil, nil)
			d.SetClient(NewTestClient("aerolvm", tr))

			const slotID = "park-pids"
			if _, err := d.parkContainer(context.Background(), slotID, containerdpool.Key{Image: "cfg:test", Runtime: rt}); err != nil {
				t.Fatalf("park: %v", err)
			}
			spec := capture.last(t)
			wantHost, wantEnv, wantMount := int64(4096), []string(nil), false
			if rt == models.RuntimeGvisor {
				// Park default memory is 1 GiB.
				wantHost, wantEnv, wantMount = 3072, []string{"1024"}, true
			}
			if got := specPidsLimit(spec); got != wantHost {
				t.Errorf("host pids limit = %d, want %d", got, wantHost)
			}
			if got := specEnv(spec, gvisorpids.EnvVar); !slices.Equal(got, wantEnv) {
				t.Errorf("%s = %v, want %v", gvisorpids.EnvVar, got, wantEnv)
			}
			if got := specHasCgroupMount(spec); got != wantMount {
				t.Errorf("cgroup mount = %v, want %v", got, wantMount)
			}
		})
	}
}

func TestRunscCgroupMountIsReadOnly(t *testing.T) {
	m := runscCgroupMount()
	if m.Destination != "/sys/fs/cgroup" || m.Type != "cgroup" || !slices.Contains(m.Options, "ro") {
		t.Fatalf("mount = %+v, want a read-only cgroup mount at /sys/fs/cgroup", m)
	}
}
