package config

import (
	"strings"
	"testing"
)

func TestLoadContainerEngine(t *testing.T) {
	t.Run("default is docker (dark default)", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ContainerEngine != "docker" {
			t.Fatalf("default ContainerEngine = %q, want docker", cfg.ContainerEngine)
		}
	})

	t.Run("containerd accepted with defaults for socket/namespace", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ContainerEngine != "containerd" {
			t.Fatalf("ContainerEngine = %q, want containerd", cfg.ContainerEngine)
		}
		if cfg.ContainerdSocket == "" || cfg.ContainerdNamespace == "" {
			t.Fatal("containerd socket/namespace defaults must be non-empty")
		}
		if cfg.ContainerdRunDir != DefaultContainerdRunDir {
			t.Fatalf("run dir = %q, want %q", cfg.ContainerdRunDir, DefaultContainerdRunDir)
		}
	})

	t.Run("unknown engine rejected", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINER_ENGINE", "podman")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_CONTAINER_ENGINE") {
			t.Fatalf("err = %v, want SB_CONTAINER_ENGINE rejection", err)
		}
	})

	t.Run("case-insensitive normalization", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINER_ENGINE", "Containerd")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ContainerEngine != "containerd" {
			t.Fatalf("ContainerEngine = %q, want normalized containerd", cfg.ContainerEngine)
		}
	})
}

// SB_CONTAINERD_CGROUP_PARENT puts every containerd sandbox's cgroup under one
// parent (plans/kubernetes-v2-architecture.md C7). Only a clean absolute path
// below the root is taken, and only on the containerd engine.
func TestLoadContainerdCgroupParent(t *testing.T) {
	for _, tc := range []struct {
		name, engine, parent, wantErr string
	}{
		{"unset keeps the default", "containerd", "", ""},
		{"pod group accepted", "containerd", "/kubepods.slice/kubepods-podx.slice/cri-containerd-y.scope/sandboxes", ""},
		{"relative refused", "containerd", "sandboxes", "SB_CONTAINERD_CGROUP_PARENT"},
		{"root refused", "containerd", "/", "SB_CONTAINERD_CGROUP_PARENT"},
		{"unclean refused", "containerd", "/a/../b", "SB_CONTAINERD_CGROUP_PARENT"},
		{"trailing slash refused", "containerd", "/a/", "SB_CONTAINERD_CGROUP_PARENT"},
		{"docker engine refused", "docker", "/a", "needs SB_CONTAINER_ENGINE=containerd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_CONTAINER_ENGINE", tc.engine)
			t.Setenv("SB_CONTAINERD_CGROUP_PARENT", tc.parent)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.ContainerdCgroupParent != tc.parent {
				t.Fatalf("ContainerdCgroupParent = %q, want %q", cfg.ContainerdCgroupParent, tc.parent)
			}
		})
	}
}

// The sandboxes sandboxd starts itself (WASM, V8 isolates, Firecracker) go
// under SB_HOST_PROCESS_CGROUP_PARENT, by default the containerd parent, so
// in a worker pod they stay inside the runtime container's sandboxes group
// (C14). The V8 jail's group cgroups follow, unless named.
func TestLoadHostProcessCgroupParent(t *testing.T) {
	const pod = "/kubepods.slice/kubepods-podx.slice/cri-containerd-y.scope/sandboxes"
	for _, tc := range []struct {
		name, containerdParent, hostParent, jailRoot string
		wantParent, wantRoot, wantJail, wantErr      string
	}{
		{name: "VM: the machine's root", wantJail: "/sys/fs/cgroup/aerolvm-isolate"},
		{name: "pod: follows the containerd parent", containerdParent: pod,
			wantParent: pod, wantRoot: "/sys/fs/cgroup" + pod, wantJail: "/sys/fs/cgroup" + pod + "/aerolvm-isolate"},
		{name: "named on its own", hostParent: "/aerol/hosts",
			wantParent: "/aerol/hosts", wantRoot: "/sys/fs/cgroup/aerol/hosts", wantJail: "/sys/fs/cgroup/aerol/hosts/aerolvm-isolate"},
		{name: "a named jail root is kept", containerdParent: pod, jailRoot: "/sys/fs/cgroup/jail",
			wantParent: pod, wantRoot: "/sys/fs/cgroup" + pod, wantJail: "/sys/fs/cgroup/jail"},
		{name: "relative refused", hostParent: "hosts", wantErr: "SB_HOST_PROCESS_CGROUP_PARENT"},
		{name: "root refused", hostParent: "/", wantErr: "SB_HOST_PROCESS_CGROUP_PARENT"},
		{name: "unclean refused", hostParent: "/a/../b", wantErr: "SB_HOST_PROCESS_CGROUP_PARENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_CONTAINER_ENGINE", "containerd")
			t.Setenv("SB_CONTAINERD_CGROUP_PARENT", tc.containerdParent)
			t.Setenv("SB_HOST_PROCESS_CGROUP_PARENT", tc.hostParent)
			t.Setenv("SB_ISOLATE_JAIL_CGROUP_ROOT", tc.jailRoot)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.HostProcessCgroupParent != tc.wantParent || cfg.HostProcessCgroupRoot() != tc.wantRoot || cfg.IsolateJailCgroupRoot != tc.wantJail {
				t.Fatalf("parent %q, root %q, jail %q; want %q, %q, %q", cfg.HostProcessCgroupParent, cfg.HostProcessCgroupRoot(),
					cfg.IsolateJailCgroupRoot, tc.wantParent, tc.wantRoot, tc.wantJail)
			}
		})
	}
}

// SB_MOUNTS_RUNTIME_PID_FILE turns on the check that an external mount is
// visible to the worker pod's runtime container (F13): unset on a VM, an
// absolute path in the pod, a relative one refused.
func TestLoadMountsRuntimePIDFile(t *testing.T) {
	for _, tc := range []struct{ name, value, want, wantErr string }{
		{name: "VM: unset"},
		{name: "pod", value: " /run/aerolvm/runtime.pid ", want: "/run/aerolvm/runtime.pid"},
		{name: "relative refused", value: "run/aerolvm/runtime.pid", wantErr: "SB_MOUNTS_RUNTIME_PID_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_MOUNTS_RUNTIME_PID_FILE", tc.value)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || cfg.MountsRuntimePIDFile != tc.want {
				t.Fatalf("MountsRuntimePIDFile = %q (%v), want %q", cfg.MountsRuntimePIDFile, err, tc.want)
			}
		})
	}
}

func TestRunsHostProcessSandboxes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"gVisor worker", Config{NodeRole: NodeRoleWorker}, false},
		{"WASM worker", Config{NodeRole: NodeRoleWorker, EnableWasm: true}, true},
		{"V8 worker", Config{NodeRole: NodeRoleWorker, EnableIsolate: true}, true},
		{"Firecracker worker", Config{NodeRole: NodeRoleWorker, EnableFirecracker: true}, true},
		{"WASM on a server", Config{NodeRole: NodeRoleServer, EnableWasm: true}, false},
	} {
		if got := tc.cfg.RunsHostProcessSandboxes(); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
