package containerd

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestFromDaemonConfigLogDirFollowsRunDir(t *testing.T) {
	cases := []struct {
		name       string
		runDir     string
		logDir     string
		wantRunDir string
		wantLogDir string
	}{
		{"both set", "/data/ctd", "/logs/ctd", "/data/ctd", "/logs/ctd"},
		{"logdir empty derives from rundir", "/data/ctd", "", "/data/ctd", "/data/ctd/logs"},
		{"rundir empty uses default and logdir follows it", "", "", config.DefaultContainerdRunDir, config.DefaultContainerdRunDir + "/logs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FromDaemonConfig(config.Config{ContainerdRunDir: tc.runDir, ContainerdLogDir: tc.logDir})
			if got.RunDir != tc.wantRunDir {
				t.Fatalf("RunDir = %q, want %q", got.RunDir, tc.wantRunDir)
			}
			if got.LogDir != tc.wantLogDir {
				t.Fatalf("LogDir = %q, want %q", got.LogDir, tc.wantLogDir)
			}
		})
	}
}

func TestRegistryHost(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"nginx", ""},
		{"library/nginx:latest", ""},
		{"docker.io/library/nginx", "docker.io"},
		{"ghcr.io/org/app:v1", "ghcr.io"},
		{"localhost:5000/app", "localhost:5000"},
		{"registry.example.com:443/team/app@sha256:abc", "registry.example.com:443"},
	}
	for _, tc := range cases {
		if got := registryHost(tc.ref); got != tc.want {
			t.Errorf("registryHost(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestNewInitializesPullState(t *testing.T) {
	d := New(Config{PullMaxConcurrent: 3}, nil, nil)
	if d.pullSem == nil {
		t.Fatal("expected pull semaphore when PullMaxConcurrent > 0")
	}
	if cap(d.pullSem) != 3 {
		t.Fatalf("pull semaphore cap = %d, want 3", cap(d.pullSem))
	}
	if d.pullFailUntil == nil {
		t.Fatal("pullFailUntil map not initialized")
	}
	d2 := New(Config{}, nil, nil)
	if d2.pullSem != nil {
		t.Fatal("no semaphore expected when PullMaxConcurrent == 0")
	}
}
