package models

import (
	"errors"
	"testing"
)

func TestResolveContainerEngine(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		isErr bool
	}{
		{"", ContainerEngineDocker, false},
		{"docker", ContainerEngineDocker, false},
		{"DOCKER", ContainerEngineDocker, false},
		{"containerd", ContainerEngineContainerd, false},
		{"podman", "", true},
	}
	for _, tc := range cases {
		got, err := ResolveContainerEngine(tc.in)
		if tc.isErr {
			if err == nil {
				t.Errorf("ResolveContainerEngine(%q) = (%q, nil), want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveContainerEngine(%q) = error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolveContainerEngine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSandboxEngine(t *testing.T) {
	if SandboxEngine(nil) != ContainerEngineDocker {
		t.Fatalf("nil sandbox engine = %q", SandboxEngine(nil))
	}
	if SandboxEngine(&Sandbox{}) != ContainerEngineDocker {
		t.Fatalf("empty engine column = %q", SandboxEngine(&Sandbox{}))
	}
	if SandboxEngine(&Sandbox{Engine: ContainerEngineContainerd}) != ContainerEngineContainerd {
		t.Fatalf("containerd engine = %q", SandboxEngine(&Sandbox{Engine: ContainerEngineContainerd}))
	}
}

func TestValidateRuntimeRequest(t *testing.T) {
	if err := ValidateRuntimeRequest(CreateSandboxRequest{}, RuntimeDocker, true, nil); err != nil {
		t.Fatalf("docker+privileged = %v", err)
	}
	if err := ValidateRuntimeRequest(CreateSandboxRequest{}, RuntimeGvisor, true, nil); err == nil {
		t.Fatal("gvisor+privileged want error")
	}
	if err := ValidateRuntimeRequest(CreateSandboxRequest{GPUs: &GPURequest{Count: 1, Vendor: GPUVendorNVIDIA}}, RuntimeGvisor, false, nil); err == nil {
		t.Fatal("gvisor+gpu want error")
	}
	var warned bool
	logf := func(msg string, args ...any) { warned = true }
	if err := ValidateRuntimeRequest(CreateSandboxRequest{DiskGB: 10}, RuntimeGvisor, false, logf); err != nil {
		t.Fatalf("gvisor+disk warn path = %v", err)
	}
	if !warned {
		t.Fatal("expected disk quota warning for gvisor")
	}
	if !errors.Is(ErrContainerEngineNotRegistered, ErrContainerEngineNotRegistered) {
		t.Fatal("sentinel error identity")
	}
}
