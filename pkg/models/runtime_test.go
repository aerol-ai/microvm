package models

import (
	"errors"
	"testing"
)

func TestValidRuntime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Empty input is *not* an error — the caller (service layer) is
		// expected to substitute the host default. The function's job is to
		// reject *unknown* values, not to enforce that one was supplied.
		{name: "empty_passes_through", input: "", want: ""},
		{name: "docker_accepted", input: "docker", want: "docker"},
		{name: "gvisor_accepted", input: "gvisor", want: "gvisor"},
		{name: "kata_accepted_as_identifier", input: "kata", want: "kata"},
		// Firecracker is a recognized identifier so the API surface accepts
		// it before the per-host implementation lands. CreateSandbox still
		// rejects with ErrRuntimeNotImplemented when the operator hasn't
		// flipped SB_ENABLE_FIRECRACKER on (see service.go).
		{name: "firecracker_accepted_as_identifier", input: "firecracker", want: "firecracker"},
		{name: "wasm_accepted_as_identifier", input: "wasm", want: "wasm"},
		// Isolate follows the same accept-ahead-of-implementation pattern:
		// CreateSandbox rejects with ErrRuntimeNotImplemented until
		// SB_ENABLE_ISOLATE is set (plans/isolate-runtime.md Phase 1).
		{name: "isolate_accepted_as_identifier", input: "isolate", want: "isolate"},
		{name: "runc_legacy_rejected", input: "runc", wantErr: true},
		{name: "runsc_legacy_rejected", input: "runsc", wantErr: true},
		{name: "case_sensitive", input: "Docker", wantErr: true},
		{name: "whitespace_rejected", input: " gvisor ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidRuntime(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil (got=%q)", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveOCIRuntime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// "" and "docker" both map to "" so the caller leaves
		// HostConfig.Runtime unset and Docker uses its compiled-in default.
		{name: "empty_means_no_override", input: "", want: ""},
		{name: "docker_means_no_override", input: "docker", want: ""},
		{name: "gvisor_resolves_to_runsc", input: "gvisor", want: "runsc"},
		{name: "kata_returns_not_implemented", input: "kata", wantErr: ErrRuntimeNotImplemented},
		// Firecracker is a hypervisor, not an OCI runtime Docker can drive.
		// ResolveOCIRuntime returns ErrRuntimeNotImplemented so a stray
		// call from the Docker path surfaces clearly instead of silently
		// coercing the request to runc.
		{name: "firecracker_returns_not_implemented", input: "firecracker", wantErr: ErrRuntimeNotImplemented},
		{name: "wasm_returns_not_implemented", input: "wasm", wantErr: ErrRuntimeNotImplemented},
		{name: "isolate_returns_not_implemented", input: "isolate", wantErr: ErrRuntimeNotImplemented},
		{name: "unknown_value_errors", input: "containerd", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveOCIRuntime(tc.input)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if tc.input == "containerd" {
				if err == nil {
					t.Fatalf("expected error for unknown input")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
