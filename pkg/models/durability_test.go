package models

import (
	"errors"
	"testing"
)

func TestValidDurability(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty_passes_through", input: "", want: ""},
		{name: "ephemeral", input: "ephemeral", want: DurabilityEphemeral},
		{name: "passivatable", input: "passivatable", want: DurabilityPassivatable},
		{name: "durable", input: "durable", want: DurabilityDurable},
		{name: "unknown_rejected", input: "immortal", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidDurability(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultDurabilityForRuntime(t *testing.T) {
	if got := DefaultDurabilityForRuntime(RuntimeDocker); got != DurabilityPassivatable {
		t.Fatalf("docker default = %q, want %q", got, DurabilityPassivatable)
	}
	if got := DefaultDurabilityForRuntime(RuntimeWasm); got != DurabilityEphemeral {
		t.Fatalf("wasm default = %q, want %q", got, DurabilityEphemeral)
	}
}

func TestNormalizeCreateDurability(t *testing.T) {
	got, err := NormalizeCreateDurability("", RuntimeDocker)
	if err != nil {
		t.Fatalf("default docker: %v", err)
	}
	if got != DurabilityPassivatable {
		t.Fatalf("got %q, want %q", got, DurabilityPassivatable)
	}

	got, err = NormalizeCreateDurability("", RuntimeWasm)
	if err != nil {
		t.Fatalf("default wasm: %v", err)
	}
	if got != DurabilityEphemeral {
		t.Fatalf("got %q, want %q", got, DurabilityEphemeral)
	}

	_, err = NormalizeCreateDurability(DurabilityDurable, RuntimeDocker)
	if err == nil {
		t.Fatal("expected error for durable on docker")
	}

	_, err = NormalizeCreateDurability(DurabilityDurable, RuntimeWasm)
	if !errors.Is(err, ErrRuntimeNotImplemented) {
		t.Fatalf("expected ErrRuntimeNotImplemented, got %v", err)
	}
}
