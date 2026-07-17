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
	if got := DefaultDurabilityForRuntime(RuntimeIsolate); got != DurabilityEphemeral {
		t.Fatalf("isolate default = %q, want %q", got, DurabilityEphemeral)
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

// Isolate durability set (plans/isolate-runtime.md §4): default ephemeral,
// passivatable rejected outright (the bundle is the image — nothing to
// passivate), durable gated behind Phase 5 as ErrRuntimeNotImplemented.
func TestNormalizeCreateDurabilityIsolate(t *testing.T) {
	got, err := NormalizeCreateDurability("", RuntimeIsolate)
	if err != nil {
		t.Fatalf("default isolate: %v", err)
	}
	if got != DurabilityEphemeral {
		t.Fatalf("got %q, want %q", got, DurabilityEphemeral)
	}

	got, err = NormalizeCreateDurability(DurabilityEphemeral, RuntimeIsolate)
	if err != nil {
		t.Fatalf("explicit ephemeral: %v", err)
	}
	if got != DurabilityEphemeral {
		t.Fatalf("got %q, want %q", got, DurabilityEphemeral)
	}

	_, err = NormalizeCreateDurability(DurabilityPassivatable, RuntimeIsolate)
	if err == nil {
		t.Fatal("expected error for passivatable on isolate")
	}
	if errors.Is(err, ErrRuntimeNotImplemented) {
		t.Fatalf("passivatable must be rejected outright, not 'not yet': %v", err)
	}

	_, err = NormalizeCreateDurability(DurabilityDurable, RuntimeIsolate)
	if !errors.Is(err, ErrRuntimeNotImplemented) {
		t.Fatalf("expected ErrRuntimeNotImplemented for durable on isolate (Phase 5), got %v", err)
	}
}
