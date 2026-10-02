package service

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// CreateSandboxWithID feeds idOverride (from CreateSandboxWithID callers and the
// X-Cluster-Create-ID forward header) into host path components. A traversing id
// must be rejected at the create entry, before any runtime dispatch or mount,
// and must not create a sandbox state directory anywhere.
func TestCreateSandboxWithIDRejectsTraversalID(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	for _, id := range []string{"../escape", "../../etc", "sb/../..", "sb id", "sb\x00x"} {
		t.Run(id, func(t *testing.T) {
			_, err := svc.CreateSandboxWithID(context.Background(),
				models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
			if err == nil {
				t.Fatalf("CreateSandboxWithID(%q) = nil error, want rejection", id)
			}
			if !strings.Contains(err.Error(), "sandbox ID") {
				t.Fatalf("error = %v, want sandbox-ID rejection", err)
			}
		})
	}
}

// A well-formed override still creates, so the guard doesn't block the normal
// reservation/recreate path (which supplies a generated sb-<hex> id).
func TestCreateSandboxWithIDAcceptsGeneratedID(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	resp, err := svc.CreateSandboxWithID(context.Background(),
		models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-0123456789abcdef")
	if err != nil {
		t.Fatalf("CreateSandboxWithID(valid id) = %v", err)
	}
	if resp.ID != "sb-0123456789abcdef" {
		t.Fatalf("resp.ID = %q, want sb-0123456789abcdef", resp.ID)
	}
	if _, err := st.Get(context.Background(), resp.ID); err != nil {
		t.Fatalf("sandbox not persisted: %v", err)
	}
	// Guard against a path that looks fine but would still escape if joined.
	if strings.Contains(resp.ID, "..") || strings.ContainsAny(resp.ID, `/\`) {
		t.Fatalf("accepted id is not path-safe: %q", resp.ID)
	}
	_ = filepath.Clean(resp.ID)
}
