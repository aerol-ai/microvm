package daytona

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTranslateCreateSandboxRequestAcceptsDaytonaGoImageFixture(t *testing.T) {
	fixture := []byte(`{
		"public": false,
		"buildInfo": {
			"dockerfileContent": "FROM alpine"
		}
	}`)

	var req createSandboxRequest
	if err := json.Unmarshal(fixture, &req); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	h := newHandlers(Deps{})
	translated, err := h.translateCreateSandboxRequest(req)
	if err != nil {
		t.Fatalf("translateCreateSandboxRequest() error = %v", err)
	}
	if translated.Image != "alpine" {
		t.Fatalf("translated.Image = %q, want %q", translated.Image, "alpine")
	}
	if translated.NetworkBlockAll {
		t.Fatal("translated.NetworkBlockAll unexpectedly true")
	}
	if translated.Lifecycle != nil {
		t.Fatalf("translated.Lifecycle = %+v, want nil", translated.Lifecycle)
	}
	if translated.CPU != 0 || translated.MemoryMB != 0 || translated.DiskGB != 0 {
		t.Fatalf("unexpected translated resource values: %+v", translated)
	}
	if len(translated.Env) != 0 {
		t.Fatalf("translated.Env = %+v, want empty", translated.Env)
	}
}

func TestTranslateCreateSandboxRequestRejectsComplexBuildInfo(t *testing.T) {
	fixture := []byte(`{
		"buildInfo": {
			"dockerfileContent": "FROM alpine\nRUN echo hello"
		}
	}`)

	var req createSandboxRequest
	if err := json.Unmarshal(fixture, &req); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	h := newHandlers(Deps{})
	_, err := h.translateCreateSandboxRequest(req)
	if err == nil {
		t.Fatal("expected translateCreateSandboxRequest() error for complex buildInfo")
	}
	if got := err.Error(); got != "buildInfo is only supported for simple single-line Dockerfiles of the form `FROM <image>`" {
		t.Fatalf("error = %q", got)
	}
}

func TestTranslateCreateSandboxRequestPreservesIdleLifecycleFields(t *testing.T) {
	autoStop := int32(5)
	autoDelete := int32(15)
	req := createSandboxRequest{
		Public:             boolPtr(false),
		BuildInfo:          &buildInfoRequest{DockerfileContent: stringPtr("FROM alpine")},
		AutoStopInterval:   &autoStop,
		AutoDeleteInterval: &autoDelete,
		NetworkBlockAll:    boolPtr(true),
	}

	h := newHandlers(Deps{})
	translated, err := h.translateCreateSandboxRequest(req)
	if err != nil {
		t.Fatalf("translateCreateSandboxRequest() error = %v", err)
	}
	if translated.Image != "alpine" {
		t.Fatalf("translated.Image = %q, want alpine", translated.Image)
	}
	if !translated.NetworkBlockAll {
		t.Fatal("translated.NetworkBlockAll = false, want true")
	}
	if translated.Lifecycle == nil {
		t.Fatal("translated.Lifecycle = nil, want non-nil")
	}
	if translated.Lifecycle.StopIfIdleFor != 5*time.Minute {
		t.Fatalf("StopIfIdleFor = %v, want 5m", translated.Lifecycle.StopIfIdleFor)
	}
	if translated.Lifecycle.DestroyIfIdleFor != 15*time.Minute {
		t.Fatalf("DestroyIfIdleFor = %v, want 15m", translated.Lifecycle.DestroyIfIdleFor)
	}
}

func boolPtr(value bool) *bool {
	return &value
}
