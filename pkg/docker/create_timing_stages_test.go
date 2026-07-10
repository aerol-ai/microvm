package docker

import (
	"context"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

func stageNames(t *CreateTiming) []string {
	stages := t.Stages()
	names := make([]string, 0, len(stages))
	for _, s := range stages {
		names = append(names, s.Name)
	}
	return names
}

func findStage(t *CreateTiming, name string) (createtiming.Stage, bool) {
	for _, s := range t.Stages() {
		if s.Name == name {
			return s, true
		}
	}
	return createtiming.Stage{}, false
}

// A successful cold create must attribute the dockerd round trips as
// Server-Timing stages so operators can see where boot latency goes.
func TestCreate_RecordsStageTimingsLocalImage(t *testing.T) {
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Config": map[string]any{"Entrypoint": []string{"/bin/sh"}},
			})
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	c := newCreateClient(t, d, true, nil)

	ctx, timing := WithCreateTiming(context.Background())
	if _, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-timing", "tok", nil); err != nil {
		t.Fatalf("create: %v", err)
	}

	want := []string{"docker_image", "docker_create", "docker_start"}
	got := stageNames(timing)
	if len(got) != len(want) {
		t.Fatalf("stages = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stages = %v, want %v", got, want)
		}
	}
	img, ok := findStage(timing, "docker_image")
	if !ok || img.Desc != "local" {
		t.Fatalf("docker_image stage = %+v, want desc=local", img)
	}
}

func TestCreate_RecordsPulledImageStage(t *testing.T) {
	inspectCalls := 0
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			inspectCalls++
			if inspectCalls == 1 {
				return textResponse(http.StatusNotFound, "no such image")
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"Config": map[string]any{"Entrypoint": []string{"/bin/sh"}},
			})
		},
		pull:   func() *http.Response { return textResponse(http.StatusOK, `{"status":"done"}`) },
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	c := newCreateClient(t, d, true, nil)

	ctx, timing := WithCreateTiming(context.Background())
	if _, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-pulled", "tok", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	img, ok := findStage(timing, "docker_image")
	if !ok || img.Desc != "pulled" {
		t.Fatalf("docker_image stage = %+v, want desc=pulled", img)
	}
}

// Create must stay nil-safe when no recorder is on the context — the
// warm-pool spawner and direct callers don't attach one.
func TestCreate_NoTimingRecorderOnContext(t *testing.T) {
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Config": map[string]any{"Entrypoint": []string{"/bin/sh"}},
			})
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	c := newCreateClient(t, d, true, nil)
	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-notiming", "tok", nil); err != nil {
		t.Fatalf("create without recorder: %v", err)
	}
}
