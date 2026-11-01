package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/models"
)

// envValues returns every value of key in a create body's Env.
func envValues(env []any, key string) []string {
	var out []string
	for _, e := range env {
		if k, v, _ := strings.Cut(e.(string), "="); k == key {
			out = append(out, v)
		}
	}
	return out
}

// UC-320 on the Docker engine: a gVisor sandbox's cap goes into the sentry
// (toolboxd applies the env; Docker's own spec already has the cgroup mount
// that gives the sentry a pids.max), and its host cgroup holds two host tasks
// per sandbox task. runc keeps the node's limit.
func TestCreateGvisorPidsLimits(t *testing.T) {
	cases := []struct {
		name      string
		runtime   string
		memoryMB  int
		env       map[string]string
		limitsOff bool
		wantPids  any // HostConfig.PidsLimit as JSON decodes it, nil = unset
		wantEnv   []string
	}{
		{name: "gvisor default sandbox", runtime: models.RuntimeGvisor, memoryMB: 1024, wantPids: float64(3072), wantEnv: []string{"1024"}},
		{name: "gvisor large sandbox", runtime: models.RuntimeGvisor, memoryMB: 8192, wantPids: float64(9216), wantEnv: []string{"4096"}},
		{name: "gvisor drops a create's own value", runtime: models.RuntimeGvisor, memoryMB: 1024,
			env: map[string]string{gvisorpids.EnvVar: "0"}, wantPids: float64(3072), wantEnv: []string{"1024"}},
		{name: "gvisor with resource limits off", runtime: models.RuntimeGvisor, memoryMB: 1024, limitsOff: true, wantPids: nil, wantEnv: nil},
		{name: "runc keeps the node limit", runtime: models.RuntimeDocker, memoryMB: 1024, wantPids: float64(4096), wantEnv: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDaemon{
				t: t,
				imageInspect: func() *http.Response {
					return jsonResponse(http.StatusOK, map[string]any{
						"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{"/e"}, "Cmd": []string{}},
					})
				},
				create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
				start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
			}
			c := newCreateClient(t, d, true, func(c *Client) {
				c.pidsLimit = 4096
				c.resourceLimitsOff = tc.limitsOff
			})
			req := models.CreateSandboxRequest{Image: "img", Runtime: tc.runtime, MemoryMB: tc.memoryMB, Env: tc.env}
			if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err != nil {
				t.Fatalf("Create() = %v", err)
			}
			hc, _ := d.createBody["HostConfig"].(map[string]any)
			if got := hc["PidsLimit"]; got != tc.wantPids {
				t.Errorf("PidsLimit = %v, want %v", got, tc.wantPids)
			}
			env, _ := d.createBody["Env"].([]any)
			if got := envValues(env, gvisorpids.EnvVar); !slices.Equal(got, tc.wantEnv) {
				t.Errorf("%s = %v, want %v", gvisorpids.EnvVar, got, tc.wantEnv)
			}
		})
	}
}

// A parked gVisor toolboxd caps the sentry at park time (adopt does not
// restart it), so the park body carries the env and the host budget.
func TestParkGvisorPidsLimits(t *testing.T) {
	for _, rt := range []string{models.RuntimeGvisor, models.RuntimeDocker} {
		t.Run(rt, func(t *testing.T) {
			d := &poolFakeDaemon{t: t}
			d.create = func() *http.Response {
				return textResponse(http.StatusInternalServerError, "stop-after-create-body")
			}
			c := newPoolClient(t, d, func(c *Client) {
				c.pidsLimit = 4096
				c.readyDir = coverageReadyDir(t)
			})
			if _, err := c.parkContainer(context.Background(), "park-pids", dockerpool.Key{Image: "alpine:3.20", Runtime: rt}); err == nil {
				t.Fatal("expected the stubbed create failure")
			}
			if len(d.createBodies) != 1 {
				t.Fatalf("create bodies = %d", len(d.createBodies))
			}
			var body struct {
				Env        []any          `json:"Env"`
				HostConfig map[string]any `json:"HostConfig"`
			}
			if err := json.Unmarshal(d.createBodies[0], &body); err != nil {
				t.Fatal(err)
			}
			wantPids, wantEnv := float64(4096), []string(nil)
			if rt == models.RuntimeGvisor {
				wantPids, wantEnv = float64(3072), []string{"1024"} // park default memory: 1 GiB
			}
			if got := body.HostConfig["PidsLimit"]; got != wantPids {
				t.Errorf("PidsLimit = %v, want %v", got, wantPids)
			}
			if got := envValues(body.Env, gvisorpids.EnvVar); !slices.Equal(got, wantEnv) {
				t.Errorf("%s = %v, want %v", gvisorpids.EnvVar, got, wantEnv)
			}
		})
	}
}
