package docker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRawDockerEventNormalize(t *testing.T) {
	const containerID = "abcd1234ef567890"
	const sandboxName = "/sb-abcd1234ef56"
	const wantSandboxID = "sb-abcd1234ef56"

	cases := []struct {
		name        string
		payload     string
		wantOK      bool
		wantAction  string
		wantExit    int
		wantSandbox string
	}{
		{
			name: "die with exit code",
			payload: `{
				"status": "die",
				"id": "` + containerID + `",
				"time": 1700000000,
				"Actor": {"Attributes": {"name": "` + sandboxName + `", "exitCode": "137"}}
			}`,
			wantOK:      true,
			wantAction:  "die",
			wantExit:    137,
			wantSandbox: wantSandboxID,
		},
		{
			name: "destroy without exit code",
			payload: `{
				"Action": "destroy",
				"id": "` + containerID + `",
				"time": 1700000001,
				"Actor": {"Attributes": {"name": "` + sandboxName + `"}}
			}`,
			wantOK:      true,
			wantAction:  "destroy",
			wantExit:    0,
			wantSandbox: wantSandboxID,
		},
		{
			name: "oom",
			payload: `{
				"status": "oom",
				"id": "` + containerID + `",
				"Actor": {"Attributes": {"name": "` + sandboxName + `"}}
			}`,
			wantOK:      true,
			wantAction:  "oom",
			wantSandbox: wantSandboxID,
		},
		{
			name:    "missing id",
			payload: `{"status":"die"}`,
			wantOK:  false,
		},
		{
			name:    "missing action",
			payload: `{"id":"` + containerID + `"}`,
			wantOK:  false,
		},
		{
			name: "missing name attribute",
			payload: `{
				"status": "die",
				"id": "` + containerID + `"
			}`,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw rawDockerEvent
			if err := json.NewDecoder(strings.NewReader(tc.payload)).Decode(&raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got, ok := raw.normalize()
			if ok != tc.wantOK {
				t.Fatalf("normalize ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.Action != tc.wantAction {
				t.Errorf("action = %q, want %q", got.Action, tc.wantAction)
			}
			if got.ExitCode != tc.wantExit {
				t.Errorf("exit code = %d, want %d", got.ExitCode, tc.wantExit)
			}
			if got.SandboxID != tc.wantSandbox {
				t.Errorf("sandbox id = %q, want %q", got.SandboxID, tc.wantSandbox)
			}
			if got.ContainerID != containerID {
				t.Errorf("container id = %q, want %q", got.ContainerID, containerID)
			}
		})
	}
}

func TestRawDockerEventNormalizeStreamOrder(t *testing.T) {
	// Multiple NDJSON frames decoded sequentially, simulating Docker's stream.
	payload := `{"status":"start","id":"aaaaaaaaaaaaffff","time":1,"Actor":{"Attributes":{"name":"/sb-aaaa1111"}}}
{"status":"die","id":"aaaaaaaaaaaaffff","Actor":{"Attributes":{"name":"/sb-aaaa1111","exitCode":"0"}},"time":2}
{"status":"destroy","id":"aaaaaaaaaaaaffff","time":3,"Actor":{"Attributes":{"name":"/sb-aaaa1111"}}}
`
	decoder := json.NewDecoder(strings.NewReader(payload))
	wantActions := []string{"start", "die", "destroy"}

	for i, want := range wantActions {
		var raw rawDockerEvent
		if err := decoder.Decode(&raw); err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		ev, ok := raw.normalize()
		if !ok {
			t.Fatalf("frame %d normalize returned !ok", i)
		}
		if ev.Action != want {
			t.Errorf("frame %d action = %q, want %q", i, ev.Action, want)
		}
		if ev.SandboxID != "sb-aaaa1111" {
			t.Errorf("frame %d sandbox = %q, want %q", i, ev.SandboxID, "sb-aaaa1111")
		}
	}
}
