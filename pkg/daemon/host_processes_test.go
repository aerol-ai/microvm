package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// A worker pod whose agent container owns its PID namespace would kill every
// WASM, V8 and Firecracker sandbox at each agent restart: it does not boot
// with them on (C14). Everywhere else the check stays out of the way.
func TestCheckHostProcessesOutliveAgent(t *testing.T) {
	const pod = "/kubepods.slice/pod1/sandboxes"
	worker := func(edit func(*config.Config)) config.Config {
		c := config.Config{NodeRole: config.NodeRoleWorker, HostProcessCgroupParent: pod, EnableWasm: true}
		if edit != nil {
			edit(&c)
		}
		return c
	}
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		owns    bool
		ownsErr error
		wantErr string
	}{
		{name: "shared namespace boots", cfg: worker(nil)},
		{name: "own namespace refused", cfg: worker(nil), owns: true, wantErr: "shareProcessNamespace"},
		{name: "unreadable procfs refused", cfg: worker(nil), ownsErr: errors.New("no procfs"), wantErr: "cannot tell"},
		{name: "V8 alone is checked", cfg: worker(func(c *config.Config) { c.EnableWasm, c.EnableIsolate = false, true }), owns: true, wantErr: "shareProcessNamespace"},
		{name: "gVisor only: not checked", cfg: worker(func(c *config.Config) { c.EnableWasm = false }), owns: true},
		{name: "no cgroup parent (VM or plain container): not checked", cfg: worker(func(c *config.Config) { c.HostProcessCgroupParent = "" }), owns: true},
		{name: "not a worker: not checked", cfg: worker(func(c *config.Config) { c.NodeRole = config.NodeRoleServer }), owns: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := ownsPIDNamespace
			ownsPIDNamespace = func() (bool, error) { return tc.owns, tc.ownsErr }
			t.Cleanup(func() { ownsPIDNamespace = old })
			err := checkHostProcessesOutliveAgent(tc.cfg)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
