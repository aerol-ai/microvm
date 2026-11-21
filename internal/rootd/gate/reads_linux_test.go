//go:build linux

package gate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// agentUID stands for the agent when the test runs as root.
const agentUID = 65531

// readFixture is a runsc config and a restore image as the helper lays
// them out: in folders only it (here: this test's user) can write.
func readFixture(t *testing.T) (dir string, h hostPaths) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "runsc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runsc", "config.toml"), []byte("[runsc_config]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "moves", "in", testID), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, hostPaths{owner: uint32(os.Getuid())}
}

func TestReadChecker(t *testing.T) {
	cfg := func(p string) rootpolicy.RootRead {
		return rootpolicy.RootRead{Path: p, Rule: rootpolicy.RuleRuntimeOptions}
	}
	img := func(p string) rootpolicy.RootRead {
		return rootpolicy.RootRead{Path: p, Folder: true, Rule: rootpolicy.RuleCheckpoint}
	}
	for _, tc := range []struct {
		name  string
		root  bool // needs root to set up
		setup func(t *testing.T, dir string) rootpolicy.RootRead
		want  string // "" passes
	}{
		{"the helper's config", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			return cfg(filepath.Join(dir, "runsc", "config.toml"))
		}, ""},
		{"the helper's restore image", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			return img(filepath.Join(dir, "moves", "in", testID))
		}, ""},
		{"a config others can write", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			p := filepath.Join(dir, "runsc", "config.toml")
			if err := os.Chmod(p, 0o666); err != nil {
				t.Fatal(err)
			}
			return cfg(p)
		}, "others can write it"},
		{"a config in a folder the agent can write", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			if err := os.Chmod(filepath.Join(dir, "runsc"), 0o777); err != nil {
				t.Fatal(err)
			}
			return cfg(filepath.Join(dir, "runsc", "config.toml"))
		}, "can be written by others"},
		{"a config that is a link", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			p := filepath.Join(dir, "runsc", "link.toml")
			if err := os.Symlink(filepath.Join(dir, "runsc", "config.toml"), p); err != nil {
				t.Fatal(err)
			}
			return cfg(p)
		}, "not a regular file"},
		{"a config through a linked folder", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			if err := os.Symlink(filepath.Join(dir, "runsc"), filepath.Join(dir, "via")); err != nil {
				t.Fatal(err)
			}
			return cfg(filepath.Join(dir, "via", "config.toml"))
		}, "via is not a folder"},
		{"a config with a second name", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			if err := os.Link(filepath.Join(dir, "runsc", "config.toml"), filepath.Join(dir, "runsc", "second")); err != nil {
				t.Fatal(err)
			}
			return cfg(filepath.Join(dir, "runsc", "config.toml"))
		}, "hard links"},
		{"a folder where a config goes", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			return cfg(filepath.Join(dir, "runsc"))
		}, "not a regular file"},
		{"a file where an image goes", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			return img(filepath.Join(dir, "runsc", "config.toml"))
		}, "not a folder"},
		{"an image others can write", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			p := filepath.Join(dir, "moves", "in", testID)
			if err := os.Chmod(p, 0o777); err != nil {
				t.Fatal(err)
			}
			return img(p)
		}, "others can write it"},
		{"a missing config", false, func(t *testing.T, dir string) rootpolicy.RootRead {
			return cfg(filepath.Join(dir, "runsc", "nope.toml"))
		}, "open nope.toml"},
		{"a config the agent planted", true, func(t *testing.T, dir string) rootpolicy.RootRead {
			p := filepath.Join(dir, "runsc", "config.toml")
			if err := os.Chown(p, agentUID, agentUID); err != nil {
				t.Fatal(err)
			}
			return cfg(p)
		}, "belongs to uid 65531"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() != 0 {
				t.Skip("needs root to give a file to another user")
			}
			dir, h := readFixture(t)
			r := tc.setup(t, dir)
			err := h.CheckRead(r)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if rootpolicy.RuleOf(err) != r.Rule || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckRead = %v, want rule %s naming %q", err, r.Rule, tc.want)
			}
		})
	}
}

// TestGateRefusesAPlantedRunscConfig is review H2 end to end: the runsc
// config a container names is on the policy's list, but the file there is
// one the agent could write. The gate refuses the create, and containerd
// never stores it; the helper's own config passes.
func TestGateRefusesAPlantedRunscConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		plant   func(t *testing.T, cfg string)
		refused bool
	}{
		{"the helper's own config", func(*testing.T, string) {}, false},
		{"a config in a folder the agent can write", func(t *testing.T, cfg string) {
			if err := unix.Chmod(filepath.Dir(cfg), 0o777); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a config the agent can write", func(t *testing.T, cfg string) {
			if err := os.Chmod(cfg, 0o666); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a link where the config goes", func(t *testing.T, cfg string) {
			other := filepath.Join(filepath.Dir(cfg), "other.toml")
			if err := os.Rename(cfg, other); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, cfg); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, h := readFixture(t)
			cfg := filepath.Join(dir, "runsc", "config.toml")
			tc.plant(t, cfg)
			p := testPolicy()
			p.RunscConfigPaths = []string{cfg}
			r := newRig(t, p, func(c *Config) { c.Reads = h })
			statefulContainerd(r)
			client, ctx := agentClient(t, r)
			spec := goodSpec(t)
			spec.Annotations = map[string]string{rootpolicy.CRIContainerTypeAnnotation: rootpolicy.CRIContainerTypeSandbox}
			_, err := client.NewContainer(ctx, testID, cntr.WithSpec(spec), withSnapshot,
				cntr.WithRuntime(rootpolicy.RuntimeRunsc, &runtimeoptions.Options{TypeUrl: rootpolicy.RunscOptionsTypeURL, ConfigPath: cfg}))
			stored := slices.Contains(r.fake.methodsSeen(), "/containerd.services.containers.v1.Containers/Create")
			if !tc.refused {
				if err != nil || !stored {
					t.Fatalf("NewContainer = %v, stored %v", err, stored)
				}
				return
			}
			refs := r.refused()
			if !errdefs.IsPermissionDenied(err) || stored || len(refs) != 1 || refs[0].Reason != string(rootpolicy.RuleRuntimeOptions) {
				t.Fatalf("NewContainer = %v, stored %v, refusals %+v; want one runtime_options refusal", err, stored, refs)
			}
		})
	}
}
