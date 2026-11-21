//go:build linux

package gate

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

func mkfifo(p string) error { return unix.Mkfifo(p, 0o660) }

// chmodRaw sets mode bits as the kernel reads them: os.Chmod drops 0o1000.
func chmodRaw(p string, mode uint32) error { return unix.Chmod(p, mode) }

// hostsTree lays out a bind root as the helper will (plan T2): root-owned
// folders no one else can write, holding a sandbox's host files. Owned by
// the test's user, which the checker trusts in place of root.
func hostsTree(t *testing.T) (root string, c hostPaths) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "hosts")
	if err := os.MkdirAll(filepath.Join(root, testID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, testID, "resolv.conf"), []byte("nameserver 10.0.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, hostPaths{owner: uint32(os.Getuid())}
}

func TestBindChecker(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string) string // returns the source
		ok    bool
		// folder: the source may be a folder (a bind root's, the external
		// mounts); otherwise only a file or socket is (a helper's file).
		folder bool
	}{
		{"a regular file", func(t *testing.T, root string) string { return filepath.Join(root, testID, "resolv.conf") }, true, false},
		{"a folder where folders may be bound", func(t *testing.T, root string) string { return filepath.Join(root, testID) }, true, true},
		// A folder bound into a sandbox (uid 0) is one it can write, so a
		// helper file root accepts only the files in it.
		{"a folder where only a file may be bound", func(t *testing.T, root string) string { return filepath.Join(root, testID) }, false, false},
		{"a socket (the ready socket)", func(t *testing.T, root string) string {
			// A short path: a socket's name has a length limit.
			dir, err := os.MkdirTemp("/tmp", "b")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			l, err := net.Listen("unix", filepath.Join(dir, "r.sock"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			return filepath.Join(dir, "r.sock")
		}, true, false},
		// Round 2 finding 1: the agent turns its host file into a link to /,
		// and runc follows it, binding the host's whole filesystem in.
		{"a link to /", func(t *testing.T, root string) string {
			p := filepath.Join(root, testID, "resolv.conf")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/", p); err != nil {
				t.Fatal(err)
			}
			return p
		}, false, false},
		{"a link to a file in the root", func(t *testing.T, root string) string {
			p := filepath.Join(root, testID, "hosts")
			if err := os.Symlink(filepath.Join(root, testID, "resolv.conf"), p); err != nil {
				t.Fatal(err)
			}
			return p
		}, false, false},
		{"a path through a linked folder", func(t *testing.T, root string) string {
			if err := os.Symlink("/etc", filepath.Join(root, "sb-2")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "sb-2", "passwd")
		}, false, false},
		{"a hard-linked file", func(t *testing.T, root string) string {
			p := filepath.Join(root, testID, "resolv.conf")
			if err := os.Link(p, filepath.Join(root, testID, "second-name")); err != nil {
				t.Fatal(err)
			}
			return p
		}, false, false},
		{"a FIFO", func(t *testing.T, root string) string {
			p := filepath.Join(root, testID, "fifo")
			if err := mkfifo(p); err != nil {
				t.Fatal(err)
			}
			return p
		}, false, false},
		// Round 2 finding 1(b): a folder the agent can write lets it swap
		// the file after the check, so it is refused outright.
		{"a root others can write", func(t *testing.T, root string) string {
			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, testID, "resolv.conf")
		}, false, false},
		{"a group-writable sandbox folder", func(t *testing.T, root string) string {
			if err := os.Chmod(filepath.Join(root, testID), 0o775); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, testID, "resolv.conf")
		}, false, false},
		{"a sticky world-writable folder under the root", func(t *testing.T, root string) string {
			if err := chmodRaw(filepath.Join(root, testID), 0o1777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, testID, "resolv.conf")
		}, false, false},
		{"missing", func(t *testing.T, root string) string { return filepath.Join(root, testID, "nope") }, false, false},
		{"unclean", func(t *testing.T, root string) string { return root + "/" + testID + "/../" + testID + "/resolv.conf" }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, c := hostsTree(t)
			src := tc.setup(t, root)
			bindRoot := root
			if tc.name == "a socket (the ready socket)" {
				bindRoot = filepath.Dir(src)
			}
			err := c.CheckBind(bindRoot, src, tc.folder)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if rootpolicy.RuleOf(err) != rootpolicy.RuleMount {
				t.Fatalf("err %v, want a mount refusal", err)
			}
		})
	}
}

// TestBindCheckerOwners needs root to hand files to the agent's user.
func TestBindCheckerOwners(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	t.Run("the agent owns the sandbox's folder", func(t *testing.T) {
		root, c := hostsTree(t)
		if err := os.Lchown(filepath.Join(root, testID), 65532, 65532); err != nil {
			t.Fatal(err)
		}
		if err := c.CheckBind(root, filepath.Join(root, testID, "resolv.conf"), false); rootpolicy.RuleOf(err) != rootpolicy.RuleMount {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("root's tree passes the default checker", func(t *testing.T) {
		root, _ := hostsTree(t)
		if err := defaultBindChecker().CheckBind(root, filepath.Join(root, testID, "resolv.conf"), false); err != nil {
			t.Fatal(err)
		}
	})
}

// TestRuncPlantRefused runs only beside the review's runc reproduction
// (POC_PLANT=1): the agent (uid 65532) has linked the real
// /var/lib/sandboxd/containerd/hosts/sb-1/resolv.conf to /. The gate's own
// checker, as root, must refuse the bind runc would follow.
func TestRuncPlantRefused(t *testing.T) {
	if os.Getenv("POC_PLANT") == "" {
		t.Skip("POC_PLANT not set")
	}
	hosts := "/var/lib/sandboxd/containerd/hosts"
	p := testPolicy()
	p.BindRoots = []string{hosts}
	g, err := New(Config{Policy: p, Upstream: &grpc.ClientConn{}})
	if err != nil {
		t.Fatal(err)
	}
	s := goodSpec(t)
	s.Mounts = []specs.Mount{{Type: "bind", Source: hosts + "/" + testID + "/resolv.conf", Destination: "/host", Options: []string{"rbind", "rw"}}}
	c := goodContainer(t)
	c.Spec = specAny(t, s)
	err = g.checkBinds(policyContainer(c))
	if rootpolicy.RuleOf(err) != rootpolicy.RuleMount {
		t.Fatalf("the gate let the planted bind through: %v", err)
	}
	t.Logf("REFUSED by the gate: %v", err)
}

// TestGateBindsOnDisk is round 2's finding 1 end to end, the reviewer's
// exact plant: the agent links hosts/sb-1/resolv.conf to / and asks for a
// read-write bind of it. The rules on the text pass it; the gate's walk
// refuses it at create and again at task create. A real file passes.
func TestGateBindsOnDisk(t *testing.T) {
	root, c := hostsTree(t)
	src := filepath.Join(root, testID, "resolv.conf")
	p := testPolicy()
	p.BindRoots = []string{root}
	p.BindFiles = nil
	withBind := func(t *testing.T) *containersapi.Container {
		s := goodSpec(t)
		s.Mounts = []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
			{Type: "bind", Source: src, Destination: "/host", Options: []string{"rbind", "rw"}},
		}
		cont := goodContainer(t)
		cont.Spec = specAny(t, s)
		return cont
	}
	r := newRig(t, p, func(cfg *Config) { cfg.Binds = c })
	if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: withBind(t)}); err != nil {
		t.Fatalf("a real host file refused: %v", err)
	}
	var s specs.Spec
	if err := json.Unmarshal(withBind(t).Spec.Value, &s); err != nil {
		t.Fatal(err)
	}
	if err := rootpolicy.CheckSpec(p, testID, &s); err != nil {
		t.Fatalf("the text rules refuse the plant's spec, so this test proves nothing: %v", err)
	}

	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", src); err != nil {
		t.Fatal(err)
	}
	// A fresh containerd: the one above has seen the allowed create.
	r = newRig(t, p, func(cfg *Config) { cfg.Binds = c })
	_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: withBind(t)})
	r.wantRefused(err, cCreate, string(rootpolicy.RuleMount))
	r.storedContainer(withBind(t))
	_, err = r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs()})
	r.wantRefused(err, tCreate, string(rootpolicy.RuleMount))
}
