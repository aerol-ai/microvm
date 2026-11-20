//go:build linux

package rootd

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// realPeer serves with the production peer check: egress.UnixPeerCheck
// for the configured uid and cgroup, over SO_PEERCRED.
func realPeer(uid uint32, cgroup string) func(*Config, *Options) {
	return func(c *Config, o *Options) {
		c.AgentUID, c.AgentCgroup = uid, cgroup
		o.Peer = nil
	}
}

func versionCode(t *testing.T, r *rig) codes.Code {
	t.Helper()
	_, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
	return status.Code(err)
}

// TestPeerCheckUID: the agent's uid is let in; any other is refused at the
// handshake, and the refusal names the uid.
func TestPeerCheckUID(t *testing.T) {
	me := uint32(os.Getuid())
	t.Run("the agent's uid", func(t *testing.T) {
		r := newRig(t, realPeer(me, ""))
		if c := versionCode(t, r); c != codes.OK {
			t.Fatalf("Version = %v", c)
		}
		if refs := r.refused(); len(refs) != 0 {
			t.Fatalf("refusals %v", refs)
		}
	})
	t.Run("another uid", func(t *testing.T) {
		r := newRig(t, realPeer(me+1, ""))
		if c := versionCode(t, r); c != codes.Unavailable {
			t.Fatalf("Version = %v, want Unavailable", c)
		}
		refs := r.refused()
		if len(refs) == 0 || refs[0].Reason != ReasonPeer || !strings.Contains(refs[0].Detail, "uid") {
			t.Fatalf("refusals %+v", refs)
		}
	})
}

// TestPeerCheckCgroup: on VMs the agent must also be in its unit's cgroup
// (§3.3), so a second process running as the agent's user is refused.
func TestPeerCheckCgroup(t *testing.T) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip(err)
	}
	line := strings.TrimSpace(strings.Split(string(data), "\n")[0])
	me := uint32(os.Getuid())
	if r := newRig(t, realPeer(me, line)); versionCode(t, r) != codes.OK {
		t.Fatalf("a caller in %q was refused", line)
	}
	r := newRig(t, realPeer(me, "not-a-unit.service"))
	if c := versionCode(t, r); c != codes.Unavailable {
		t.Fatalf("Version = %v, want Unavailable", c)
	}
	if refs := r.refused(); len(refs) == 0 || !strings.Contains(refs[0].Detail, "not-a-unit.service") {
		t.Fatalf("refusals %+v", refs)
	}
}

// childEnv makes this test binary a client: TestPeerChild dials the socket
// named here, calls Version and prints what happened.
const childEnv = "AEROLVM_ROOTD_TEST_CHILD_SOCKET"

// TestPeerCheckOtherUsers runs real callers as other users, as root can:
// the agent's uid in the socket's group passes; another uid in that group
// gets through the file mode and is refused by the peer check; the agent's
// uid outside the group is stopped by the file mode before that; and root
// itself, which the file mode never stops, is refused too.
func TestPeerCheckOtherUsers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run callers as other users")
	}
	const agent, group = 65532, 4242
	// The child runs this binary, which sits in a folder only root can
	// read: copy it where the other users can run it.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "rootd.test")
	copyFile(t, exe, bin)
	sockDir := filepath.Join(dir, "s")
	if err := os.Mkdir(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *Config, o *Options) {
		c.Socket, c.SocketGID, c.AgentUID, o.Peer = filepath.Join(sockDir, "root.sock"), group, agent, nil
	})

	run := func(uid, gid uint32) string {
		t.Helper()
		cmd := exec.Command(bin, "-test.run=^TestPeerChild$")
		cmd.Env = append(os.Environ(), childEnv+"="+r.cfg.Socket)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child as %d:%d: %v\n%s", uid, gid, err, out)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "result: "); ok {
				return v
			}
		}
		t.Fatalf("child as %d:%d said nothing:\n%s", uid, gid, out)
		return ""
	}
	for _, tc := range []struct {
		name     string
		uid, gid uint32
		want     string
		refusal  bool
	}{
		{"the agent, in the group", agent, group, "ok", false},
		{"another user in the group", agent + 1, group, "Unavailable", true},
		{"the agent outside the group", agent, group + 1, "permission denied", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(r.refused())
			if got := run(tc.uid, tc.gid); !strings.Contains(got, tc.want) {
				t.Fatalf("child got %q, want %q", got, tc.want)
			}
			if got := len(r.refused()) > before; got != tc.refusal {
				t.Fatalf("refusal heard: %v, want %v (%+v)", got, tc.refusal, r.refused())
			}
		})
	}
	t.Run("root", func(t *testing.T) {
		if c := versionCode(t, r); c != codes.Unavailable {
			t.Fatalf("root's Version = %v, want Unavailable", c)
		}
	})
}

// TestPeerChild is the other user's side of TestPeerCheckOtherUsers.
func TestPeerChild(t *testing.T) {
	sock := os.Getenv(childEnv)
	if sock == "" {
		t.Skip("runs only as TestPeerCheckOtherUsers's child")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		os.Stdout.WriteString("result: " + err.Error() + "\n")
		return
	}
	_ = c.Close()
	_, err = rootdpb.NewRootHelperClient(dialSocket(t, sock)).Version(ctx, &rootdpb.VersionRequest{})
	if err != nil {
		os.Stdout.WriteString("result: " + status.Code(err).String() + "\n")
		return
	}
	os.Stdout.WriteString("result: ok\n")
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
