//go:build linux

package rootd

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
)

// TestReadySocketSwapRace: the agent swaps the name in its ready folder
// back and forth, as fast as it can, between its real socket and a link
// to a file it wants root to hand a sandbox. Whatever the timing, the
// helper's name is only ever the agent's socket: it checks what it linked
// after linking, where the agent can no longer change it. Without that
// check (a stat of the agent's name, then a link of it) a swap between
// the two would put the link in root's folder.
func TestReadySocketSwapRace(t *testing.T) {
	r := newRig(t, nil)
	f := r.srv.files
	agentPath := agentSocket(t, r.cfg, testCID, "0a1b")
	sockIno := statOf(t, agentPath).Ino
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Two names to swap in with rename, which is one step.
	sockAlt, linkAlt := agentPath+".s", agentPath+".l"
	if err := os.Link(agentPath, sockAlt); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, linkAlt); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			src := sockAlt
			if i%2 == 1 {
				src = linkAlt
			}
			// Keep a spare of each, so both stay available to swap in.
			tmp := agentPath + ".t"
			_ = os.Remove(tmp)
			if err := os.Link(src, tmp); err != nil {
				_ = os.Symlink(secret, tmp)
			}
			_ = os.Rename(tmp, agentPath)
		}
	}()
	var ok, refused atomic.Int64
	req := &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "0a1b"}
	name := filepath.Join(r.cfg.Files.Ready, testCID, "0a1b.sock")
	for range 3000 {
		_, err := f.ensureReadySocket(req)
		var fe *fileError
		switch {
		case err == nil:
			ok.Add(1)
		case errors.As(err, &fe) && fe.reason == ReasonNotAgentSocket:
			refused.Add(1)
		case err != nil && strings.Contains(err.Error(), "no ready socket"):
			// Between a remove and a rename in the loop above.
		default:
			close(stop)
			wg.Wait()
			t.Fatalf("unexpected error: %v", err)
		}
		if fi, err := os.Lstat(name); err == nil {
			st := fi.Sys().(*syscall.Stat_t)
			if fi.Mode().Type() != fs.ModeSocket || st.Ino != sockIno {
				close(stop)
				wg.Wait()
				t.Fatalf("the helper's name is %v (inode %d), not the agent's socket (inode %d)", fi.Mode(), st.Ino, sockIno)
			}
		}
	}
	close(stop)
	wg.Wait()
	if ok.Load() == 0 || refused.Load() == 0 {
		t.Logf("linked %d, refused %d: the swap timing never hit both sides", ok.Load(), refused.Load())
	}
	entries, _ := os.ReadDir(filepath.Join(r.cfg.Files.Ready, testCID))
	for _, e := range entries {
		if e.Name() != "0a1b.sock" {
			t.Fatalf("leftover %s in the helper's folder", e.Name())
		}
	}
	t.Logf("linked %d, refused %d", ok.Load(), refused.Load())
}

// TestReadySocketOwners: as root, the helper names a socket only if the
// agent's uid owns it; root's own socket, or another user's, linked into
// the agent's folder under a container's name, is refused.
func TestReadySocketOwners(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand sockets to other users")
	}
	const agent = 65531
	for _, tc := range []struct {
		name  string
		owner int
		want  codes.Code
	}{
		{"the agent's socket", agent, codes.OK},
		{"root's socket", 0, codes.PermissionDenied},
		{"another user's socket", 65532, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(c *Config, _ *Options) { c.AgentUID = agent })
			if err := os.MkdirAll(r.cfg.Files.AgentReady, 0o755); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(r.cfg.Files.AgentReady, testCID+".sock")
			ln, err := net.Listen("unix", p)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if err := os.Lchown(p, tc.owner, tc.owner); err != nil {
				t.Fatal(err)
			}
			resp, err := r.srv.files.ensureReadySocket(&rootdpb.EnsureReadySocketRequest{ContainerId: testCID})
			if got := status.Code(toStatus(err)); got != tc.want {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if tc.want == codes.OK {
				if st := statOf(t, resp.GetPath()); st.Uid != agent || st.Ino != statOf(t, p).Ino {
					t.Fatalf("named uid %d inode %d", st.Uid, st.Ino)
				}
			}
		})
	}
}

func toStatus(err error) error {
	if fe, ok := err.(*fileError); ok {
		return status.Error(fe.code, fe.msg)
	}
	return err
}

// TestFilesOwnedByRoot: as root, the files are root's and the FIFOs are
// readable by the agent's group alone.
func TestFilesOwnedByRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	r := newRig(t, func(c *Config, _ *Options) { c.SocketGID = 4242 })
	c := helperClient(r)
	hosts, err := c.EnsureHostFiles(callCtx(t), &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID})
	if err != nil {
		t.Fatal(err)
	}
	fifos, err := c.EnsureTaskFIFOs(callCtx(t), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: testCID})
	if err != nil {
		t.Fatal(err)
	}
	if st := statOf(t, hosts.GetHostnamePath()); st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("hostname owned %d:%d", st.Uid, st.Gid)
	}
	if st := statOf(t, fifos.GetStdoutPath()); st.Uid != 0 || st.Gid != 4242 || st.Mode&0o777 != 0o640 {
		t.Fatalf("stdout FIFO owned %d:%d mode %o", st.Uid, st.Gid, st.Mode&0o777)
	}
	for _, tc := range []struct {
		dir       string
		gid, mode uint32
	}{
		{filepath.Join(r.cfg.Files.Hosts, testCID), 0, 0o755},
		// The agent's group reaches its FIFOs; no one else does.
		{r.cfg.Policy.FIFODir, 4242, 0o750},
		{filepath.Join(r.cfg.Policy.FIFODir, testCID), 4242, 0o750},
	} {
		if st := statOf(t, tc.dir); st.Uid != 0 || st.Gid != tc.gid || st.Mode&0o7777 != tc.mode {
			t.Fatalf("%s owned by %d:%d, mode %o; want 0:%d, %o", tc.dir, st.Uid, st.Gid, st.Mode&0o7777, tc.gid, tc.mode)
		}
	}
}

// dialEnv makes this test binary a dialer: TestReadyDialChild connects to
// the socket it names and says what happened.
const dialEnv = "AEROLVM_ROOTD_TEST_DIAL"

// TestReadyNameClosedToOtherUsers: as root, another user can no more reach
// the agent's ready socket through the helper's name for it than through
// the agent's own name. The agent's 0700 ready folder keeps others off
// its socket (pkg/docker), and the helper's folders on the way to its
// name are root's alone: only root (runc, the gate) needs that name.
func TestReadyNameClosedToOtherUsers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a dial as another user")
	}
	const agent, other = 65531, 1000
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *Config, _ *Options) { c.AgentUID = agent })
	// Every folder above the two ready folders lets others through, so the
	// ready folders alone decide. Only the test's own are changed.
	base := filepath.Dir(filepath.Dir(r.cfg.Files.AgentReady))
	for p := filepath.Dir(base); p != "/"; p = filepath.Dir(p) {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm()&0o001 == 0 {
			t.Skipf("%s is closed to other users, so this test would prove nothing", p)
		}
	}
	for _, p := range []string{base, filepath.Dir(r.cfg.Files.Ready), filepath.Dir(r.cfg.Files.AgentReady)} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(base, "rootd.test")
	copyFile(t, exe, bin)
	// The agent's ready folder as pkg/docker makes it: 0700, the agent's.
	if err := os.MkdirAll(r.cfg.Files.AgentReady, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(r.cfg.Files.AgentReady, agent, agent); err != nil {
		t.Fatal(err)
	}
	ln, err := dockerpkg.NewReadyListener(r.cfg.Files.AgentReady, testCID, "token", "0a1b")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Lchown(ln.HostSocketPath(), agent, agent); err != nil {
		t.Fatal(err)
	}
	resp, err := r.srv.files.ensureReadySocket(&rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "0a1b"})
	if err != nil {
		t.Fatal(err)
	}
	dial := func(uid uint32, sock string) string {
		t.Helper()
		cmd := exec.Command(bin, "-test.run=^TestReadyDialChild$")
		cmd.Env = append(os.Environ(), dialEnv+"="+sock)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("dial as %d: %v\n%s", uid, err, out)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "result: "); ok {
				return v
			}
		}
		t.Fatalf("dial as %d said nothing:\n%s", uid, out)
		return ""
	}
	for _, tc := range []struct {
		name string
		uid  uint32
		sock string
		want string
	}{
		{"another user, the agent's name", other, ln.HostSocketPath(), "permission denied"},
		{"another user, the helper's name", other, resp.GetPath(), "permission denied"},
		{"the agent, its own name", agent, ln.HostSocketPath(), "connected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dial(tc.uid, tc.sock); !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	// Root, as runc and the gate, still reaches the helper's name.
	c, err := net.Dial("unix", resp.GetPath())
	if err != nil {
		t.Fatalf("root cannot reach the helper's name: %v", err)
	}
	_ = c.Close()
}

// TestReadyDialChild is the dialing side of TestReadyNameClosedToOtherUsers.
func TestReadyDialChild(t *testing.T) {
	sock := os.Getenv(dialEnv)
	if sock == "" {
		t.Skip("runs only as TestReadyNameClosedToOtherUsers's child")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		os.Stdout.WriteString("result: " + err.Error() + "\n")
		return
	}
	_ = c.Close()
	os.Stdout.WriteString("result: connected\n")
}
