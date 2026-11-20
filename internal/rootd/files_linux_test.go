//go:build linux

package rootd

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
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
	for _, dir := range []string{filepath.Join(r.cfg.Files.Hosts, testCID), filepath.Join(r.cfg.Policy.FIFODir, testCID)} {
		if st := statOf(t, dir); st.Uid != 0 || st.Mode&0o777 != 0o755 {
			t.Fatalf("%s owned by %d, mode %o", dir, st.Uid, st.Mode&0o777)
		}
	}
}
