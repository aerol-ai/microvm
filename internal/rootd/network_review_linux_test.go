//go:build linux

package rootd

// Regression tests for the PR 4 review's findings, as root on the real
// kernel. Each one failed on the code before the fixes.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/network/nsbuild"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return st.Ino
}

// threads is this process's OS thread count.
func threads() int {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return -1
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "Threads:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return -1
}

// TestUnmarkedNamespaceIsLeftAlone (finding 2): a namespace in the netns
// folder that holds loopback alone but is not the helper's (an operator's
// `ip netns add`) is refused by every call, and left as it is. Before the
// fix RealizeNetns replaced it with a sandbox's and RemoveNetns deleted it.
func TestUnmarkedNamespaceIsLeftAlone(t *testing.T) {
	k, _ := kernelRig(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	for _, name := range []string{"offline", "offline2"} {
		if err := nsbuild.CreateNamed(k.netnsDir, name); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(k.netnsDir, "offline")
	before := inode(t, p)
	_, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "offline"})
	wantRefusal(t, r, err, codes.PermissionDenied, ReasonNotSandboxNetns)
	if after := inode(t, p); after != before {
		t.Fatalf("RealizeNetns replaced a namespace the helper never made (inode %d -> %d)", before, after)
	}
	_, err = c.RemoveNetns(ctx, &rootdpb.RemoveNetnsRequest{NetnsName: "offline2"})
	wantRefusal(t, r, err, codes.PermissionDenied, ReasonNotSandboxNetns)
	if _, err := os.Stat(filepath.Join(k.netnsDir, "offline2")); err != nil {
		t.Fatalf("RemoveNetns removed a namespace the helper never made: %v", err)
	}
}

// TestNetnsFolderIsClosedToTheAgent (finding 3): the agent's uid cannot
// open the helper's netns folder, so it cannot hold the flock every build
// takes on it. Before the fix the folder was 0755, and uid 65531 held the
// lock with a read-only descriptor.
func TestNetnsFolderIsClosedToTheAgent(t *testing.T) {
	needRoot(t)
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("no flock(1) here")
	}
	l := newNetLayout(t)
	if _, err := openNetwork(l.cfg); err != nil {
		t.Fatal(err)
	}
	// Every folder above it the test made lets the agent through, so only
	// the netns folder's own mode is what stops it.
	for d := filepath.Dir(l.cfg.Policy.NetnsDir); strings.HasPrefix(d, os.TempDir()+"/"); d = filepath.Dir(d) {
		_ = os.Chmod(d, 0o755)
	}
	try := exec.Command("flock", "-n", "-x", l.cfg.Policy.NetnsDir, "true")
	try.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65531, Gid: 65531, NoSetGroups: true}}
	if out, err := try.CombinedOutput(); err == nil {
		t.Fatalf("uid 65531 took the netns folder's lock (%s)", out)
	}
}

// TestBurstWithTheFolderLockHeld (finding 3): with the folder's flock held
// (only root can now), a burst of builds holds no OS thread each and is
// bounded: past the helper's turns and queue it is answered
// ResourceExhausted at once, every wait ends with its call, and the
// helper serves again once the lock goes. Before the fix each call slept
// in flock(2) on a thread of its own, without end, and a burst past
// 10,000 killed the helper.
func TestBurstWithTheFolderLockHeld(t *testing.T) {
	k, _ := kernelRig(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	if err := os.MkdirAll(k.netnsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := unix.Open(k.netnsDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(lock) }()
	if err := unix.Flock(lock, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	// Two connections: one connection's streams stop at maxStreams on the
	// client side, so the helper's own queue bound is reached only past it.
	conns := []rootdpb.RootHelperClient{rootdpb.NewRootHelperClient(r.conn), rootdpb.NewRootHelperClient(dialSocket(t, r.cfg.Socket))}
	const n = 2 * 1024 // maxStreams
	base := threads()
	var most atomic.Int64
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			if th := int64(threads()); th > most.Load() {
				most.Store(th)
			}
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	codesSeen := map[codes.Code]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := conns[i%2].RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: fmt.Sprintf("burst-%d", i)})
			mu.Lock()
			codesSeen[status.Code(err)]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(stop)
	<-watched
	t.Logf("%d builds with the lock held: %v; OS threads %d at the start, %d at most", n, codesSeen, base, most.Load())
	if grown := most.Load() - int64(base); grown > 200 {
		t.Errorf("the burst grew the helper by %d OS threads; a wait for the lock must hold none", grown)
	}
	if codesSeen[codes.ResourceExhausted] == 0 {
		t.Errorf("no call past the helper's queue was answered ResourceExhausted: %v", codesSeen)
	}
	if codesSeen[codes.OK] != 0 || codesSeen[codes.ResourceExhausted]+codesSeen[codes.DeadlineExceeded] != n {
		t.Errorf("want every call busy or past its deadline: %v", codesSeen)
	}
	// No call built anything, and the helper serves once the lock goes.
	if entries, _ := os.ReadDir(k.netnsDir); len(entries) != 0 {
		t.Errorf("%d namespaces made while the lock was held", len(entries))
	}
	_ = unix.Flock(lock, unix.LOCK_UN)
	if _, err := conns[0].RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "after"}); err != nil {
		t.Fatalf("the helper did not serve after the burst: %v", err)
	}
}

// TestBurstThroughTheAgentsClient (finding 4): 100 builds at once, through
// the client sandboxd builds (rootclient's defaults, as pkg/daemon's
// rootHelperConfig sets them; TestNewRootHelper pins that), all succeed,
// and leave exactly their 100 namespaces. Before the fix the client's 2 s
// bound failed 90 of them while the helper went on building.
func TestBurstThroughTheAgentsClient(t *testing.T) {
	k, _ := kernelRig(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		o.Network = k
	})
	c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, HelperUID: uint32(os.Geteuid())})
	t.Cleanup(func() { _ = c.Close() })
	var failed atomic.Int32
	var first atomic.Value
	d, _ := burstOf(100, func(j int) error {
		// The refiller and the create path set no deadline of their own.
		if _, _, err := c.RealizeNetns(context.Background(), fmt.Sprintf("b-%d", j)); err != nil {
			failed.Add(1)
			first.CompareAndSwap(nil, err.Error())
		}
		return nil
	})
	t.Logf("100 at once through the agent's client: p50 %v p99 %v", percentileOf(d, 0.5), percentileOf(d, 0.99))
	if failed.Load() > 0 {
		t.Fatalf("%d of 100 failed; first: %v", failed.Load(), first.Load())
	}
	if entries, _ := os.ReadDir(k.netnsDir); len(entries) != 100 {
		t.Fatalf("%d namespaces in the folder, want 100", len(entries))
	}
}

// TestSwapHelperProcess is one helper of TestSwapEndsTheCallsChildren
// (its child process only). It stops as cmd/aerolvm-rootd does: Shutdown
// with a grace, and exit only once Shutdown is over.
func TestSwapHelperProcess(t *testing.T) {
	sock := os.Getenv("SWAP_HELPER_SOCK")
	if sock == "" {
		t.Skip("child process only")
	}
	cfg := testConfig(t)
	cfg.Socket, cfg.SocketGID, cfg.AgentUID = sock, 0, 0
	cfg.Policy.NetnsDir = os.Getenv("SWAP_NETNS_DIR")
	cfg.Network = NetworkConfig{PluginDir: os.Getenv("SWAP_PLUGINS"), ConfPath: os.Getenv("SWAP_CONF")}
	srv, err := New(cfg, Options{Containerd: (&stubContainerd{}).handle, Peer: egress.UnixPeerCheck([]uint32{0}, "")}, nil)
	if err != nil {
		fmt.Println("NEW_FAILED", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(sctx)
		close(stopped)
	}()
	fmt.Println("SERVING")
	_ = srv.Serve()
	<-stopped
	os.Exit(0)
}

// runs reports whether pid runs (a zombie runs no more of its code).
func runs(pid int) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || (s[i+2] != 'Z' && s[i+2] != 'X')
}

// TestSwapEndsTheCallsChildren (finding 1): a RemoveNetns in flight when
// its helper is swapped out is tried again on the next helper (rootclient
// retrySafe), which holds only if the first try can never run after the
// second. The first try's CNI plugin had started its IPAM plugin as a
// child; that child must die with the call, not finish the first try's
// DEL after the retry and the slot's next build, freeing the address the
// new build holds. Before the fix it was orphaned and did just that.
func TestSwapEndsTheCallsChildren(t *testing.T) {
	needRoot(t)
	if os.Getenv("SWAP_HELPER_SOCK") != "" {
		t.Skip("parent only")
	}
	base := t.TempDir()
	plugins := filepath.Join(base, "cni", "bin")
	confDir := filepath.Join(base, "cni", "net.d")
	leases := filepath.Join(base, "leases")
	for _, d := range []string{plugins, confDir, leases} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logf := filepath.Join(base, "plugin.log")
	slow := filepath.Join(base, "slowdel")
	pidf := filepath.Join(base, "slow.pid")
	// The bridge stand-in runs its IPAM plugin as a child, as the real one
	// does; the IPAM stand-in keeps a lease file per container id, and its
	// first DEL is slow, as one waiting on host-local's lock is.
	bridge := fmt.Sprintf(`#!/bin/sh
cat >/dev/null
case "$CNI_COMMAND" in
ADD) echo "bridge ADD $CNI_CONTAINERID" >> %[1]s
     "$CNI_PATH/host-local" </dev/null
     echo '{"cniVersion":"1.0.0","ips":[{"address":"10.88.0.5/16"}]}' ;;
DEL) echo "bridge DEL $CNI_CONTAINERID" >> %[1]s
     "$CNI_PATH/host-local" </dev/null ;;
esac
`, logf)
	ipam := fmt.Sprintf(`#!/bin/sh
case "$CNI_COMMAND" in
ADD) touch %[1]s/$CNI_CONTAINERID; echo "ipam ADD $CNI_CONTAINERID" >> %[2]s ;;
DEL) if [ -e %[3]s ]; then rm -f %[3]s; echo $$ > %[4]s; sleep 6; fi
     rm -f %[1]s/$CNI_CONTAINERID; echo "ipam DEL $CNI_CONTAINERID" >> %[2]s ;;
esac
`, leases, logf, slow, pidf)
	if err := os.WriteFile(filepath.Join(plugins, "bridge"), []byte(bridge), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "host-local"), []byte(ipam), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(confDir, "aerolvm.conflist")
	if err := os.WriteFile(conf, []byte(`{"cniVersion":"1.0.0","name":"aerolvm","plugins":[{"type":"bridge","bridge":"aerolvm0","isGateway":true,"ipMasq":false,"ipam":{"type":"host-local","subnet":"10.88.0.0/16"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortDir(t), "sock", "root.sock")
	netnsDir := tmpfsFolder(t, filepath.Join(base, "netns"))
	t.Cleanup(func() {
		entries, _ := os.ReadDir(netnsDir)
		for _, e := range entries {
			_ = nsbuild.DeleteNamed(netnsDir, e.Name())
		}
	})
	start := func(name string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSwapHelperProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), "SWAP_HELPER_SOCK="+sock, "SWAP_NETNS_DIR="+netnsDir, "SWAP_PLUGINS="+plugins, "SWAP_CONF="+conf)
		out, err := os.Create(filepath.Join(base, name+".out"))
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		for range 400 {
			raw, _ := os.ReadFile(out.Name())
			if strings.Contains(string(raw), "SERVING") {
				return cmd
			}
			if strings.Contains(string(raw), "NEW_FAILED") {
				t.Fatalf("%s: %s", name, raw)
			}
			time.Sleep(25 * time.Millisecond)
		}
		raw, _ := os.ReadFile(out.Name())
		t.Fatalf("%s never served: %s", name, raw)
		return nil
	}
	h1 := start("h1")
	// A retry window long enough for the next helper to start, as the
	// supervisor's swap gives it.
	c := rootclient.New(rootclient.Config{Socket: sock, Timeout: 10 * time.Second, HelperUID: 0})
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()
	if _, _, err := c.RealizeNetns(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slow, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() { removed <- c.RemoveNetns(ctx, "x", "") }()
	var slowPid int
	for i := 0; slowPid == 0; i++ {
		if raw, err := os.ReadFile(pidf); err == nil && strings.HasSuffix(string(raw), "\n") {
			slowPid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
		if i > 400 {
			t.Fatal("the slow DEL never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The supervisor's swap: SIGTERM, wait for the helper to exit, SIGKILL
	// it past the stop's grace, start the next one on the same socket. The
	// helper's own part is to have ended the call's children by the time
	// it exits, whichever way it exits; the supervisor's part (emptying
	// the helper's cgroup) is not here.
	_ = h1.Process.Signal(syscall.SIGTERM)
	exited := make(chan struct{})
	go func() { _ = h1.Wait(); close(exited) }()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Log("helper 1 still running 3 s after SIGTERM; killed")
		_ = h1.Process.Kill()
		<-exited
	}
	start("h2")
	if err := <-removed; err != nil {
		t.Fatalf("RemoveNetns, tried again on the next helper: %v", err)
	}
	// The pool builds the slot again under the same name.
	if _, _, err := c.RealizeNetns(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(10 * time.Second); runs(slowPid) && time.Now().Before(end); {
		time.Sleep(20 * time.Millisecond)
	}
	raw, _ := os.ReadFile(logf)
	t.Logf("plugin log:\n%s", raw)
	if runs(slowPid) {
		t.Fatalf("the first try's IPAM plugin (pid %d) still runs", slowPid)
	}
	if _, err := os.Stat(filepath.Join(leases, "x")); err != nil {
		t.Fatal("x is built again on the next helper, but its lease is gone: the first try's IPAM DEL ran after the retry")
	}
}
