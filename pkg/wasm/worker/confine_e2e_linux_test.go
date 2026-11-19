//go:build linux

package worker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

const confinedChildEnv = "AEROL_WASM_CONFINED_TEST_CHILD"

// e2eWorkerUID is "nobody" in the golang image.
const e2eWorkerUID = 65534

// TestConfinedWorkerChild is the worker half of TestConfinedWorkerEndToEnd:
// RunCLI exactly as sandboxd starts it (`sandboxd --wasm-worker <socket>`).
func TestConfinedWorkerChild(t *testing.T) {
	sock := os.Getenv(confinedChildEnv)
	if sock == "" {
		t.Skip("child half of TestConfinedWorkerEndToEnd")
	}
	run := RunCLI
	if os.Getenv(confinedChildEnv+"_RESIDENT") == "1" {
		run = RunCLIResident
	}
	err := run([]string{sock})
	fmt.Fprintln(os.Stderr, "worker exited:", err)
	os.Exit(3)
}

const fenceChildEnv = "AEROL_WASM_FENCE_TEST_CHILD"

// TestConfinedConnectChild is the worker half of
// TestWorkerFenceBlocksConfinedWorker: it confines itself as a worker does
// (confineFromEnv, after Confine started it in a PID namespace of its own)
// and dials each address, printing "<addr> ok" or "<addr> <error>".
func TestConfinedConnectChild(t *testing.T) {
	targets := os.Getenv(fenceChildEnv)
	if targets == "" {
		t.Skip("child half of TestWorkerFenceBlocksConfinedWorker")
	}
	if err := confineFromEnv(); err != nil {
		fmt.Println("confine:", err)
		os.Exit(4)
	}
	for _, addr := range strings.Split(targets, ",") {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			fmt.Println(addr, err)
			continue
		}
		_ = c.Close()
		fmt.Println(addr, "ok")
	}
	os.Exit(0)
}

// TestWorkerFenceBlocksConfinedWorker installs the WASM worker fence
// (internal/network/workerfence) for the worker uid and checks it in the
// kernel: a confined worker cannot connect to a service on 127.0.0.1, nor
// to one on the metadata address, that root connects to, and still reaches
// a listener on the guest listen address, where its own guests listen. The
// fence drops the worker's SYN, so its connect times out (TCP retransmits a
// dropped SYN rather than failing it); root's, to the same listener, gets
// through at once.
func TestWorkerFenceBlocksConfinedWorker(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the worker drops from root to nobody, and the fence is an nftables table")
	}
	if !canMakePIDNamespace() {
		t.Skip("needs a host (or privileged container) that allows new PID namespaces, as sandboxd's does")
	}
	be := workerfence.NewBackend()
	rules, err := workerfence.Plan(workerfence.Spec{UID: e2eWorkerUID, Allow: []workerfence.Allow{{
		Proto: "tcp", Prefix: netip.MustParsePrefix(workerfence.GuestListenHost + "/32"), PortLo: 1024, PortHi: 65535, Why: "guest listeners",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Apply(rules); err != nil {
		t.Fatalf("install the fence (needs nf_tables and CAP_NET_ADMIN, as sandboxd has): %v", err)
	}
	t.Cleanup(func() { _ = be.Remove() })
	if in, err := be.Check(rules); err != nil || !in {
		t.Fatalf("fence not in the kernel after Apply: %v %v", in, err)
	}
	if err := be.Apply(rules); err != nil { // idempotent: a second install replaces the first
		t.Fatal(err)
	}

	serve := func(addr string) net.Listener {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		return ln
	}
	// The metadata address, made local so something answers on it.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	imds := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("169.254.169.254"), Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrAdd(lo, imds); err != nil {
		t.Fatalf("put 169.254.169.254 on lo: %v", err)
	}
	t.Cleanup(func() { _ = netlink.AddrDel(lo, imds) })
	admin := serve("127.0.0.1:0").Addr().String() // a loopback-only service, as Caddy's admin API is
	metadata := serve("169.254.169.254:0").Addr().String()
	guest := serve(workerfence.GuestListenHost + ":0").Addr().String()

	for _, addr := range []string{admin, metadata, guest} {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("root cannot reach %s: %v", addr, err)
		}
		_ = c.Close()
	}

	spawn := Confine(func(context.Context, string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConfinedConnectChild$")
		cmd.Env = append(os.Environ(), fenceChildEnv+"="+strings.Join([]string{admin, guest, metadata}, ","))
		cmd.Stderr = os.Stderr
		return cmd, nil
	}, Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID})
	cmd, err := spawn(context.Background(), filepath.Join(t.TempDir(), "w.sock"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("confined child: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		addr, result, _ := strings.Cut(line, " ")
		got[addr] = result
	}
	for addr, want := range map[string]string{admin: "i/o timeout", metadata: "i/o timeout", guest: "ok"} {
		if !strings.Contains(got[addr], want) {
			t.Errorf("confined worker dial %s = %q, want %q (all: %s)", addr, got[addr], want, out)
		}
	}
	// And with the fence gone, the same worker reaches the loopback
	// service: the fence, not the drop, is what kept it out.
	if err := be.Remove(); err != nil {
		t.Fatal(err)
	}
	cmd, err = spawn(context.Background(), filepath.Join(t.TempDir(), "w.sock"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(cmd.Env, fenceChildEnv+"="+admin)
	if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), admin+" ok") {
		t.Fatalf("without the fence the confined worker dial = %q, %v", out, err)
	}
}

// TestConfinedWorkerEndToEnd starts a worker the way sandboxd does when it
// runs as root with the drop on, and checks the whole contract: the worker
// is uid nobody with no groups, no_new_privs, a seccomp filter and a PID
// namespace of its own; its socket is root's; it loads a module and runs a
// guest whose /work, module and checkpoint folder all sit under a folder
// only root may enter, reaching them through the descriptors passed with
// each message; and it cannot open those paths by name.
func TestConfinedWorkerEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the worker drops from root to nobody")
	}
	if !canMakePIDNamespace() {
		t.Skip("needs a host (or privileged container) that allows new PID namespaces, as sandboxd's does")
	}
	guest := wasmtestguest.Path(t, wasmtestguest.Stdio)

	// Everything the worker uses lives under private/, which only root may
	// enter, like /var/lib/sandboxd and /run/sandboxd.
	private := filepath.Join(t.TempDir(), "private")
	modules, work, stage, sockets := filepath.Join(private, "modules"), filepath.Join(private, "run", "sb-e2e"),
		filepath.Join(private, "modules", "sb-e2e", ".mem.snap-stage"), filepath.Join(private, "sockets")
	for _, d := range []string{modules, work, stage, sockets} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	module := filepath.Join(modules, "stdio.wasm")
	raw, err := os.ReadFile(guest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// What the driver hands the worker uid: /work and the staging folder.
	for _, d := range []string{work, stage} {
		if err := os.Chown(d, e2eWorkerUID, e2eWorkerUID); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(sockets, "w.sock")
	// Passed paths are opened from private/ one name at a time (R2), as
	// the daemon wires it.
	withGrantPolicy(t, GrantPolicy{Roots: []string{private}, Worker: Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID}})
	// The shared compile cache: the trusted step compiles the module,
	// sandboxd seals it (root's, 0444) and links it into the owner's
	// cache, which is the worker's.
	ownerCache := sharedCacheFor(t, private, module)

	sup, client := startConfinedWorker(t, sock, false, ownerCache)

	sup.mu.Lock()
	pid := sup.slots["sb-e2e"].cmd.Process.Pid
	sup.mu.Unlock()
	status := procStatus(t, pid)
	for key, want := range map[string]string{
		"Uid":        fmt.Sprintf("%d\t%d\t%d\t%d", e2eWorkerUID, e2eWorkerUID, e2eWorkerUID, e2eWorkerUID),
		"Gid":        fmt.Sprintf("%d\t%d\t%d\t%d", e2eWorkerUID, e2eWorkerUID, e2eWorkerUID, e2eWorkerUID),
		"Groups":     "",
		"NoNewPrivs": "1",
		"Seccomp":    "2",
	} {
		if status[key] != want {
			t.Fatalf("worker %s = %q, want %q", key, status[key], want)
		}
	}
	if ns := strings.Fields(status["NSpid"]); len(ns) != 2 || ns[1] != "1" {
		t.Fatalf("worker NSpid = %q: want its own PID namespace, where it is 1", status["NSpid"])
	}
	if st, err := os.Stat(sock); err != nil || st.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("socket = %v, %v: want root's (bound before the drop)", st, err)
	}

	// Through the read-only shared entry: a cache hit, nothing written.
	before := cacheFiles(t, ownerCache)
	// By name, the worker cannot even reach the module.
	if err := rawLoad(sock, module); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("load by name = %v, want permission denied", err)
	}
	// Through the descriptor sandboxd passes, it can.
	if _, err := client.LoadModule("sb-e2e", module, 64); err != nil {
		t.Fatalf("load through the grant: %v", err)
	}
	if after := cacheFiles(t, ownerCache); len(after) != len(before) {
		t.Fatalf("owner cache %v -> %v: the shared entry was not used", before, after)
	}
	caps := wasmengine.Capabilities{
		Preopens:       []wasmengine.Preopen{{GuestPath: "/work", HostPath: work}},
		MemoryMB:       64,
		WASIListenPort: wasmengine.WASIListenPortDisabled,
	}
	run := func(args ...string) wasmengine.RunResult {
		t.Helper()
		c := caps
		c.Args = append([]string{"aerolstdio"}, args...)
		res, err := client.Exec("sb-e2e", c, "_start")
		if err != nil {
			t.Fatalf("exec %v: %v", args, err)
		}
		return res
	}
	if res := run("write-work", "hello.txt", "hi there"); res.ExitCode != 0 {
		t.Fatalf("write-work = %+v", res)
	}
	written := filepath.Join(work, "hello.txt")
	st, err := os.Stat(written)
	if err != nil || st.Sys().(*syscall.Stat_t).Uid != e2eWorkerUID {
		t.Fatalf("guest file = %v, %v: want the worker's", st, err)
	}
	if res := run("read-file", "/work/hello.txt"); res.ExitCode != 0 || res.Stdout != "hi there" {
		t.Fatalf("read-file = %+v", res)
	}

	// A checkpoint lands in the staging folder, the worker's to write.
	if err := client.Instantiate("sb-e2e", caps); err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	staged := filepath.Join(stage, "mem.snap")
	if err := client.Checkpoint(context.Background(), "sb-e2e", staged, wasmengine.SnapshotConfig{SchemaVersion: 1}); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	files := wasmengine.SnapshotFiles(staged)
	if st, err := os.Stat(files[0]); err != nil || st.Sys().(*syscall.Stat_t).Uid != e2eWorkerUID {
		t.Fatalf("staged snapshot = %v, %v", st, err)
	}
	// Published as root's (what promoteCheckpoint does), then restored
	// through the files' descriptors.
	final := filepath.Join(private, "modules", "sb-e2e", "mem.snap")
	for _, f := range append([]string{staged}, files...) {
		if err := os.Lchown(f, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(staged, final); err != nil {
		t.Fatal(err)
	}
	if err := client.Restore("sb-e2e", final, caps); err != nil {
		t.Fatalf("restore through the grants: %v", err)
	}
	if err := client.Ping("sb-e2e"); err != nil {
		t.Fatalf("worker gone after the run: %v", err)
	}

	// The guest's mediated egress: socket, connect and the poller all pass
	// the filter.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		if c, err := backend.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	if res := run("dial", backend.Addr().String()); res.ExitCode != 0 || strings.HasPrefix(res.Stdout, "dial=-") {
		t.Fatalf("guest dial = %+v", res)
	}

	// A streaming run: its own connection, stdin and output frames.
	streamEcho(t, client, "sb-e2e", caps)

	// A resident host drops the same way and keeps a sandbox's grants
	// until that sandbox stops.
	rsock := filepath.Join(sockets, "r.sock")
	rsup, rclient := startConfinedWorker(t, rsock, true, ownerCache)
	rsup.mu.Lock()
	rpid := rsup.slots["sb-e2e"].cmd.Process.Pid
	rsup.mu.Unlock()
	if st := procStatus(t, rpid); st["Seccomp"] != "2" || !strings.HasPrefix(st["Uid"], strconv.Itoa(e2eWorkerUID)) {
		t.Fatalf("resident host status = %v", st)
	}
	if _, err := rclient.LoadModule("host", module, 64); err != nil {
		t.Fatalf("resident load: %v", err)
	}
	if err := rclient.Instantiate("sb-r", caps); err != nil {
		t.Fatalf("resident instantiate: %v", err)
	}
	streamEcho(t, rclient, "sb-r", caps)
	if err := rclient.StopInstance("sb-r"); err != nil {
		t.Fatalf("resident stop: %v", err)
	}
}

// startConfinedWorker starts the test binary as a worker (or a resident
// host), confined as sandboxd confines one, and waits for it.
func startConfinedWorker(t *testing.T, sock string, resident bool, cache string) (*Supervisor, *Client) {
	t.Helper()
	spawn := Confine(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConfinedWorkerChild$")
		cmd.Env = append(workerEnvironment(ctx), confinedChildEnv+"="+socketPath)
		if resident {
			cmd.Env = append(cmd.Env, confinedChildEnv+"_RESIDENT=1")
		}
		cmd.Stderr = os.Stderr
		return cmd, nil
	}, Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID})
	sup := NewSupervisor(spawn)
	if err := sup.Ensure(WithCompileCache(context.Background(), cache), "sb-e2e", sock); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Stop("sb-e2e") })
	client := NewClient(sock)
	deadline := time.Now().Add(20 * time.Second)
	for client.Ping("sb-e2e") != nil {
		if time.Now().After(deadline) {
			t.Fatal("confined worker never answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return sup, client
}

// streamEcho runs the guest's echo over a stream and checks what comes back.
func streamEcho(t *testing.T, client *Client, sandboxID string, caps wasmengine.Capabilities) {
	t.Helper()
	c := caps
	c.Args = []string{"aerolstdio", "echo"}
	st, err := client.StartExec(context.Background(), sandboxID, ExecStartPayload{Caps: c, Stdin: true})
	if err != nil {
		t.Fatalf("%s: start stream: %v", sandboxID, err)
	}
	defer st.Close()
	if err := st.WriteStdin([]byte("ping over stdin")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseStdin(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for {
		ev, err := st.Recv()
		if err != nil {
			t.Fatalf("%s: stream: %v (stdout %q)", sandboxID, err, out.String())
		}
		if ev.Exit != nil {
			if ev.Exit.ExitCode != 0 || out.String() != "ping over stdin" {
				t.Fatalf("%s: stream exit %+v stdout %q", sandboxID, ev.Exit, out.String())
			}
			return
		}
		out.Write(ev.Data)
	}
}

// rawLoad sends a LoadModule with no descriptor attached, as a sandboxd from
// before grants would.
func rawLoad(sock, module string) error {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	body, err := encodePayload(loadModulePayload{Path: module, MemoryMB: 64})
	if err != nil {
		return err
	}
	if err := writeFrame(conn, Envelope{Type: MsgLoadModule, SandboxID: "sb-e2e", Payload: body}); err != nil {
		return err
	}
	reply, err := readFrame(conn)
	if err != nil {
		return err
	}
	return (&Client{}).expectOK(reply)
}

func procStatus(t *testing.T, pid int) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// canMakePIDNamespace reports whether this process may start a child in a
// new PID namespace (a default container's seccomp profile refuses it).
func canMakePIDNamespace() bool {
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	return cmd.Run() == nil
}

// sharedCacheFor builds what the driver does for an operator module: the
// shared cache with the module compiled into it by root, sealed (folders
// 0700, entries 0444), and an owner cache owned by the worker uid with a
// hard link to each entry. It returns the owner cache.
func sharedCacheFor(t *testing.T, private, module string) string {
	t.Helper()
	shared := filepath.Join(private, "cache", "shared")
	owner := filepath.Join(private, "cache", "owners", "owner-e2e")
	for _, d := range []string{shared, owner} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := wasmengine.PrecompileModule(context.Background(), shared, module); err != nil {
		t.Fatal(err)
	}
	versions, err := os.ReadDir(shared)
	if err != nil || len(versions) != 1 {
		t.Fatalf("shared cache = %v, %v", versions, err)
	}
	vdir := versions[0].Name()
	if err := os.Mkdir(filepath.Join(owner, vdir), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(shared, vdir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		src := filepath.Join(shared, vdir, e.Name())
		if err := os.Chmod(src, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(src, filepath.Join(owner, vdir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{owner, filepath.Join(owner, vdir)} {
		if err := os.Chown(d, e2eWorkerUID, e2eWorkerUID); err != nil {
			t.Fatal(err)
		}
	}
	return owner
}

// cacheFiles lists the entries of every version folder in a cache.
func cacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}
