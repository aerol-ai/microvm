package rootd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// wasmLoans records GrantWasmMounts' opens and loans, and answers each loan
// with err.
type wasmLoans struct {
	mu     sync.Mutex
	opened []string
	loans  []string
	files  int
	err    error
	dir    string
	// block makes each loan wait out its deadline. Set before any call.
	block bool
}

func (l *wasmLoans) open(root, id string, index int) (*os.File, error) {
	l.mu.Lock()
	l.opened = append(l.opened, fmt.Sprintf("%s/%s/%d", root, id, index))
	l.mu.Unlock()
	return os.Open(l.dir)
}

func (l *wasmLoans) lend(ctx context.Context, socket, id string, paths []string, files []*os.File) error {
	l.mu.Lock()
	block := l.block
	l.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loans = append(l.loans, socket+" "+id+" "+strings.Join(paths, ","))
	l.files += len(files)
	return l.err
}

func (l *wasmLoans) snapshot() ([]string, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.opened), slices.Clone(l.loans)
}

const (
	wasmWorker   = rootdpb.HostKind_HOST_KIND_WASM_WORKER
	wasmResident = rootdpb.HostKind_HOST_KIND_WASM_RESIDENT
)

// wasmMountsRig is a helper that serves external mounts and WASM hosts,
// with its kernel, its mount tools and the hosts in memory: sb-1's worker
// and a resident host run, sb-1 has two mount points.
func wasmMountsRig(t *testing.T) (*rig, *wasmLoans, *fakeMounts, string) {
	t.Helper()
	dir := shortDir(t)
	root := filepath.Join(dir, "mounts")
	kernel := newFakeHostKernel()
	for i, g := range []string{"aerolvm-wasm/w-sb-1", "aerolvm-wasm/r-o0123456789abcdef-b", "aerolvm-wasm/w-sb-2"} {
		kernel.groups[g] = []int{100 + i}
		kernel.ticks[100+i] = uint64(1 + i)
	}
	fm := &fakeMounts{binds: []mounts.ContainerBind{{HostPath: root + "/sb-1/0", ContainerPath: "/data"}, {HostPath: root + "/sb-1/1", ContainerPath: "/logs", ReadOnly: true}}}
	loans := &wasmLoans{dir: dir}
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(dir, "hosts.log"), Wasm: testWasmHostsConfig(t, dir)}
		c.Policy.MountsRoot = root
		c.Policy.BindRoots = append(c.Policy.BindRoots, root)
		o.HostKernel, o.WorkerFence, o.Mounts = kernel, &memWorkerFence{}, fm
		o.wasmOpenPoint, o.wasmLend = loans.open, loans.lend
	})
	return r, loans, fm, root
}

func grantMounts(r *rig, id string, kind rootdpb.HostKind, host string) (*rootdpb.GrantWasmMountsResponse, error) {
	return rootdpb.NewRootHelperClient(r.conn).GrantWasmMounts(callCtx(r.t),
		&rootdpb.GrantWasmMountsRequest{SandboxId: id, Kind: kind, HostId: host})
}

// TestGrantWasmMounts: the helper lends a sandbox's own mount points, by
// the paths its Manager holds, to the host the agent names, on the socket
// the helper serves that host on.
func TestGrantWasmMounts(t *testing.T) {
	r, loans, _, root := wasmMountsRig(t)
	resp, err := grantMounts(r, "sb-1", wasmWorker, "sb-1")
	if err != nil || resp.GetGranted() != 2 {
		t.Fatalf("grant = %v, %v", resp, err)
	}
	sockets := r.cfg.Hosts.Wasm.SocketDir
	opened, lent := loans.snapshot()
	if !slices.Equal(opened, []string{root + "/sb-1/0", root + "/sb-1/1"}) ||
		!slices.Equal(lent, []string{sockets + "/w-sb-1.sock sb-1 " + root + "/sb-1/0," + root + "/sb-1/1"}) || loans.files != 2 {
		t.Fatalf("opened %v lent %v (%d files)", opened, lent, loans.files)
	}
	// A resident host, by its own socket.
	if resp, err := grantMounts(r, "sb-1", wasmResident, "o0123456789abcdef-b"); err != nil || resp.GetGranted() != 2 {
		t.Fatalf("resident: %v, %v", resp, err)
	}
	if _, lent := loans.snapshot(); !strings.HasPrefix(lent[1], sockets+"/r-o0123456789abcdef-b.sock sb-1 ") {
		t.Fatalf("resident loan %v", lent)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}

// TestGrantWasmMountsBrokenAgent: each request a broken agent could send is
// refused before anything is opened or lent, and the refusals that only a
// broken agent sends are reported; what a working agent meets in a race (a
// host gone, a host without the sandbox yet) is answered, not reported.
func TestGrantWasmMountsBrokenAgent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		id        string
		kind      rootdpb.HostKind
		host      string
		lendErr   error
		code      codes.Code
		reason    string
		lendsOnce bool
	}{
		{"a sandbox id with ../", "../sb-1", wasmWorker, "sb-1", nil, codes.InvalidArgument, string(rootpolicy.RuleExternalMount), false},
		{"no sandbox id", "", wasmWorker, "sb-1", nil, codes.InvalidArgument, string(rootpolicy.RuleExternalMount), false},
		{"a host that is no WASM host", "sb-1", rootdpb.HostKind_HOST_KIND_WORKERD, "g", nil, codes.InvalidArgument, ReasonHostKind, false},
		{"no host kind", "sb-1", rootdpb.HostKind_HOST_KIND_UNSPECIFIED, "sb-1", nil, codes.InvalidArgument, ReasonHostKind, false},
		{"a kind no build knows", "sb-1", 99, "sb-1", nil, codes.InvalidArgument, ReasonHostKind, false},
		{"a host id with ../", "sb-1", wasmWorker, "../sb-1", nil, codes.InvalidArgument, string(rootpolicy.RuleHost), false},
		{"the machinery's group", "sb-1", wasmWorker, "aerolvm-mounts", nil, codes.InvalidArgument, string(rootpolicy.RuleHost), false},
		{"a host that does not run", "sb-1", wasmWorker, "sb-9", nil, codes.NotFound, "", false},
		{"another tenant's worker", "sb-1", wasmWorker, "sb-2", worker.ErrLendForeign, codes.PermissionDenied, ReasonWasmMountHost, true},
		{"a host without the sandbox yet", "sb-1", wasmResident, "o0123456789abcdef-b", worker.ErrLendNotHeld, codes.FailedPrecondition, "", true},
		{"a host that does not answer", "sb-1", wasmWorker, "sb-1", errors.New("connection refused"), codes.Unavailable, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, loans, _, _ := wasmMountsRig(t)
			loans.err = tc.lendErr
			_, err := grantMounts(r, tc.id, tc.kind, tc.host)
			if status.Code(err) != tc.code {
				t.Fatalf("grant = %v, want %v", err, tc.code)
			}
			reason, refused := rootdpb.RefusalReason(err)
			if refused != (tc.reason != "") || reason != tc.reason {
				t.Fatalf("refusal %q %v, want %q", reason, refused, tc.reason)
			}
			if refs := r.refused(); (len(refs) > 0) != (tc.reason != "") {
				t.Fatalf("reported %v", refs)
			}
			if _, lent := loans.snapshot(); (len(lent) == 1) != tc.lendsOnce {
				t.Fatalf("lent %v", lent)
			}
			if !tc.lendsOnce && loans.files != 0 {
				t.Fatal("folders were opened for a refused request")
			}
		})
	}
}

// TestGrantWasmMountsOnlyItsOwnMountPoints: a mount point the Manager holds
// outside the sandbox's own folder (never so, unless the helper itself is
// wrong) is never opened, and none of the sandbox's is lent.
func TestGrantWasmMountsOnlyItsOwnMountPoints(t *testing.T) {
	for name, bad := range map[string]string{
		"another sandbox's":     "/sb-2/0",
		"outside the folder":    "/../etc/0",
		"no index":              "/sb-1/x",
		"an index past the cap": "/sb-1/99",
	} {
		t.Run(name, func(t *testing.T) {
			r, loans, fm, root := wasmMountsRig(t)
			fm.binds = append(fm.binds, mounts.ContainerBind{HostPath: root + bad, ContainerPath: "/x"})
			if _, err := grantMounts(r, "sb-1", wasmWorker, "sb-1"); status.Code(err) != codes.Internal {
				t.Fatalf("grant = %v", err)
			}
			opened, lent := loans.snapshot()
			if len(lent) != 0 || slices.ContainsFunc(opened, func(p string) bool { return !strings.HasPrefix(p, root+"/sb-1/") }) {
				t.Fatalf("opened %v lent %v", opened, lent)
			}
		})
	}
	// A sandbox with no mounts here: nothing to lend, no error.
	r, loans, fm, _ := wasmMountsRig(t)
	fm.binds = []mounts.ContainerBind{}
	fm.specs = nil
	if resp, err := grantMounts(r, "sb-3", wasmWorker, "sb-1"); err != nil || resp.GetGranted() != 0 {
		t.Fatalf("no mounts: %v %v", resp, err)
	}
	if _, lent := loans.snapshot(); len(lent) != 0 {
		t.Fatalf("lent %v", lent)
	}
}

// TestGrantWasmMountsWrongCaller: a caller the peer check refuses reaches
// no loan.
func TestGrantWasmMountsWrongCaller(t *testing.T) {
	dir := shortDir(t)
	loans := &wasmLoans{dir: dir}
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(dir, "hosts.log"), Wasm: testWasmHostsConfig(t, dir)}
		c.Policy.MountsRoot = filepath.Join(dir, "mounts")
		c.Policy.BindRoots = append(c.Policy.BindRoots, c.Policy.MountsRoot)
		o.HostKernel, o.WorkerFence, o.Mounts = newFakeHostKernel(), &memWorkerFence{}, &fakeMounts{}
		o.wasmOpenPoint, o.wasmLend = loans.open, loans.lend
		o.Peer = func(net.Conn) error { return errors.New("egress: peer uid 4242 not allowed") }
	})
	if _, err := grantMounts(r, "sb-1", wasmWorker, "sb-1"); status.Code(err) != codes.Unavailable {
		t.Fatalf("grant = %v", err)
	}
	if opened, lent := loans.snapshot(); len(opened)+len(lent) != 0 {
		t.Fatalf("opened %v lent %v", opened, lent)
	}
	if refs := r.refused(); len(refs) == 0 || refs[0].Reason != ReasonPeer {
		t.Fatalf("refusals %v", refs)
	}
}

// TestGrantWasmMountsServed: a helper lists GrantWasmMounts only with both
// a mount manager and WASM hosts; without them the call is Unimplemented.
func TestGrantWasmMountsServed(t *testing.T) {
	r, _, _, _ := wasmMountsRig(t)
	resp, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
	if err != nil || !slices.Contains(resp.GetFeatures(), rootdpb.FeatureGrantWasmMounts) {
		t.Fatalf("features %v (%v)", resp.GetFeatures(), err)
	}
	for name, mutate := range map[string]func(*Config, *Options){
		"no mounts": func(c *Config, o *Options) {
			c.Hosts = HostsConfig{LogPath: "/x", Wasm: testWasmHostsConfig(t, shortDir(t))}
			o.WorkerFence = &memWorkerFence{}
		},
		"no WASM hosts": func(c *Config, o *Options) { o.Mounts = &fakeMounts{}; c.Hosts = testHostsConfig(t) },
		"no mounts folder": func(c *Config, o *Options) {
			c.Hosts = HostsConfig{LogPath: "/x", Wasm: testWasmHostsConfig(t, shortDir(t))}
			o.WorkerFence, o.Mounts = &memWorkerFence{}, &fakeMounts{}
		},
	} {
		r := newRig(t, mutate)
		resp, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
		if err != nil || slices.Contains(resp.GetFeatures(), rootdpb.FeatureGrantWasmMounts) {
			t.Fatalf("%s: features %v (%v)", name, resp.GetFeatures(), err)
		}
		if _, err := grantMounts(r, "sb-1", wasmWorker, "sb-1"); status.Code(err) != codes.Unimplemented {
			t.Fatalf("%s: grant = %v", name, err)
		}
	}
}

// TestGrantWasmMountsDeadline: a host that does not answer in time is the
// host's failure, answered DeadlineExceeded.
func TestGrantWasmMountsDeadline(t *testing.T) {
	r, loans, _, _ := wasmMountsRig(t)
	loans.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := rootdpb.NewRootHelperClient(r.conn).GrantWasmMounts(ctx, &rootdpb.GrantWasmMountsRequest{SandboxId: "sb-1", Kind: wasmWorker, HostId: "sb-1"})
	if c := status.Code(err); c != codes.DeadlineExceeded {
		t.Fatalf("grant = %v", err)
	}
	if len(r.refused()) != 0 {
		t.Fatal("a slow host was reported as a broken agent")
	}
}

// TestLendToHost: the helper's loan talks to the host on its socket, and
// a socket with nothing behind it fails the loan.
func TestLendToHost(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "w-sb-1.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &worker.Server{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.Serve(c) }()
		}
	}()
	folder, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The worker holds no sandbox yet: nothing is lent.
	if err := lendToHost(ctx, sock, "sb-1", []string{"/m/sb-1/0"}, []*os.File{folder}); !errors.Is(err, worker.ErrLendNotHeld) {
		t.Fatalf("lend = %v", err)
	}
	if err := lendToHost(ctx, filepath.Join(dir, "none.sock"), "sb-1", []string{"/m/sb-1/0"}, []*os.File{folder}); err == nil {
		t.Fatal("lent to no one")
	}
}
