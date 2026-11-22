package rootd

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// testNonce is short: macOS's temporary folders leave little of a socket
// path's 104 bytes.
const testNonce = "ab12"

// filesReq is the files part a create sends for id: what the containerd
// driver asks for (split_files.go).
func filesReq(id string) *rootdpb.PrepareSandboxRequest {
	return &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: id, Setup: &rootdpb.ContainerSetup{
		Naming: &rootdpb.HostNaming{Hostname: id, Hosts: localhostEntries(), Nameservers: []string{"10.0.0.2"},
			Search: []string{"svc.cluster.local"}, DnsOptions: []string{"ndots:5"}},
		TaskFifos: true, ReadyNonce: testNonce, RunscConfig: rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT, Toolbox: true,
	}}
}

// TestFilesPartMakesWhatItAsks (M1 PR 7): one files part makes what the
// four T2b calls make, the same files at the same paths, and answers with
// them; a repeat answers the same; the release removes them all.
func TestFilesPartMakesWhatItAsks(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	agent := agentSocket(t, r.cfg, testCID, testNonce)
	resp, err := c.PrepareSandbox(callCtx(t), filesReq(testCID))
	if err != nil {
		t.Fatal(err)
	}
	f := resp.GetFiles()
	hosts := filepath.Join(r.cfg.Files.Hosts, testCID)
	want := &rootdpb.SandboxFilePaths{
		HostnamePath: filepath.Join(hosts, hostnameFile), HostsPath: filepath.Join(hosts, hostsFile), ResolvConfPath: filepath.Join(hosts, resolvConfFile),
		StdoutPath: filepath.Join(r.cfg.Policy.FIFODir, testCID, stdoutFIFO), StderrPath: filepath.Join(r.cfg.Policy.FIFODir, testCID, stderrFIFO),
		ReadySocketPath: filepath.Join(r.cfg.Files.Ready, testCID, testNonce+".sock"), RunscConfigPath: r.cfg.Files.runscPath(runscDefaultFile),
		ToolboxPath: r.cfg.Files.Toolbox,
	}
	if !proto.Equal(f, want) {
		t.Fatalf("paths %v, want %v", f, want)
	}
	wantFile(t, f.GetHostnamePath(), 0o644, testCID+"\n")
	wantFile(t, f.GetHostsPath(), 0o644, "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n")
	wantFile(t, f.GetResolvConfPath(), 0o644, "search svc.cluster.local\noptions ndots:5\nnameserver 10.0.0.2\n")
	for _, p := range []string{f.GetStdoutPath(), f.GetStderrPath()} {
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&fs.ModeNamedPipe == 0 || fi.Mode().Perm() != 0o640 {
			t.Fatalf("%s: %v (%v), want a FIFO, 0640", p, fi, err)
		}
	}
	if a, b := statOf(t, agent), statOf(t, f.GetReadySocketPath()); a.Ino != b.Ino {
		t.Fatal("the ready socket's name is not the agent's socket")
	}
	if !strings.Contains(readFile(t, f.GetRunscConfigPath()), "host-uds") {
		t.Fatal("the runsc config lacks its flags")
	}
	stdout := statOf(t, f.GetStdoutPath()).Ino
	// A repeat (a retried create, or a start): the same paths, fresh FIFOs.
	again, err := c.PrepareSandbox(callCtx(t), filesReq(testCID))
	if err != nil || !proto.Equal(again.GetFiles(), want) {
		t.Fatalf("repeat: %v, %v", again, err)
	}
	if statOf(t, f.GetStdoutPath()).Ino == stdout {
		t.Fatal("a repeat kept the last task's FIFOs")
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
	// The release takes everything, and a repeat is done already.
	for range 2 {
		if _, err := c.ReleaseSandbox(callCtx(t), &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: testCID}); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{hosts, filepath.Join(r.cfg.Policy.FIFODir, testCID), filepath.Join(r.cfg.Files.Ready, testCID)} {
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s left after the release: %v", dir, err)
		}
	}
	if _, err := os.Lstat(agent); err != nil {
		t.Fatalf("the release took the agent's own socket: %v", err)
	}
}

// TestFilesPartAsksForLess: each piece comes only when asked, and the
// paths of what was not asked for are empty.
func TestFilesPartAsksForLess(t *testing.T) {
	r := newRig(t, nil)
	resp, err := helperClient(r).PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles},
		ContainerId: testCID, Setup: &rootdpb.ContainerSetup{TaskFifos: true}})
	if err != nil {
		t.Fatal(err)
	}
	if f := resp.GetFiles(); f.GetStdoutPath() == "" || f.GetHostsPath() != "" || f.GetReadySocketPath() != "" || f.GetRunscConfigPath() != "" || f.GetToolboxPath() != "" {
		t.Fatalf("paths %v", f)
	}
	if _, err := os.Lstat(filepath.Join(r.cfg.Files.Hosts, testCID)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("host files made unasked: %v", err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withUnknownField appends a field this helper does not know to m, as a
// newer agent's request would carry it.
func withUnknownField[M proto.Message](m M) M {
	raw := m.ProtoReflect().GetUnknown()
	raw = protowire.AppendTag(raw, 99, protowire.VarintType)
	m.ProtoReflect().SetUnknown(protowire.AppendVarint(raw, 1))
	return m
}

// TestFilesPartBrokenAgent: every hostile files part a broken agent can
// send is refused before anything is made, recorded as a refusal (eng
// review D9), and leaves the helper's folders and everything beside them
// as they were. A newer agent's part or field is version skew instead:
// Unimplemented, not counted as a refusal.
func TestFilesPartBrokenAgent(t *testing.T) {
	mut := func(f func(*rootdpb.PrepareSandboxRequest)) *rootdpb.PrepareSandboxRequest {
		req := filesReq(testCID)
		f(req)
		return req
	}
	for _, tc := range []struct {
		name   string
		req    *rootdpb.PrepareSandboxRequest
		code   codes.Code
		reason string // "" for skew: no refusal
	}{
		{"an ID that climbs out", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerId = "../../etc" }), codes.InvalidArgument, ReasonBadRequest},
		{"an ID of dots", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerId = ".." }), codes.InvalidArgument, ReasonBadRequest},
		{"an ID that is a path", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerId = "/run/aerolvm-rootd/sock" }), codes.InvalidArgument, ReasonBadRequest},
		{"an ID with a slash", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerId = "sb-1/../sb-2" }), codes.InvalidArgument, ReasonBadRequest},
		{"no ID", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerId = "" }), codes.InvalidArgument, ReasonBadRequest},
		{"a machinery group's name", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerId = "_runtime" }), codes.InvalidArgument, ReasonBadRequest},
		{"a hostname with a newline", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup.Naming.Hostname = "a\nnameserver 6.6.6.6" }), codes.InvalidArgument, ReasonBadRequest},
		{"a hosts address that is a name", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup.Naming.Hosts[0].Address = "evil" }), codes.InvalidArgument, ReasonBadRequest},
		{"a ready nonce that climbs out", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup.ReadyNonce = "../../sock/root" }), codes.InvalidArgument, ReasonBadRequest},
		{"a ready nonce in capitals", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup.ReadyNonce = "ABCD" }), codes.InvalidArgument, ReasonBadRequest},
		{"a runsc config the helper does not write", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup.RunscConfig = 99 }), codes.InvalidArgument, ReasonBadRequest},
		{"no setup", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup = nil }), codes.InvalidArgument, ReasonBadRequest},
		{"a setup that asks for nothing", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup = &rootdpb.ContainerSetup{} }), codes.InvalidArgument, ReasonBadRequest},
		{"with a namespace", mut(func(r *rootdpb.PrepareSandboxRequest) { r.NetnsName = "sb-1" }), codes.InvalidArgument, ReasonBadRequest},
		{"with an address", mut(func(r *rootdpb.PrepareSandboxRequest) { r.ContainerIp = "10.88.0.2" }), codes.InvalidArgument, ReasonBadRequest},
		{"with rules", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Firewall = &rootdpb.SandboxFirewall{} }), codes.InvalidArgument, ReasonBadRequest},
		{"with a cgroup", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Cgroup = &rootdpb.SandboxCgroup{ContainerId: testCID} }), codes.InvalidArgument, ReasonBadRequest},
		{"listed twice", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Parts = []string{rootdpb.PartFiles, rootdpb.PartFiles} }), codes.InvalidArgument, ReasonBadRequest},
		{"with the netns part", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Parts = []string{rootdpb.PartFiles, rootdpb.PartNetns} }), codes.Unimplemented, ""},
		{"a container named under the netns part", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Parts = []string{rootdpb.PartNetns} }), codes.InvalidArgument, ReasonBadRequest},
		{"a setup under no part", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Parts, r.ContainerId = nil, "" }), codes.InvalidArgument, ReasonBadRequest},
		{"a newer agent's part", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Parts = []string{rootdpb.PartFiles, "files-v2"} }), codes.Unimplemented, ""},
		{"a newer agent's field", withUnknownField(filesReq(testCID)), codes.Unimplemented, ""},
		{"a newer agent's field in the setup", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup = withUnknownField(r.Setup) }), codes.Unimplemented, ""},
		{"a newer agent's field in the naming", mut(func(r *rootdpb.PrepareSandboxRequest) { r.Setup.Naming = withUnknownField(r.Setup.Naming) }), codes.Unimplemented, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			agentSocket(t, r.cfg, testCID, testNonce)
			before := helperTree(t, r.cfg)
			_, err := helperClient(r).PrepareSandbox(callCtx(t), tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("err %v, want %v", err, tc.code)
			}
			ref := r.refused()
			if tc.reason == "" {
				if len(ref) != 0 {
					t.Fatalf("version skew counted as a refusal: %v", ref)
				}
			} else if len(ref) != 1 || ref[0].Reason != tc.reason {
				t.Fatalf("refusals %v, want one %s", ref, tc.reason)
			}
			if after := helperTree(t, r.cfg); !slices.Equal(before, after) {
				t.Fatalf("a refused call changed the helper's folders: %v -> %v", before, after)
			}
			for _, p := range []string{filepath.Join(r.cfg.Files.Hosts, "..", "..", "etc"), filepath.Join(filepath.Dir(r.cfg.Socket), "x")} {
				if _, err := os.Lstat(p); err == nil {
					t.Fatalf("%s was made", p)
				}
			}
		})
	}
}

// TestFilesPartAnotherSandbox: which sandbox a container ID means is the
// agent's bookkeeping (plan R9). A broken agent may name another sandbox's
// container; it gets that container's files, in that container's own
// folders, with the values it sends, and nothing outside them changes.
func TestFilesPartAnotherSandbox(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	agentSocket(t, r.cfg, testCID, testNonce)
	agentSocket(t, r.cfg, "sb-2", testNonce)
	if _, err := c.PrepareSandbox(callCtx(t), filesReq(testCID)); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(r.cfg.Files.Hosts, testCID, hostnameFile)
	before := readFile(t, other)
	resp, err := c.PrepareSandbox(callCtx(t), filesReq("sb-2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.GetFiles().GetHostnamePath(), filepath.Join(r.cfg.Files.Hosts, "sb-2")+"/") {
		t.Fatalf("sb-2's files at %v", resp.GetFiles())
	}
	if readFile(t, other) != before {
		t.Fatal("a call for sb-2 changed sb-1's files")
	}
	// Its release takes only its own.
	if _, err := c.ReleaseSandbox(callCtx(t), &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "sb-2"}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, other) != before {
		t.Fatal("sb-2's release took sb-1's files")
	}
}

// TestFilesReleaseRefuses: the files part of ReleaseSandbox comes alone,
// names a container, and never a path.
func TestFilesReleaseRefuses(t *testing.T) {
	rel := func(f func(*rootdpb.ReleaseSandboxRequest)) *rootdpb.ReleaseSandboxRequest {
		req := &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: testCID}
		f(req)
		return req
	}
	for _, tc := range []struct {
		name   string
		req    *rootdpb.ReleaseSandboxRequest
		code   codes.Code
		reason string
	}{
		{"an ID that climbs out", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.ContainerId = "../hosts" }), codes.InvalidArgument, ReasonBadRequest},
		{"no ID", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.ContainerId = "" }), codes.InvalidArgument, ReasonBadRequest},
		{"with a namespace", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.NetnsName = "sb-1" }), codes.InvalidArgument, ReasonBadRequest},
		{"with an address", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.ContainerIp = "10.88.0.2" }), codes.InvalidArgument, ReasonBadRequest},
		{"listed twice", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.Parts = []string{rootdpb.PartFiles, rootdpb.PartFiles} }), codes.InvalidArgument, ReasonBadRequest},
		{"a container under no part", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.Parts = nil }), codes.InvalidArgument, ReasonBadRequest},
		{"a newer agent's part", rel(func(r *rootdpb.ReleaseSandboxRequest) { r.Parts = []string{rootdpb.PartFiles, "files-v2"} }), codes.Unimplemented, ""},
		{"a newer agent's field", withUnknownField(rel(func(*rootdpb.ReleaseSandboxRequest) {})), codes.Unimplemented, ""},
		{"no network part on a helper without one", &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", Parts: []string{rootdpb.PartNetns}}, codes.Unimplemented, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			if _, err := helperClient(r).PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles},
				ContainerId: testCID, Setup: &rootdpb.ContainerSetup{TaskFifos: true}}); err != nil {
				t.Fatal(err)
			}
			before := helperTree(t, r.cfg)
			_, err := helperClient(r).ReleaseSandbox(callCtx(t), tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("err %v, want %v", err, tc.code)
			}
			if ref := r.refused(); (tc.reason == "") != (len(ref) == 0) || (tc.reason != "" && ref[0].Reason != tc.reason) {
				t.Fatalf("refusals %v, want %q", ref, tc.reason)
			}
			if after := helperTree(t, r.cfg); !slices.Equal(before, after) {
				t.Fatalf("a refused release changed the helper's folders: %v -> %v", before, after)
			}
		})
	}
}

// TestFilesPartFailures: a part whose agent socket is missing fails with
// NotFound, not a refusal; one whose socket is not the agent's is refused.
func TestFilesPartFailures(t *testing.T) {
	r := newRig(t, nil)
	_, err := helperClient(r).PrepareSandbox(callCtx(t), filesReq(testCID))
	if status.Code(err) != codes.FailedPrecondition || len(r.refused()) != 0 {
		t.Fatalf("no agent ready folder: %v (refusals %v)", err, r.refused())
	}
	if err := os.MkdirAll(r.cfg.Files.AgentReady, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = helperClient(r).PrepareSandbox(callCtx(t), filesReq(testCID))
	if status.Code(err) != codes.NotFound || len(r.refused()) != 0 {
		t.Fatalf("no agent socket: %v (refusals %v)", err, r.refused())
	}
	if err := os.WriteFile(filepath.Join(r.cfg.Files.AgentReady, testCID+"."+testNonce+".sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = helperClient(r).PrepareSandbox(callCtx(t), filesReq(testCID))
	if status.Code(err) != codes.PermissionDenied || len(r.refused()) != 1 || r.refused()[0].Reason != ReasonNotAgentSocket {
		t.Fatalf("a file for a socket: %v (refusals %v)", err, r.refused())
	}
}

// TestFilesPartsForOneContainerRunInOrder (D11): files parts for one
// container, and its release, never interleave; parts for different
// containers run side by side.
func TestFilesPartsForOneContainerRunInOrder(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 20 {
		id := []string{testCID, "sb-2"}[i%2]
		wg.Go(func() {
			_, err := c.PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: id,
				Setup: &rootdpb.ContainerSetup{TaskFifos: true, Naming: &rootdpb.HostNaming{Hostname: id}}})
			errs <- err
		})
		if i%5 == 0 {
			wg.Go(func() {
				_, err := c.ReleaseSandbox(callCtx(t), &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: id})
				errs <- err
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Whatever the order, each container's folders hold only whole files:
	// no temporary name is left behind.
	for _, p := range helperTree(t, r.cfg) {
		if strings.Contains(filepath.Base(p), ".tmp") {
			t.Fatalf("a temporary name left: %s", p)
		}
	}
}

// fakeLister is containerd's list of containers for the sweep.
type fakeLister struct {
	mu   sync.Mutex
	ids  map[string]bool
	err  error
	asks int
}

func (l *fakeLister) ContainerIDs(context.Context) (map[string]bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asks++
	return l.ids, l.err
}

func (l *fakeLister) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.asks
}

// TestSweepContainerFiles: the sweep removes the files of containers
// containerd no longer has, once their folders are older than the grace
// period, and leaves a live container's and a fresh one's.
func TestSweepContainerFiles(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	for _, id := range []string{"sb-gone", "sb-live", "sb-fresh"} {
		agentSocket(t, r.cfg, id, testNonce)
		req := filesReq(id)
		if _, err := c.PrepareSandbox(callCtx(t), req); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	for _, id := range []string{"sb-gone", "sb-live"} {
		for _, dir := range []string{r.cfg.Files.Hosts, r.cfg.Files.Ready, r.cfg.Policy.FIFODir} {
			// The change time cannot be set back; leave the mtime old and
			// compare with a grace in the future for those two.
			if err := os.Chtimes(filepath.Join(dir, id), old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	lister := &fakeLister{ids: map[string]bool{"sb-live": true}}
	// Grace 1h: every folder changed just now (its change time), so none goes.
	removed, err := r.srv.SweepContainerFiles(callCtx(t), lister, time.Hour)
	if err != nil || len(removed) != 0 {
		t.Fatalf("grace 1h: removed %v, %v", removed, err)
	}
	// Grace in the past of every change: the gone container's and the
	// fresh one's go, the live one's stays.
	removed, err = r.srv.SweepContainerFiles(callCtx(t), lister, -time.Minute)
	if err != nil || !slices.Equal(removed, []string{"sb-fresh", "sb-gone"}) {
		t.Fatalf("removed %v, %v", removed, err)
	}
	if _, err := os.Lstat(filepath.Join(r.cfg.Files.Hosts, "sb-live")); err != nil {
		t.Fatalf("the live container's files went: %v", err)
	}
	for _, dir := range []string{r.cfg.Files.Hosts, r.cfg.Files.Ready, r.cfg.Policy.FIFODir} {
		if _, err := os.Lstat(filepath.Join(dir, "sb-gone")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s/sb-gone left: %v", dir, err)
		}
	}
	// A list containerd cannot give stops the sweep, and nothing goes.
	lister.err = errors.New("containerd is down")
	if _, err := r.srv.SweepContainerFiles(callCtx(t), lister, -time.Minute); err == nil || !strings.Contains(err.Error(), "containerd is down") {
		t.Fatalf("a failed list: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(r.cfg.Files.Hosts, "sb-live")); err != nil {
		t.Fatalf("a failed list removed files: %v", err)
	}
	// Nothing to sweep: containerd is not asked.
	empty := newRig(t, nil)
	if removed, err := empty.srv.SweepContainerFiles(callCtx(t), &fakeLister{err: errors.New("unasked")}, 0); err != nil || removed != nil {
		t.Fatalf("an empty helper: %v, %v", removed, err)
	}
}

// TestSweepLoop: a helper given containerd's list sweeps on its own timer,
// and its stop waits for the sweep.
func TestSweepLoop(t *testing.T) {
	origFirst, origEvery := sweepFirst, sweepEvery
	sweepFirst, sweepEvery = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { sweepFirst, sweepEvery = origFirst, origEvery })
	lister := &fakeLister{ids: map[string]bool{}}
	r := newRig(t, func(_ *Config, o *Options) { o.Containers = lister })
	if _, err := helperClient(r).PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles},
		ContainerId: testCID, Setup: &rootdpb.ContainerSetup{TaskFifos: true}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for lister.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if lister.count() < 2 {
		t.Fatal("the sweep did not run on its timer")
	}
	lister.mu.Lock()
	lister.err = errors.New("containerd restarting")
	lister.mu.Unlock()
	n := lister.count()
	for lister.count() == n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r.srv.Shutdown(ctx)
}

// TestContainerIDsSkipsOtherNames: the sweep reads only container IDs from
// the helper's folders: a temporary name or a stray file is no container.
func TestContainerIDsSkipsOtherNames(t *testing.T) {
	r := newRig(t, nil)
	for _, n := range []string{"sb-a", ".tmp-x", "_runtime"} {
		if err := os.Mkdir(filepath.Join(r.cfg.Files.Hosts, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(r.cfg.Policy.FIFODir, "sb-a"), 0o750); err != nil {
		t.Fatal(err)
	}
	ids, err := r.srv.files.containerIDs()
	if err != nil || !slices.Equal(ids, []string{"sb-a"}) {
		t.Fatalf("ids %v, %v", ids, err)
	}
	if r.srv.files.newestChange("sb-none").IsZero() == false {
		t.Fatal("a container with no folder has a change time")
	}
	bad := &files{hosts: -1, ready: -1, fifo: -1}
	if _, err := bad.containerIDs(); err == nil {
		t.Fatal("closed folders listed")
	}
}

// TestToolboxCopy: with the agent's toolbox in a folder the agent writes,
// the helper keeps its own copy, root's, and copies again only when the
// agent's changed; a sandbox already running keeps the copy it started
// with. A link, a FIFO, a folder or an oversized file is refused, and a
// FIFO never holds the call.
func TestToolboxCopy(t *testing.T) {
	base := shortDir(t)
	src := filepath.Join(base, "agent", "toolbox", "toolboxd")
	copyPath := filepath.Join(base, "state", "toolbox", toolboxFile)
	r := newRig(t, func(c *Config, _ *Options) {
		c.Files.Toolbox, c.Files.ToolboxSource = copyPath, src
		c.Policy.BindFiles = []string{copyPath}
	})
	write := func(body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
			t.Fatal(err)
		}
		tmp := src + ".new"
		if err := os.WriteFile(tmp, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, src); err != nil {
			t.Fatal(err)
		}
	}
	ask := func() (string, error) {
		resp, err := helperClient(r).PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles},
			ContainerId: testCID, Setup: &rootdpb.ContainerSetup{Toolbox: true}})
		return resp.GetFiles().GetToolboxPath(), err
	}
	if _, err := ask(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("no toolbox yet: %v", err)
	}
	write("toolbox v1")
	p, err := ask()
	if err != nil || p != copyPath {
		t.Fatalf("copy at %q, %v", p, err)
	}
	wantFile(t, copyPath, 0o755, "toolbox v1")
	ino := statOf(t, copyPath).Ino
	running, err := os.Open(copyPath) // a sandbox's bind holds the inode
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	if _, err := ask(); err != nil || statOf(t, copyPath).Ino != ino {
		t.Fatalf("an unchanged toolbox was copied again: %v", err)
	}
	write("toolbox v2, longer")
	if _, err := ask(); err != nil {
		t.Fatal(err)
	}
	wantFile(t, copyPath, 0o755, "toolbox v2, longer")
	if b := make([]byte, 64); true {
		n, _ := running.ReadAt(b, 0)
		if string(b[:n]) != "toolbox v1" {
			t.Fatalf("the running sandbox's copy changed to %q", b[:n])
		}
	}
	// The copy removed (an operator's cleanup): made again.
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ask(); err != nil {
		t.Fatal(err)
	}
	wantFile(t, copyPath, 0o755, "toolbox v2, longer")
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}

	plant := func(f func()) {
		t.Helper()
		_ = os.RemoveAll(src)
		f()
	}
	for _, tc := range []struct {
		name  string
		plant func()
	}{
		{"a link to a host file", func() {
			if err := os.Symlink("/etc/passwd", src); err != nil {
				t.Fatal(err)
			}
		}},
		{"a FIFO", func() {
			if err := syscall.Mkfifo(src, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a folder", func() {
			if err := os.Mkdir(src, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"an empty file", func() {
			if err := os.WriteFile(src, nil, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"a file past the bound", func() {
			f, err := os.Create(src)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(maxToolboxBytes + 1); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plant(tc.plant)
			before := statOf(t, copyPath).Ino
			n := len(r.refused())
			done := make(chan error, 1)
			go func() { _, err := ask(); done <- err }()
			select {
			case err := <-done:
				if status.Code(err) != codes.PermissionDenied || len(r.refused()) != n+1 || r.refused()[n].Reason != ReasonBadToolbox {
					t.Fatalf("err %v, refusals %v", err, r.refused())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the call hung on the planted toolbox")
			}
			if statOf(t, copyPath).Ino != before {
				t.Fatal("a refused toolbox replaced the copy")
			}
		})
	}
	// The agent's folder is a link: not followed.
	plant(func() {})
	dir := filepath.Dir(src)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ask(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a linked folder: %v", err)
	}
}

// TestToolboxConfig: the toolbox settings the helper refuses to start
// with.
func TestToolboxConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"a toolbox the policy does not bind", func(c *Config) { c.Policy.BindFiles = nil }, "lack the toolbox binary"},
		{"a copy not named toolboxd", func(c *Config) {
			c.Files.ToolboxSource, c.Files.Toolbox = "/agent/toolboxd", "/state/tb/other"
			c.Policy.BindFiles = []string{c.Files.Toolbox}
		}, "must be a toolboxd"},
		{"a relative source", func(c *Config) {
			c.Files.ToolboxSource, c.Files.Toolbox = "agent/toolboxd", "/state/tb/toolboxd"
			c.Policy.BindFiles = []string{c.Files.Toolbox}
		}, "clean absolute path"},
		{"a copy among the host files", func(c *Config) {
			c.Files.ToolboxSource, c.Files.Toolbox = "/agent/toolboxd", filepath.Join(c.Files.Hosts, "toolboxd")
			c.Policy.BindFiles = []string{c.Files.Toolbox}
		}, "overlap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.mut(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}
