//go:build linux

package rootd

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// benchSnapshotter is containerd's snapshotter as oci.WithImageConfig sees
// it in single mode: Mounts answers the container's overlay, which
// containerd 2.4 reads in process (fsview), with no mount.
type benchSnapshotter struct {
	snapshots.Snapshotter
	ms []mount.Mount
}

func (b benchSnapshotter) Mounts(context.Context, string) ([]mount.Mount, error) { return b.ms, nil }

type benchClient struct{ s benchSnapshotter }

func (b benchClient) SnapshotService(string) snapshots.Snapshotter { return b.s }

// TestKernelContainerPartsBudget measures, as root, the root work a
// create's container needs, single against split, in turns: single mode's
// own (three host files and two FIFOs written by sandboxd, and
// oci.WithImageConfig reading the image's users from the layers in
// process), and split mode's one PrepareSandbox call over the socket
// (files part; with image_user on the first create of an image, which
// mounts the layers in a private namespace). It reports each part's cost
// inside the call too.
//
//	AEROL_BUDGET_ROUNDS=25 go test -run TestKernelContainerPartsBudget -v ./internal/rootd/
func TestKernelContainerPartsBudget(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("AEROL_BUDGET_ROUNDS"))
	if rounds <= 0 || os.Geteuid() != 0 {
		t.Skip("a measurement, as root: set AEROL_BUDGET_ROUNDS")
	}
	per := 5
	// Two image layers, as the overlayfs snapshotter lays them out.
	snapRoot := t.TempDir()
	snaps := filepath.Join(snapRoot, "snapshots")
	for n, files := range map[int]map[string]string{
		1: {"etc/passwd": "root:x:0:0::/root:/bin/sh\n", "etc/group": "root:x:0:\nwheel:x:10:appuser\n"},
		2: {"etc/passwd": "root:x:0:0::/root:/bin/sh\nappuser:x:1234:1234::/home/appuser:/bin/sh\n", "bin/sh": "x"},
		3: {},
	} {
		for name, body := range files {
			p := filepath.Join(snaps, strconv.Itoa(n), "fs", name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(snaps, strconv.Itoa(n), "fs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(snaps, strconv.Itoa(n), "work"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	overlay := []string{"workdir=" + snaps + "/3/work", "upperdir=" + snaps + "/3/fs", "lowerdir=" + snaps + "/2/fs:" + snaps + "/1/fs"}
	fs := &fakeSnapshots{snaps: map[string]fakeSnap{}}
	var handler time.Duration
	rg := newRig(t, func(c *Config, o *Options) {
		c.Policy.SnapshotterRoot = snapRoot
		o.Snapshots = fs
		o.ServerOptions = append(o.ServerOptions, grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			t0 := time.Now()
			resp, err := h(ctx, req)
			handler = time.Since(t0)
			return resp, err
		}))
	})
	c := helperClient(rg)
	ctx := context.Background()
	single := t.TempDir()
	singleWork := func(i int) time.Duration {
		t0 := time.Now()
		dir := filepath.Join(single, fmt.Sprintf("sb-%d", i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{"resolv.conf": "nameserver 10.0.0.2\n", "hosts": "127.0.0.1 localhost\n", "hostname": "sb\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for _, f := range []string{"stdout", "stderr"} {
			if err := syscall.Mkfifo(filepath.Join(dir, f), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		s := &oci.Spec{Process: &specs.Process{}, Linux: &specs.Linux{}}
		cl := benchClient{benchSnapshotter{ms: []mount.Mount{{Type: "overlay", Source: "overlay", Options: overlay}}}}
		cont := &containers.Container{Snapshotter: "overlayfs", SnapshotKey: "sb"}
		if err := oci.WithUser("appuser")(ctx, cl, cont, s); err != nil {
			t.Fatal(err)
		}
		if err := oci.WithAdditionalGIDs("1234")(ctx, cl, cont, s); err != nil {
			t.Fatal(err)
		}
		d := time.Since(t0)
		_ = os.RemoveAll(dir)
		return d
	}
	call := func(i int, user string) (time.Duration, time.Duration) {
		id := fmt.Sprintf("sb-%d", i)
		fs.set(id, fakeSnap{info: SnapshotInfo{Kind: "active", Parent: "sha256:p"}, mounts: []rootpolicy.Mount{{Type: "overlay", Source: "overlay", Options: overlay}}})
		req := &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: id, Setup: &rootdpb.ContainerSetup{
			Naming:    &rootdpb.HostNaming{Hostname: id, Hosts: localhostEntries(), Nameservers: []string{"10.0.0.2"}},
			TaskFifos: true, Toolbox: true}}
		if user != "" {
			req.Parts = append(req.Parts, rootdpb.PartImageUser)
			req.ImageUser = &rootdpb.ImageUser{User: user}
		}
		t0 := time.Now()
		if _, err := c.PrepareSandbox(ctx, req); err != nil {
			t.Fatal(err)
		}
		d := time.Since(t0)
		if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: id}); err != nil {
			t.Fatal(err)
		}
		return d, handler
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	var sWarm, pWarm, pWarmIn, sMiss, pMiss, pMissIn, inFiles, inUserMiss, inUserHit []float64
	n := 0
	for r := range rounds {
		for k := range per {
			for _, split := range [][]bool{{false, true}, {true, false}}[(r+k)%2] {
				n++
				if !split {
					d := singleWork(n)
					sWarm, sMiss = append(sWarm, ms(d)), append(sMiss, ms(d)) // single reads the image every create
					continue
				}
				// Warm path: the agent knows the image's user; files only.
				d, in := call(n, "")
				pWarm, pWarmIn = append(pWarm, ms(d)), append(pWarmIn, ms(in))
				// First create of a new image: a user string the helper has
				// not resolved, so it mounts and reads the layers.
				d, in = call(n+100000, fmt.Sprintf("%d", 2000+n))
				pMiss, pMissIn = append(pMiss, ms(d)), append(pMissIn, ms(in))
			}
		}
		// Each part inside the call, straight on the helper's code.
		ct := newContainerCalls(rg.cfg, Options{Snapshots: fs})
		plan, _ := rg.srv.files.checkSetup(&rootdpb.ContainerSetup{Naming: &rootdpb.HostNaming{Hostname: "sb-x", Hosts: localhostEntries()}, TaskFifos: true, Toolbox: true})
		t0 := time.Now()
		if _, err := rg.srv.files.setup("sb-x", plan); err != nil {
			t.Fatal(err)
		}
		inFiles = append(inFiles, ms(time.Since(t0)))
		// A parent the cache has not seen: a miss, then a hit.
		fs.set("sb-u", fakeSnap{info: SnapshotInfo{Kind: "active", Parent: fmt.Sprintf("sha256:p%d", r)}, mounts: []rootpolicy.Mount{{Type: "overlay", Source: "overlay", Options: overlay}}})
		t0 = time.Now()
		if _, err := ct.imageUser(ctx, "sb-u", "appuser"); err != nil {
			t.Fatal(err)
		}
		inUserMiss = append(inUserMiss, ms(time.Since(t0)))
		t0 = time.Now()
		if _, err := ct.imageUser(ctx, "sb-u", "appuser"); err != nil {
			t.Fatal(err)
		}
		inUserHit = append(inUserHit, ms(time.Since(t0)))
	}
	report := func(name string, a, b []float64) {
		d := make([]float64, len(a))
		for i := range a {
			d[i] = b[i] - a[i]
		}
		m, lo, hi := meanCI(d)
		t.Logf("%-48s single p50 %.3f ms, split p50 %.3f ms; split-single mean %+.3f ms (95%% CI %+.3f to %+.3f), median %+.3f (n=%d)",
			name, p50(a), p50(b), m, lo, hi, p50(d), len(d))
	}
	report("warm path (agent knows the user): files call", sWarm, pWarm)
	report("first create of an image: files + image_user", sMiss, pMiss)
	t.Logf("inside the call: whole handler, warm p50 %.3f ms; first create p50 %.3f ms", p50(pWarmIn), p50(pMissIn))
	t.Logf("inside the call, by part: files p50 %.3f ms; image_user miss (mount, read, resolve) p50 %.3f ms; image_user hit (helper cache) p50 %.3f ms",
		p50(inFiles), p50(inUserMiss), p50(inUserHit))
	t.Logf("round trip (call minus handler), warm p50 %.3f ms", p50(sub(pWarm, pWarmIn)))
}

func sub(a, b []float64) []float64 {
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] - b[i]
	}
	return out
}

func p50(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s) == 0 {
		return math.NaN()
	}
	return s[len(s)/2]
}

func meanCI(v []float64) (mean, lo, hi float64) {
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	var ss float64
	for _, x := range v {
		ss += (x - mean) * (x - mean)
	}
	se := math.Sqrt(ss/float64(len(v)-1)) / math.Sqrt(float64(len(v)))
	return mean, mean - 1.96*se, mean + 1.96*se
}
