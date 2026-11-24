//go:build linux

package rootd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The warm VM pool and disk images on a live helper (M1 PR 18), in the
// PR 18 box: the helper runs as root with the real jailer and firecracker,
// these calls come as the agent's uid, and the box looks at the files
// between the steps (it has no KVM, so no VM boots). AEROL_E2E_FC_POOL
// names one step; AEROL_E2E_FC_POOL_TEMPLATE is a template folder of the
// agent's (memory, state, disk) and AEROL_E2E_FC_POOL_WORK a folder of the
// agent's for the export VM's image.

const (
	e2ePoolSlot   = "vmms-00000000e2e00001"
	e2ePoolTap    = "fctap12"
	e2eExportImg  = "export-0000e2e00001"
	e2eExportVM   = "export-0000e2e00002"
	ext4MagicAt   = 1080
	ext4Magic     = 0xEF53
	poolDiskBytes = 64 << 20
)

func TestE2EFirecrackerPool(t *testing.T) {
	sock, phase := os.Getenv("AEROL_E2E_HELPER_SOCKET"), os.Getenv("AEROL_E2E_FC_POOL")
	if sock == "" || phase == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_FC_POOL")
	}
	if phase == "wrong-caller" {
		// Run as a uid other than the agent's: the helper's peer check
		// refuses the connection or the call.
		conn := dialSocket(t, sock)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := rootdpb.NewRootHelperClient(conn).PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: rootdpb.HostKind_HOST_KIND_FIRECRACKER, Id: e2ePoolSlot})
		t.Logf("a call as uid %d: %v", os.Getuid(), err)
		if err == nil {
			t.Fatal("the helper served a caller that is not the agent")
		}
		return
	}
	tpl, work := os.Getenv("AEROL_E2E_FC_POOL_TEMPLATE"), os.Getenv("AEROL_E2E_FC_POOL_WORK")
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const fc = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	prepare := func(id string, stage ...string) *rootdpb.PrepareHostResponse {
		t.Helper()
		req := &rootdpb.PrepareHostRequest{Kind: fc, Id: id}
		if len(stage) > 0 {
			req.Firecracker = &rootdpb.FirecrackerHostSpec{Stage: stage}
		}
		resp, err := c.PrepareHost(ctx, req)
		if err != nil {
			t.Fatalf("PrepareHost %s %v: %v", id, stage, err)
		}
		return resp
	}
	files := func(id string, names ...string) *rootdpb.FirecrackerFilesRequest {
		return &rootdpb.FirecrackerFilesRequest{Id: id, Names: names}
	}
	show := func(paths ...string) {
		for _, p := range paths {
			fi, err := os.Lstat(p)
			if err != nil {
				t.Logf("  %s: %v", filepath.Base(p), err)
				continue
			}
			st := fi.Sys().(*syscall.Stat_t)
			t.Logf("  %s %d:%d %o ino %d", filepath.Base(p), st.Uid, st.Gid, fi.Mode().Perm(), st.Ino)
		}
	}
	sparse := func(p string, size int64) {
		t.Helper()
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, size); err != nil {
			t.Fatal(err)
		}
	}
	slot := prepare(e2ePoolSlot)
	root, stage := slot.GetRunDir(), slot.GetStageDir()
	switch phase {
	case "refill":
		// The slot's jail, its TAP with the snapshot's MAC and its jailer,
		// all under the slot's ID; the template's three files shared in one
		// call; the placeholder overlay moved in; the sockets shared.
		if _, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: e2ePoolTap, GuestCid: 7}); err != nil {
			t.Fatal(err)
		}
		sp, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: e2ePoolSlot})
		if err != nil {
			t.Fatal(err)
		}
		names := []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState, rootpolicy.FirecrackerRootfs}
		for _, n := range names {
			if err := os.Link(filepath.Join(tpl, n), filepath.Join(stage, n)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.ShareFirecrackerFiles(ctx, files(e2ePoolSlot, names...)); err != nil {
			t.Fatalf("ShareFirecrackerFiles: %v", err)
		}
		sparse(filepath.Join(stage, rootpolicy.FirecrackerOverlay), 1<<20)
		prepare(e2ePoolSlot, rootpolicy.FirecrackerOverlay)
		prepare(e2ePoolSlot)
		t.Logf("slot %s: firecracker pid %d, chroot %s", e2ePoolSlot, sp.GetPid(), root)
		show(filepath.Join(root, rootpolicy.FirecrackerMemory), filepath.Join(root, rootpolicy.FirecrackerRootfs),
			filepath.Join(root, rootpolicy.FirecrackerOverlay), filepath.Join(root, "api.socket"))
	case "claim":
		// A claim with an overlay of the sandbox's own: the helper makes its
		// filesystem in the stage folder and moves it in over the
		// placeholder, while the slot's VM runs on.
		before, _ := os.Lstat(filepath.Join(root, rootpolicy.FirecrackerOverlay))
		sparse(filepath.Join(stage, rootpolicy.FirecrackerOverlay), poolDiskBytes)
		if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: e2ePoolSlot, Name: rootpolicy.FirecrackerOverlay}); err != nil {
			t.Fatalf("MakeFilesystem: %v", err)
		}
		prepare(e2ePoolSlot, rootpolicy.FirecrackerOverlay)
		after, err := os.Lstat(filepath.Join(root, rootpolicy.FirecrackerOverlay))
		if err != nil || before == nil || os.SameFile(before, after) {
			t.Fatalf("the overlay was not replaced: %v", err)
		}
		sp, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: e2ePoolSlot})
		if err != nil || !sp.GetAlready() {
			t.Fatalf("the slot's VM did not run on: %v %v", sp, err)
		}
		show(filepath.Join(root, rootpolicy.FirecrackerOverlay), filepath.Join(root, "api.socket"))
	case "handout":
		// A running claimed slot's disk, handed out by the slot's ID: the
		// agent reads it through no link and cannot write it.
		if _, err := c.HandOutFirecrackerFiles(ctx, files(e2ePoolSlot, rootpolicy.FirecrackerOverlay)); err != nil {
			t.Fatalf("HandOutFirecrackerFiles: %v", err)
		}
		p := filepath.Join(root, rootpolicy.FirecrackerOverlay)
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatalf("the agent opens the handed-out disk: %v", err)
		}
		head := make([]byte, ext4MagicAt+2)
		_, rerr := io.ReadFull(f, head)
		_ = f.Close()
		if rerr != nil || binary.LittleEndian.Uint16(head[ext4MagicAt:]) != ext4Magic {
			t.Fatalf("the handed-out disk is no ext4 filesystem: %v", rerr)
		}
		t.Logf("the handed-out disk is an ext4 filesystem (magic %#x)", binary.LittleEndian.Uint16(head[ext4MagicAt:]))
		if err := os.WriteFile(p, []byte("x"), 0o640); err == nil {
			t.Fatal("the agent wrote the VM's disk")
		}
		show(p)
	case "export":
		// The export VM's image, built by the helper's mkfs in a jail of
		// its own and moved to the agent's folder; then an export VM with
		// that image read-only and a copy of the slot's disk as its
		// writable one, under the overlay's name.
		src := filepath.Join(work, "src")
		for _, d := range []string{"dev", "proc", "sys", "mnt"} {
			if err := os.MkdirAll(filepath.Join(src, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(src, "toolboxd"), []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		img := prepare(e2eExportImg)
		if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: e2eExportImg, Name: rootpolicy.FirecrackerRootfs, Source: src, SizeMib: 128}); err != nil {
			t.Fatalf("MakeFilesystem with a source: %v", err)
		}
		image := filepath.Join(work, "helper.ext4")
		if err := os.Rename(filepath.Join(img.GetStageDir(), rootpolicy.FirecrackerRootfs), image); err != nil {
			t.Fatal(err)
		}
		if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: e2eExportImg}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Dir(img.GetRunDir())); !os.IsNotExist(err) {
			t.Fatalf("the image build's jail is left: %v", err)
		}
		show(image)
		// In the driver's order: the jailer first, as a share goes only
		// into a chroot a process runs in.
		vm := prepare(e2eExportVM)
		if _, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: e2eExportVM}); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(image, filepath.Join(vm.GetStageDir(), rootpolicy.FirecrackerRootfs)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ShareFirecrackerFiles(ctx, files(e2eExportVM, rootpolicy.FirecrackerRootfs)); err != nil {
			t.Fatalf("share the image: %v", err)
		}
		in, err := os.OpenFile(filepath.Join(root, rootpolicy.FirecrackerOverlay), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(filepath.Join(vm.GetStageDir(), rootpolicy.FirecrackerOverlay), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, cerr := io.Copy(out, in)
		_, _ = in.Close(), out.Close()
		if cerr != nil {
			t.Fatal(cerr)
		}
		prepare(e2eExportVM, rootpolicy.FirecrackerOverlay)
		prepare(e2eExportVM)
		show(filepath.Join(vm.GetRunDir(), rootpolicy.FirecrackerRootfs), filepath.Join(vm.GetRunDir(), rootpolicy.FirecrackerOverlay),
			filepath.Join(vm.GetRunDir(), "api.socket"))
		if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: e2eExportVM}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Dir(vm.GetRunDir())); !os.IsNotExist(err) {
			t.Fatalf("the export VM's jail is left: %v", err)
		}
	case "refuse":
		// A broken agent: each call is refused before root acts on it. It
		// plants a file with two names and a link to the slot's disk in the
		// export VM's stage folder first.
		other := prepare(e2eExportVM)
		ov := filepath.Join(other.GetStageDir(), rootpolicy.FirecrackerOverlay)
		if err := os.WriteFile(ov, []byte("disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(ov, filepath.Join(other.GetStageDir(), "again")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, rootpolicy.FirecrackerOverlay), filepath.Join(other.GetStageDir(), rootpolicy.FirecrackerRootfs)); err != nil {
			t.Fatal(err)
		}
		show(ov, filepath.Join(other.GetStageDir(), rootpolicy.FirecrackerRootfs))
		for _, tc := range []struct {
			name string
			call func() error
		}{
			{"a slot ID up the tree", func() error {
				_, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: "../" + e2ePoolSlot})
				return err
			}},
			{"a slot ID with a slash", func() error {
				_, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: e2ePoolSlot + "/../sb-1"})
				return err
			}},
			{"a jail stopped by a path", func() error {
				_, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: "../../etc"})
				return err
			}},
			{"a filesystem under a name the helper does not take", func() error {
				_, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: e2ePoolSlot, Name: "export.ext4"})
				return err
			}},
			{"a filesystem from a relative folder", func() error {
				_, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: e2ePoolSlot, Name: rootpolicy.FirecrackerRootfs, Source: "src", SizeMib: 8})
				return err
			}},
			{"a staged disk with two names", func() error {
				_, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: e2eExportVM,
					Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerOverlay}}})
				return err
			}},
			{"a staged link to another VM's disk", func() error {
				_, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: e2eExportVM,
					Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerRootfs}}})
				return err
			}},
			{"the overlay shared read-only", func() error {
				_, err := c.ShareFirecrackerFiles(ctx, files(e2ePoolSlot, rootpolicy.FirecrackerOverlay))
				return err
			}},
			{"the kernel handed out", func() error {
				_, err := c.HandOutFirecrackerFiles(ctx, files(e2ePoolSlot, rootpolicy.FirecrackerKernel))
				return err
			}},
		} {
			err := tc.call()
			reason, refused := rootdpb.RefusalReason(err)
			t.Logf("%s: %v %q", tc.name, status.Code(err), reason)
			if !refused {
				t.Errorf("%s = %v, want a refusal", tc.name, err)
			}
		}
		show(filepath.Join(other.GetRunDir(), rootpolicy.FirecrackerOverlay), filepath.Join(other.GetRunDir(), rootpolicy.FirecrackerRootfs))
		if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: e2eExportVM}); err != nil {
			t.Fatal(err)
		}
	case "fresh":
		// A slot whose VM ended: its next jail is made from nothing, so
		// nothing the slot's VM left reaches the next one.
		if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: e2ePoolSlot}); err != nil {
			t.Fatal(err)
		}
		again := prepare(e2ePoolSlot)
		entries, err := os.ReadDir(again.GetRunDir())
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Logf("the slot's chroot made again holds %v", names)
		if len(names) != 1 || names[0] != rootpolicy.FirecrackerKernel {
			t.Fatalf("the slot's next chroot holds %v, want the kernel alone", names)
		}
		if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: e2ePoolSlot}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: e2ePoolTap}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("phase %q", phase)
	}
}

// TestE2EFirecrackerClaimTiming is one round of the split root work this PR
// adds, through the helper as the agent: a warm claim with an overlay of the
// sandbox's own (the stage file, the helper's mkfs, the move in over the
// placeholder, on a running slot), and the export VM's image built in a jail
// of its own. TestFirecrackerSingleModeClaimTiming is the same round as
// single mode does it. A claim with no overlay of its own makes no helper
// call in split, so it is not timed.
func TestE2EFirecrackerClaimTiming(t *testing.T) {
	sock, work := os.Getenv("AEROL_E2E_HELPER_SOCKET"), os.Getenv("AEROL_E2E_FC_POOL_WORK")
	if sock == "" || work == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_FC_POOL_WORK")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.Version(ctx, &rootdpb.VersionRequest{}); err != nil {
		t.Fatal(err)
	}
	const fc = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	const id, img = "vmms-00000000e2e0000t", "export-0000e2e0000t"
	prep, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	ov := filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, poolDiskBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: id, Name: rootpolicy.FirecrackerOverlay}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id,
		Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerOverlay}}}); err != nil {
		t.Fatal(err)
	}
	tClaim := lap()
	ip, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: img})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: img, Name: rootpolicy.FirecrackerRootfs,
		Source: filepath.Join(work, "src"), SizeMib: 128}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(work, "timing.ext4")
	if err := os.Rename(filepath.Join(ip.GetStageDir(), rootpolicy.FirecrackerRootfs), out); err != nil {
		t.Fatal(err)
	}
	if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: img}); err != nil {
		t.Fatal(err)
	}
	tImage := lap()
	_ = os.Remove(out)
	if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("timing\tsplit\tclaim=%.3f\timage=%.3f\n", msOf(tClaim), msOf(tImage))
}
