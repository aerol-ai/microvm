//go:build linux

package rootd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// A VM's snapshot files on a live helper (M1 PR 14b), in the PR 14 box:
// the helper runs as root with the real jailer and firecracker, these calls
// come as the agent's uid, and the box writes in the VM's chroot as the
// jailer's user between the steps, standing in for what firecracker
// writes for a snapshot (the box has no KVM). AEROL_E2E_FC_FILES names one
// step.

const e2eFilesVM = "sb-e2e-files"

func TestE2EFirecrackerFiles(t *testing.T) {
	sock, phase := os.Getenv("AEROL_E2E_HELPER_SOCKET"), os.Getenv("AEROL_E2E_FC_FILES")
	if sock == "" || phase == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_FC_FILES")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const fc = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	prep, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: e2eFilesVM})
	if err != nil {
		t.Fatal(err)
	}
	root, stage := prep.GetRunDir(), prep.GetStageDir()
	files := func(names ...string) *rootdpb.FirecrackerFilesRequest {
		return &rootdpb.FirecrackerFilesRequest{Id: e2eFilesVM, Names: names}
	}
	owner := func(p string) string {
		fi, err := os.Lstat(p)
		if err != nil {
			return err.Error()
		}
		st := fi.Sys().(*syscall.Stat_t)
		return fmt.Sprintf("%d:%d %o", st.Uid, st.Gid, fi.Mode().Perm())
	}
	switch phase {
	case "spawn":
		sp, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: e2eFilesVM})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("firecracker pid %d; chroot %s", sp.GetPid(), root)
	case "out":
		// The box wrote saved.memory and saved.state in the chroot as the
		// jailer's user, 0600, where firecracker writes a snapshot in
		// split: the agent cannot read them.
		mem := filepath.Join(root, rootpolicy.FirecrackerSavedMemory)
		if _, err := os.ReadFile(mem); err == nil {
			t.Fatal("the agent read the jailer's file before the hand-out")
		}
		t.Logf("before: %s %s", rootpolicy.FirecrackerSavedMemory, owner(mem))
		if _, err := c.HandOutFirecrackerFiles(ctx, files(rootpolicy.FirecrackerSavedMemory, rootpolicy.FirecrackerSavedState)); err != nil {
			t.Fatalf("HandOutFirecrackerFiles: %v", err)
		}
		t.Logf("after: %s %s", rootpolicy.FirecrackerSavedMemory, owner(mem))
		b, err := os.ReadFile(mem)
		if err != nil {
			t.Fatalf("the agent reads the handed-out file: %v", err)
		}
		t.Logf("the agent read %d bytes: %q", len(b), b)
		// The agent still writes nothing in the chroot.
		if err := os.WriteFile(mem, []byte("x"), 0o640); err == nil {
			t.Fatal("the agent wrote the VM's file")
		}
	case "in":
		saved := filepath.Join(stage, rootpolicy.FirecrackerMemory)
		if err := os.WriteFile(saved, []byte("the agent's saved memory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ShareFirecrackerFiles(ctx, files(rootpolicy.FirecrackerMemory)); err != nil {
			t.Fatalf("ShareFirecrackerFiles: %v", err)
		}
		in := filepath.Join(root, rootpolicy.FirecrackerMemory)
		t.Logf("shared in: %s %s", rootpolicy.FirecrackerMemory, owner(in))
		if b, err := os.ReadFile(in); err != nil || string(b) != "the agent's saved memory" {
			t.Fatalf("the chroot's file: %q %v", b, err)
		}
	case "refuse":
		for _, tc := range []struct {
			name string
			call func() error
		}{
			{"a VM id up the tree", func() error {
				_, err := c.HandOutFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "../" + e2eFilesVM, Names: []string{rootpolicy.FirecrackerMemory}})
				return err
			}},
			{"a path for a name", func() error { _, err := c.HandOutFirecrackerFiles(ctx, files("../../../etc/shadow")); return err }},
			{"the kernel handed out", func() error {
				_, err := c.HandOutFirecrackerFiles(ctx, files(rootpolicy.FirecrackerKernel))
				return err
			}},
			{"a link the VM put where its disk should be", func() error {
				_, err := c.HandOutFirecrackerFiles(ctx, files(rootpolicy.FirecrackerRootfs))
				return err
			}},
			{"a file the VM gave two names", func() error {
				_, err := c.HandOutFirecrackerFiles(ctx, files(rootpolicy.FirecrackerOverlay))
				return err
			}},
			{"a file the VM grew past the cap", func() error { _, err := c.HandOutFirecrackerFiles(ctx, files(rootpolicy.FirecrackerState)); return err }},
			{"a link in the stage folder", func() error { _, err := c.ShareFirecrackerFiles(ctx, files(rootpolicy.FirecrackerRootfs)); return err }},
			{"the overlay shared read-only", func() error { _, err := c.ShareFirecrackerFiles(ctx, files(rootpolicy.FirecrackerOverlay)); return err }},
			{"a snapshot CID past 24 bits", func() error {
				_, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap7", GuestCid: 1 << 24})
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
	case "stop":
		if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: e2eFilesVM}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("phase %q", phase)
	}
}

// TestE2EFirecrackerLoadTiming is one round of a snapshot load's root work
// in split mode, through the helper as the agent, in the driver's order
// (Create's snapshot-load path, up to LoadSnapshot, which needs KVM): the
// jail, the TAP with the snapshot's MAC, the jailer, the template's
// memory, state and disk shared in one call, the overlay moved in, the
// sockets shared; then the stop. TestFirecrackerSingleModeLoadTiming is the
// same round as single mode does it.
func TestE2EFirecrackerLoadTiming(t *testing.T) {
	sock, tpl := os.Getenv("AEROL_E2E_HELPER_SOCKET"), os.Getenv("AEROL_E2E_FC_LOAD_TEMPLATE")
	if sock == "" || tpl == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_FC_LOAD_TEMPLATE")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.Version(ctx, &rootdpb.VersionRequest{}); err != nil {
		t.Fatal(err)
	}
	const fc = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	id := "sb-load-timing"
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	prep, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id})
	if err != nil {
		t.Fatal(err)
	}
	tJail := lap()
	if _, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap9", GuestCid: 7}); err != nil {
		t.Fatal(err)
	}
	tTap := lap()
	if _, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	tSpawn := lap()
	for _, n := range []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState, rootpolicy.FirecrackerRootfs} {
		if err := os.Link(filepath.Join(tpl, n), filepath.Join(prep.GetStageDir(), n)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ShareFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: id,
		Names: []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState, rootpolicy.FirecrackerRootfs}}); err != nil {
		t.Fatal(err)
	}
	tShare := lap()
	ov := filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id,
		Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerOverlay}}}); err != nil {
		t.Fatal(err)
	}
	tOverlay := lap()
	if _, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	tSockets := lap()
	if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap9"}); err != nil {
		t.Fatal(err)
	}
	tStop := lap()
	fmt.Printf("timing\tsplit\tjail=%.3f\ttap=%.3f\tspawn=%.3f\tshare=%.3f\toverlay=%.3f\tsockets=%.3f\tstop=%.3f\n",
		msOf(tJail), msOf(tTap), msOf(tSpawn), msOf(tShare), msOf(tOverlay), msOf(tSockets), msOf(tStop))
}
