//go:build linux

package rootd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestE2EFirecracker drives a live helper's Firecracker calls (M1 PR 9b)
// over its socket, as the agent's own uid, with the real jailer and
// firecracker (the 9b box, AEROL_E2E_HELPER_SOCKET with AEROL_E2E_FC=1). The
// box has no KVM: a VM cannot boot, but the jailer builds its chroot and
// firecracker serves its API, which is everything the helper does for a
// VM. Then the broken agent's asks: each refused, none making anything.
func TestE2EFirecracker(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" || os.Getenv("AEROL_E2E_FC") == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_FC")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const fc = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	id := "sb-e2e-fc"

	// The jail, and a disk the agent builds in its stage folder.
	prep, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("jail: run %s stage %s", prep.GetRunDir(), prep.GetStageDir())
	if err := os.WriteFile(filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerOverlay), nil, 0o600); err != nil {
		t.Fatalf("the agent writes its stage folder: %v", err)
	}
	if err := os.Truncate(filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerOverlay), 16<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: id, Name: rootpolicy.FirecrackerOverlay}); err != nil {
		t.Fatalf("MakeFilesystem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prep.GetRunDir(), "planted"), nil, 0o600); err == nil {
		t.Fatal("the agent wrote in the chroot")
	}
	if _, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id,
		Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerOverlay}}}); err != nil {
		t.Fatalf("stage the overlay: %v", err)
	}

	// The jailer runs firecracker; the agent dials its API socket.
	sp, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: id})
	if err != nil {
		t.Fatalf("SpawnHost: %v", err)
	}
	t.Logf("firecracker pid %d", sp.GetPid())
	api := filepath.Join(prep.GetRunDir(), "api.socket")
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", api)
	}}}
	resp, err := hc.Get("http://localhost/")
	if err != nil {
		t.Fatalf("the agent dials firecracker's API: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	t.Logf("GET / -> %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "\"id\"") {
		t.Fatalf("firecracker's API answered %d %s", resp.StatusCode, body)
	}
	again, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: id})
	if err != nil || !again.GetAlready() || again.GetPid() != sp.GetPid() {
		t.Fatalf("a second SpawnHost: %v %v", again, err)
	}
	list, err := c.ListHosts(ctx, &rootdpb.ListHostsRequest{Kind: fc})
	if err != nil || len(list.GetHosts()) != 1 || list.GetHosts()[0].GetPid() != sp.GetPid() {
		t.Fatalf("ListHosts: %v %v", list, err)
	}

	// Nothing the jailer or firecracker made in the chroot is the agent's
	// group's to write.
	_ = filepath.WalkDir(prep.GetRunDir(), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := os.Lstat(p); err == nil && fi.Mode().Type() != os.ModeSocket && fi.Mode().Perm()&0o020 != 0 && p != prep.GetRunDir() {
			t.Errorf("%s is the agent's group's to write (%v)", p, fi.Mode())
		}
		return nil
	})

	// A TAP from the pool, for the jailer's user.
	tap, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap1"})
	if err != nil {
		t.Fatalf("EnsureTap: %v", err)
	}
	t.Logf("fctap1: %s host %s guest %s cid %d", tap.GetCidr(), tap.GetHostIp(), tap.GetGuestIp(), tap.GetVsockCid())
	if _, err := net.InterfaceByName("fctap1"); err != nil {
		t.Fatalf("fctap1 not up: %v", err)
	}

	// The broken agent's asks.
	refused := func(name string, err error, want string) {
		t.Helper()
		if reason, ok := rootdpb.RefusalReason(err); !ok || reason != want {
			t.Errorf("%s: %v, want a %q refusal", name, err, want)
		}
	}
	_, err = c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "eth0"})
	refused("a TAP that is the node's link", err, string(rootpolicy.RuleTap))
	_, err = c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: "lo"})
	refused("removing lo", err, string(rootpolicy.RuleTap))
	_, err = c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap99999"})
	refused("a TAP past the pool", err, string(rootpolicy.RuleTap))
	_, err = c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: "../../etc"})
	refused("a jail up the tree", err, string(rootpolicy.RuleHost))
	_, err = c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id,
		Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{"vmlinux"}}})
	refused("staging over the kernel", err, string(rootpolicy.RuleHost))
	_, err = c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: id, Name: "../../../etc/passwd"})
	refused("a filesystem outside the stage folder", err, string(rootpolicy.RuleHost))
	_, err = c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: id, Name: rootpolicy.FirecrackerRootfs, Source: "/root", SizeMib: 8})
	if err == nil {
		t.Error("mkfs.ext4 read root's folder")
	}
	_ = os.Remove(filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerRootfs)) // what the refused mkfs.ext4 began
	if err := os.Symlink("/etc/shadow", filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerRootfs)); err != nil {
		t.Fatal(err)
	}
	_, err = c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id,
		Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerRootfs}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("staging a link to /etc/shadow: %v", err)
	}
	_, err = c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: "sb-e2e-x", Limits: &rootdpb.HostLimits{Pids: 1}})
	refused("limits on a VM", err, ReasonBadRequest)

	// Stop: the VM, its jail and its TAP go.
	if _, err := c.RemoveTap(ctx, &rootdpb.RemoveTapRequest{Name: "fctap1"}); err != nil {
		t.Fatal(err)
	}
	st, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: id})
	if err != nil || !st.GetHad() {
		t.Fatalf("StopHost: %v %v", st, err)
	}
	if _, err := os.Lstat(filepath.Dir(prep.GetRunDir())); !os.IsNotExist(err) {
		t.Fatalf("the jail is left: %v", err)
	}
	fmt.Println("e2e-fc: ok")
}

// TestE2EFirecrackerSpawnTiming is one round of a VM's start in split mode,
// timed, as the agent: the jail, the overlay's filesystem, its move into
// the chroot, the jailer and firecracker up to its API socket, and the
// stop (AEROL_E2E_FC_TIMING). The box pairs it with
// TestFirecrackerSingleModeSpawnTiming, single mode's same work as root.
func TestE2EFirecrackerSpawnTiming(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" || os.Getenv("AEROL_E2E_FC_TIMING") == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_FC_TIMING")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const fc = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	id := "sb-timing"
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	prep, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id})
	if err != nil {
		t.Fatal(err)
	}
	tPrep := lap()
	ov := filepath.Join(prep.GetStageDir(), rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, 64<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MakeFilesystem(ctx, &rootdpb.MakeFilesystemRequest{Id: id, Name: rootpolicy.FirecrackerOverlay}); err != nil {
		t.Fatal(err)
	}
	tMkfs := lap()
	if _, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: fc, Id: id,
		Firecracker: &rootdpb.FirecrackerHostSpec{Stage: []string{rootpolicy.FirecrackerOverlay}}}); err != nil {
		t.Fatal(err)
	}
	tStage := lap()
	if _, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	tSpawn := lap()
	if _, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: fc, Id: id}); err != nil {
		t.Fatal(err)
	}
	tStop := lap()
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }
	fmt.Printf("timing\tsplit\tjail=%s\tmkfs=%s\tstage=%s\tspawn=%s\tstop=%s\n", ms(tPrep), ms(tMkfs), ms(tStage), ms(tSpawn), ms(tStop))
}
