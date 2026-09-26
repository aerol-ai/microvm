package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSendVsockOp_MarshalDataError(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{conns: []*errVsockConn{{reply: []byte("ok\n")}}}}
	if err := d.sendVsockOp(context.Background(), "/tmp/vsock.sock", 3, "ping", make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal data") {
		t.Fatalf("marshal data error: got %v", err)
	}
}

func TestSnapshotTemplate_ValidationShortCircuit(t *testing.T) {
	d := New(Config{KernelImage: "/k"}, nil)
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Fatalf("pool guard: got %v", err)
	}
}

func TestCreateSnapshotArtifacts_JailerMode(t *testing.T) {
	runDir := t.TempDir()
	outDir := t.TempDir()
	memOut := filepath.Join(outDir, "mem")
	stateOut := filepath.Join(outDir, "state")
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	client.snapshotBase = runDir
	if err := d.createSnapshotArtifacts(context.Background(), client, runDir, memOut, stateOut); err != nil {
		t.Fatalf("createSnapshotArtifacts: %v", err)
	}
	for _, p := range []string{memOut, stateOut} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("artifact %s: %v", p, err)
		}
	}
}

func TestSnapshotTemplate_ValidationGuards(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = f.kernel
	base := TemplateSnapshotRequest{
		TemplateID: "tpl", RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 10,
	}
	if _, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "template id is empty") {
		t.Fatalf("empty template: got %v", err)
	}
	if _, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{TemplateID: "tpl"}); err == nil || !strings.Contains(err.Error(), "rootfs/out paths are required") {
		t.Fatalf("missing paths: got %v", err)
	}
	req := base
	req.GuestCID = 2
	if _, err := f.driver.SnapshotTemplate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "GuestCID=2 is reserved") {
		t.Fatalf("bad cid: got %v", err)
	}
}

func TestCreateSnapshotArtifacts_JailerCopyFailure(t *testing.T) {
	runDir := t.TempDir()
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	client.snapshotBase = runDir
	outDir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(outDir, 0o555); err != nil {
		t.Fatal(err)
	}
	memOut := filepath.Join(outDir, "mem")
	stateOut := filepath.Join(outDir, "state")
	if err := d.createSnapshotArtifacts(context.Background(), client, runDir, memOut, stateOut); err == nil || !strings.Contains(err.Error(), "copy snapshot memory") {
		t.Fatalf("jailer copy failure: got %v", err)
	}
}

func TestCreate_SnapshotTemplatePlaceholderOverlay(t *testing.T) {
	f := newDriverFixture(t)
	rootfs := filepath.Join(t.TempDir(), "rootfs.ext4")
	mem, state, _ := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	if err := os.WriteFile(rootfs, []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: true, hasOverlay: true,
		snapshotMemoryPath: mem, snapshotStatePath: state, snapshotVsockCID: 200,
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-overlay-ph",
	}, "sb-snap-ph", "tok", nil); err != nil {
		t.Fatalf("snapshot placeholder overlay: %v", err)
	}
}

func TestSnapshotTemplate_InvalidVMMID(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = f.kernel
	_, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: strings.Repeat("x", 200),
		RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 10,
	})
	// Oversized template IDs are rejected either as invalid IDs or via the
	// VMM sandbox-ID length cap (template id becomes the VMM id).
	if err == nil || (!strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "exceeds 128")) {
		t.Fatalf("invalid template id: got %v", err)
	}
}

func TestSendVsockOp_HappyPathDiscardsAck(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{conns: []*errVsockConn{{reply: []byte(`{"ok":true}` + "\n")}}}}
	if err := d.sendVsockOp(context.Background(), "/tmp/vsock.sock", 3, "post_resume", map[string]string{"ip": "10.0.0.2"}); err != nil {
		t.Fatalf("sendVsockOp: %v", err)
	}
}

func TestCreateSnapshotArtifacts_JailerStateCopyFailure(t *testing.T) {
	runDir := t.TempDir()
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	client.snapshotBase = runDir
	memOut := filepath.Join(t.TempDir(), "mem")
	stateDir := filepath.Join(t.TempDir(), "state-dir")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stateOut := stateDir
	if err := d.createSnapshotArtifacts(context.Background(), client, runDir, memOut, stateOut); err == nil || !strings.Contains(err.Error(), "copy snapshot state") {
		t.Fatalf("state copy failure: got %v", err)
	}
}
