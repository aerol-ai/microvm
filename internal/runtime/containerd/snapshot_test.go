package containerd

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	cntr "github.com/containerd/containerd"
)

func TestSplitSnapshotImageRef(t *testing.T) {
	repo, tag, err := splitSnapshotImageRef("ghcr.io/org/app:v1")
	if err != nil || repo != "ghcr.io/org/app" || tag != "v1" {
		t.Fatalf("got %q %q err=%v", repo, tag, err)
	}
	if _, _, err := splitSnapshotImageRef("bad@sha256:abc"); err == nil {
		t.Fatal("digest should be rejected")
	}
}

func TestFormatSnapshotImageRefAddsLatest(t *testing.T) {
	got, err := formatSnapshotImageRef("local/snap")
	if err != nil || got != "local/snap:latest" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestCreateSnapshotValidation(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.CreateSnapshot(context.Background(), "", "snap:v1"); err == nil {
		t.Fatal("want container ref error")
	}
	if _, err := d.CreateSnapshot(context.Background(), "sb-1", ""); err == nil {
		t.Fatal("want image ref error")
	}
	d = newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["sb-1"] = &fakeContainer{id: "sb-1", task: &fakeTask{status: cntr.Running}}
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.CreateSnapshot(context.Background(), "sb-1", "snap:v1")
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateSnapshotFakeCommitHook(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	orig := snapshotCommitFn
	snapshotCommitFn = func(_ *Driver, _ context.Context, _ *Client, _, imageRef string) (string, error) {
		return "sha256:deadbeef", nil
	}
	t.Cleanup(func() { snapshotCommitFn = orig })

	got, err := d.CreateSnapshot(context.Background(), "sb-1", "snap:v1")
	if err != nil || got != "sha256:deadbeef" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestContainerdRuntimeNameRunsc(t *testing.T) {
	if got := containerdRuntimeName("runsc"); got != runscShimName {
		t.Fatalf("got %q", got)
	}
	if got := containerdRuntimeName(models.RuntimeDocker); got != models.RuntimeDocker {
		t.Fatalf("got %q", got)
	}
}

func TestEnsureRunscConfigWritesHostUDS(t *testing.T) {
	tmp := t.TempDir()
	d := New(Config{RunDir: tmp}, nil, nil)
	path, err := d.ensureRunscConfig()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `host-uds = "open"`) {
		t.Fatalf("config=%q", body)
	}
	opt, err := d.runscRuntimeOpts()
	if err != nil {
		t.Fatal(err)
	}
	ro, ok := opt.(*runscShimOptions)
	if !ok || ro.ConfigPath != path {
		t.Fatalf("opts=%T %+v", opt, opt)
	}
}

func TestPinImageLeaseNoOpOnFakeClient(t *testing.T) {
	d := newTestDriver(t)
	id, err := d.pinImageLease(context.Background(), d.client, &fakeImage{name: "alpine:3.20"})
	if err != nil || id != "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}
