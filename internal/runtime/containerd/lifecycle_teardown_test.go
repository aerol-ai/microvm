package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cntr "github.com/containerd/containerd"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// digestImage returns a fake image with a non-empty content digest so
// pinImageLease reaches AddResource instead of erroring on an empty digest.
func digestImage() *fakeImage {
	return &fakeImage{
		name:   "alpine:3.20",
		target: ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("a", 64))},
	}
}

// TestCreateAlreadyExistsLoserPreservesWinnerResources is the regression for the
// review's top finding (A1≡B1 + A4): a retry / concurrent-duplicate Create that
// loses the AlreadyExists race must NOT tear down the winner's sandboxID-keyed
// resources (netns slot, host files), while still cleaning up its OWN orphan
// image lease.
func TestCreateAlreadyExistsLoserPreservesWinnerResources(t *testing.T) {
	stubToolboxProbe(t)
	lm := &fakeLeaseManager{}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	tr := newFakeTransport()
	tr.image = digestImage()
	// The winner already owns the container object → NewContainer(loser) returns
	// AlreadyExists.
	tr.containers["sb-dup"] = &fakeContainer{id: "sb-dup", labels: map[string]string{managedLabelKey: "true"}}

	h := &harnessNetns{path: "/run/netns/sb-dup", ip: "10.88.0.9"}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(h)
	d.cfg.NativeNetnsPool = true

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-dup", "tok", nil)
	if !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
		t.Fatalf("want ErrSandboxContainerExists, got %v", err)
	}
	if h.released {
		t.Fatal("AlreadyExists loser must NOT release the winner's netns slot")
	}
	// Winner's host files (keyed by sandboxID) must survive the loser's teardown.
	hostDir := filepath.Join(d.cfg.RunDir, "hosts", "sb-dup")
	if _, statErr := os.Stat(hostDir); statErr != nil {
		t.Fatalf("winner's host files must survive loser teardown: %v", statErr)
	}
	// The loser's own image lease (random id, distinct from the winner's) is an
	// orphan it must delete.
	if len(lm.created) != 1 || len(lm.deleted) != 1 || lm.deleted[0] != lm.created[0] {
		t.Fatalf("loser must release its own lease: created=%v deleted=%v", lm.created, lm.deleted)
	}
}

// TestCreatePreContainerFailureCleansOwnResources is the A4 regression: a genuine
// solo failure BEFORE NewContainer (here the lease pin fails) must still reap the
// host files and netns slot this call created — the prior createdContainer gate
// leaked both because the container object never existed.
func TestCreatePreContainerFailureCleansOwnResources(t *testing.T) {
	stubToolboxProbe(t)
	lm := &fakeLeaseManager{createErr: errors.New("lease create boom")}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	h := &harnessNetns{path: "/run/netns/sb-fail", ip: "10.88.0.9"}
	d := newTestDriver(t)
	d.SetNetnsHandoff(h)
	d.cfg.NativeNetnsPool = true

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-fail", "tok", nil)
	if err == nil {
		t.Fatal("want create failure at lease pin")
	}
	if !h.released {
		t.Fatal("solo failure must release the netns slot this call reserved")
	}
	hostDir := filepath.Join(d.cfg.RunDir, "hosts", "sb-fail")
	if _, statErr := os.Stat(hostDir); !os.IsNotExist(statErr) {
		t.Fatalf("solo failure must remove its host files, stat err = %v", statErr)
	}
}

// TestDestroyParkedReleasesNetnsAndLease is the B2 regression: parked-container
// teardown must release the netns slot AND the pinned image lease, or the netns
// pool leaks to exhaustion and image layers can never be GC'd.
func TestDestroyParkedReleasesNetnsAndLease(t *testing.T) {
	lm := &fakeLeaseManager{}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	tr := newFakeTransport()
	tr.containers["park-7"] = &fakeContainer{
		id: "park-7",
		labels: map[string]string{
			managedLabelKey:    "true",
			poolParkLabelKey:   poolParkLabelValue,
			imageLeaseLabelKey: "lease-park-7",
		},
		task: &fakeTask{status: cntr.Running},
	}
	h := &harnessNetns{path: "/run/netns/park-7", ip: "10.88.0.9"}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(h)

	if err := d.destroyParked(context.Background(), &containerdpool.ParkedSlot{
		ID:          "park-7",
		ContainerID: "park-7",
		ContainerIP: "10.88.0.9",
	}); err != nil {
		t.Fatal(err)
	}
	if !h.released {
		t.Fatal("destroyParked must release the park netns slot")
	}
	if len(lm.deleted) != 1 || lm.deleted[0] != "lease-park-7" {
		t.Fatalf("destroyParked must release the park image lease, deleted=%v", lm.deleted)
	}
}
