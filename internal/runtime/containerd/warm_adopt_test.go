package containerd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPoolEligible(t *testing.T) {
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	if !poolEligible(req, nil) {
		t.Fatal("default create should be eligible")
	}
	req.Env = map[string]string{"X": "1"}
	if poolEligible(req, nil) {
		t.Fatal("env should disqualify")
	}
}

func TestTryWarmAdoptMissWhenDisabled(t *testing.T) {
	d := New(Config{ReadyEnabled: false}, nil, nil)
	d.SetWarmPool(containerdpool.New(nil))
	_, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, containerdpool.ErrNoSlot) {
		t.Fatalf("err=%v", err)
	}
}

func TestTryWarmAdoptHappyPath(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)

	tr := newFakeTransport()
	parkC := &fakeContainer{id: "park-1", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}}
	tr.containers["park-1"] = parkC

	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(p)

	handle := &fakeHandle{alive: true}
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9",
		ImageID: "sha256:img", Key: key, Handle: handle,
	})

	state, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-warm", "tok", nil, models.RuntimeDocker)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if state.SandboxID != "sb-warm" || state.ContainerID != "park-1" || state.AdoptedParkID != "park-1" {
		t.Fatalf("state=%+v", state)
	}
	if parkC.labels[sandboxIDLabelKey] != "sb-warm" {
		t.Fatalf("labels=%v", parkC.labels)
	}
	if _, parked := parkC.labels[poolParkLabelKey]; parked {
		t.Fatal("park label should be removed")
	}
}

func TestTryWarmAdoptAdoptFailsBadHandle(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ImageID: "img", Key: key, Handle: &fakeHandle{alive: true},
	})
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetWarmPool(p)
	_, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-warm", "tok", nil, models.RuntimeDocker)
	if err == nil || !strings.Contains(err.Error(), "warm adopt failed") {
		t.Fatalf("err=%v", err)
	}
}

type fakeHandle struct{ alive bool }

func (f *fakeHandle) Alive() bool                                         { return f.alive }
func (f *fakeHandle) Adopt(context.Context, string, string, string) error { return nil }
func (f *fakeHandle) Close() error                                        { return nil }

func TestIsParkedLabels(t *testing.T) {
	if !IsParkedContainerLabels(map[string]string{poolParkLabelKey: poolParkLabelValue}) {
		t.Fatal("expected parked")
	}
	if IsParkedSandboxID("park-deadbeef") != true {
		t.Fatal("expected park id")
	}
}
