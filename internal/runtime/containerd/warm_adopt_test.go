package containerd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
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

func TestPoolEligibleDisqualifiers(t *testing.T) {
	base := models.CreateSandboxRequest{Image: "alpine:3.20"}
	cases := []models.CreateSandboxRequest{
		{Image: "alpine:3.20", Mounts: []models.MountSpec{{}}},
		{Image: "alpine:3.20", OSUser: "nobody"},
		{Image: "alpine:3.20", ContainerCommand: []string{"sh"}},
		{Image: "alpine:3.20", Registry: &models.RegistryAuth{Username: "u"}},
		{Image: "alpine:3.20", GPUs: &models.GPURequest{Count: 1}},
		{Image: ""},
	}
	for i, req := range cases {
		if poolEligible(req, nil) {
			t.Fatalf("case %d should be ineligible: %+v", i, req)
		}
	}
	if poolEligible(base, []mounts.ContainerBind{{HostPath: "/x", ContainerPath: "/y"}}) {
		t.Fatal("host mounts should disqualify")
	}
	if !poolEligible(base, nil) {
		t.Fatal("base should be eligible")
	}
}

func TestTryWarmAdoptMissRecordsTiming(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	p := containerdpool.New(nil)
	d.SetWarmPool(p)
	ctx, timing := createtiming.With(context.Background())
	_, err := d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, containerdpool.ErrNoSlot) {
		t.Fatalf("err=%v", err)
	}
	stages := timing.Stages()
	found := false
	for _, st := range stages {
		if st.Name == "containerd_pool" && st.Desc == "miss" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stages=%v want containerd_pool miss", stages)
	}
}

func TestTryWarmAdoptHitRecordsTiming(t *testing.T) {
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
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9",
		ImageID: "sha256:img", Key: key, Handle: &fakeHandle{alive: true},
	})
	ctx, timing := createtiming.With(context.Background())
	_, err := d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-warm2", "tok", nil, models.RuntimeDocker)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, st := range timing.Stages() {
		if st.Name == "containerd_pool" && st.Desc == "hit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stages=%v want hit", timing.Stages())
	}
}

func TestRemoveImageEmptyAndStub(t *testing.T) {
	d := newTestDriver(t)
	if err := d.RemoveImage(context.Background(), "  "); err != nil {
		t.Fatal(err)
	}
	orig := removeImageFn
	removeImageFn = func(context.Context, *Client, string) error { return nil }
	t.Cleanup(func() { removeImageFn = orig })
	if err := d.RemoveImage(context.Background(), "alpine:3.20"); err != nil {
		t.Fatal(err)
	}
}

func TestCreateUsesWarmAdopt(t *testing.T) {
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
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9",
		ImageID: "sha256:img", Key: key, Handle: &fakeHandle{alive: true},
	})
	state, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeDocker,
	}, "sb-via-create", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.AdoptedParkID != "park-1" || state.ContainerID != "park-1" {
		t.Fatalf("state=%+v", state)
	}
}

func TestAdoptParkedAlreadyBound(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{
		id: "park-1",
		labels: map[string]string{
			poolParkLabelKey:  poolParkLabelValue,
			sandboxIDLabelKey: "sb-already",
		},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	state, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-already", "tok", &containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9",
		Handle: &fakeHandle{alive: true},
	})
	if err != nil || state.SandboxID != "sb-already" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestAdoptParkedIncompleteSlot(t *testing.T) {
	d := newTestDriver(t)
	if _, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", nil); err == nil {
		t.Fatal("want incomplete error")
	}
	if _, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", &containerdpool.ParkedSlot{ID: "x"}); err == nil {
		t.Fatal("want incomplete error")
	}
}
