package mounts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeRemote is the root helper's mount calls, in memory.
type fakeRemote struct {
	mu    sync.Mutex
	calls []string
	keep  []string
	err   error
	ready error
	had   bool
}

func (f *fakeRemote) Mount(_ context.Context, id string, mode RemoteMode, specs []models.MountSpec) (RemoteResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Mount "+id+" "+strings.Repeat("+", int(mode)))
	if f.err != nil {
		return RemoteResult{}, f.err
	}
	var res RemoteResult
	for _, s := range specs {
		res.Binds = append(res.Binds, ContainerBind{HostPath: "/h/" + id, ContainerPath: s.Target})
	}
	if mode == RemoteKeepLive {
		res.Report = KeepReport{Kept: []int{0}}
	}
	return res, nil
}

func (f *fakeRemote) Unmount(_ context.Context, id string, discard bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if discard {
		f.calls = append(f.calls, "Discard "+id)
	} else {
		f.calls = append(f.calls, "Unmount "+id)
	}
	return f.had, f.err
}

func (f *fakeRemote) Sweep(_ context.Context, keep []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Sweep")
	f.keep = keep
	return f.err
}

func (f *fakeRemote) Ready() error { return f.ready }

func remoteSpecs() []models.MountSpec {
	return []models.MountSpec{{Type: models.MountTypeNFS, Target: "/share", Source: "h:/e"}}
}

func newRemoteManager(t *testing.T, r Remote, off string) *Manager {
	t.Helper()
	m, err := NewRemote(slog.New(slog.NewTextHandler(io.Discard, nil)), r, off)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestRemoteManager: in privilege mode split every call is one call to the
// helper; sandboxd keeps only the last binds, for HostBindsFor.
func TestRemoteManager(t *testing.T) {
	f := &fakeRemote{had: true}
	m := newRemoteManager(t, f, "")
	ctx := context.Background()
	if binds, err := m.MountAll(ctx, "sb-1", nil); binds != nil || err != nil {
		t.Fatalf("no mounts: %v %v", binds, err)
	}
	binds, err := m.MountAll(ctx, "sb-1", remoteSpecs())
	if err != nil || len(binds) != 1 || binds[0].HostPath != "/h/sb-1" {
		t.Fatalf("%+v %v", binds, err)
	}
	if got := m.HostBindsFor("sb-1"); !slices.Equal(got, binds) {
		t.Fatalf("HostBindsFor %+v", got)
	}
	if err := m.Reestablish(ctx, "sb-1", remoteSpecs()); err != nil {
		t.Fatal(err)
	}
	if err := m.Reestablish(ctx, "sb-1", nil); err != nil {
		t.Fatal(err)
	}
	if r, err := m.KeepLive(ctx, "sb-1", remoteSpecs()); err != nil || !slices.Equal(r.Kept, []int{0}) {
		t.Fatalf("KeepLive %+v %v", r, err)
	}
	if err := m.UnmountAll("sb-1"); err != nil {
		t.Fatal(err)
	}
	if len(m.HostBindsFor("sb-1")) != 0 {
		t.Fatal("binds kept after the unmount")
	}
	if !m.Discard("sb-2") {
		t.Fatal("Discard")
	}
	m.Sweep(map[string]struct{}{"sb-2": {}, "sb-1": {}, "a/b": {}})
	if !slices.Equal(f.keep, []string{"sb-1", "sb-2"}) {
		t.Fatalf("keep %v", f.keep)
	}
	want := []string{"Mount sb-1 +", "Mount sb-1 ++", "Mount sb-1 +++", "Unmount sb-1", "Discard sb-2", "Sweep"}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls %v, want %v", f.calls, want)
	}
	// An ID the helper would refuse is never sent; nothing was mounted
	// under it.
	if _, err := m.MountAll(ctx, "../x", remoteSpecs()); err == nil {
		t.Fatal("a bad ID passed")
	}
	if err := m.UnmountAll("../x"); err != nil || m.Discard("../x") || len(f.calls) != len(want) {
		t.Fatalf("bad ID unmount: %v %v", err, f.calls)
	}
	m.Close()
}

func TestRemoteManagerFailures(t *testing.T) {
	f := &fakeRemote{err: errors.New("helper down")}
	m := newRemoteManager(t, f, "")
	if _, err := m.MountAll(context.Background(), "sb-1", remoteSpecs()); err == nil {
		t.Fatal("MountAll")
	}
	if len(m.HostBindsFor("sb-1")) != 0 {
		t.Fatal("binds from a failed call")
	}
	if m.Discard("sb-1") {
		t.Fatal("Discard")
	}
	m.Sweep(nil) // logged
	if _, err := m.MountAll(WithConsumer(context.Background(), Consumer{UID: 9, GID: 9}), "sb-1", remoteSpecs()); err == nil ||
		!strings.Contains(err.Error(), "WASM") {
		t.Fatalf("consumer: %v", err)
	}

	off := newRemoteManager(t, &fakeRemote{}, "the node says no")
	if _, err := off.MountAll(context.Background(), "sb-1", remoteSpecs()); !errors.Is(err, ErrMountsUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
	notReady := newRemoteManager(t, &fakeRemote{ready: errors.New("no mount user")}, "")
	if err := notReady.Available(); !errors.Is(err, ErrMountsUnavailable) || !strings.Contains(err.Error(), "no mount user") {
		t.Fatalf("not ready: %v", err)
	}
	if err := notReady.Reestablish(context.Background(), "sb-1", remoteSpecs()); !errors.Is(err, ErrMountsUnavailable) {
		t.Fatalf("not ready reestablish: %v", err)
	}
	if _, err := NewRemote(nil, &fakeRemote{}, ""); err == nil {
		t.Fatal("no logger")
	}
	if _, err := NewRemote(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, ""); err == nil {
		t.Fatal("no remote")
	}
}
