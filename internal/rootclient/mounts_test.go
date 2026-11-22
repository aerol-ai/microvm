package rootclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// helperMounts is the helper's mount manager in these tests: it records
// what reaches root, and answers with what err and report say.
type helperMounts struct {
	mu     sync.Mutex
	calls  []string
	specs  []models.MountSpec
	keep   map[string]struct{}
	err    error
	report mounts.KeepReport
}

func (h *helperMounts) note(call string, specs []models.MountSpec) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, call)
	if specs != nil {
		h.specs = specs
	}
	return h.err
}

func (h *helperMounts) binds(id string) []mounts.ContainerBind {
	var out []mounts.ContainerBind
	for i, s := range h.specs {
		out = append(out, mounts.ContainerBind{HostPath: fmt.Sprintf("/var/lib/aerolvm-rootd/mounts/%s/%d", id, i), ContainerPath: s.Target, ReadOnly: s.ReadOnly})
	}
	return out
}

func (h *helperMounts) MountAll(_ context.Context, id string, specs []models.MountSpec) ([]mounts.ContainerBind, error) {
	if err := h.note("MountAll "+id, specs); err != nil {
		return nil, err
	}
	return h.binds(id), nil
}

func (h *helperMounts) Reestablish(_ context.Context, id string, specs []models.MountSpec) error {
	return h.note("Reestablish "+id, specs)
}

func (h *helperMounts) KeepLive(_ context.Context, id string, specs []models.MountSpec) (mounts.KeepReport, error) {
	return h.report, h.note("KeepLive "+id, specs)
}

func (h *helperMounts) HostBindsFor(id string) []mounts.ContainerBind {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.binds(id)
}

func (h *helperMounts) UnmountAll(id string) error { return h.note("UnmountAll "+id, nil) }
func (h *helperMounts) Discard(id string) bool     { return h.note("Discard "+id, nil) == nil }
func (h *helperMounts) Sweep(keep map[string]struct{}) {
	_ = h.note("Sweep", nil)
	h.mu.Lock()
	h.keep = keep
	h.mu.Unlock()
}
func (h *helperMounts) Close() {}

func (h *helperMounts) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

const clientSecret = "client-s3cr3t"

func clientSpecs() []models.MountSpec {
	return []models.MountSpec{
		{Type: models.MountTypeS3, Target: "/data", Source: "bucket", ReadOnly: true,
			Options: map[string]string{"endpoint": "http://10.0.0.5:9000", "extra_args": "--force-path-style"},
			// session_name is no key mount-s3 reads: it stays with the agent.
			Credentials: map[string]string{"access_key_id": "minio", "secret_access_key": clientSecret, "session_name": "x"}},
		{Type: models.MountTypeNFS, Target: "/share", Source: "10.0.0.9:/export", Credentials: map[string]string{"password": "unused"}},
	}
}

// remoteManager is sandboxd's Manager in privilege mode split, sending
// every call to a real helper server whose mount manager is hm.
func remoteManager(t *testing.T, hm *helperMounts) (*mounts.Manager, *Client) {
	t.Helper()
	sock := sockPath(t)
	realHelper(t, sock, func(o *rootd.Options) { o.Mounts = hm })
	c := newClient(t, sock)
	m, err := mounts.NewRemote(slog.New(slog.NewTextHandler(io.Discard, nil)), Mounts{Client: func() *Client { return c }}, "")
	if err != nil {
		t.Fatal(err)
	}
	return m, c
}

// TestRemoteMountsThroughTheHelper: the service's calls on the split
// Manager reach the helper's mount manager, one helper call each, with
// only the credentials a tool reads, and its answers come back as single
// mode's.
func TestRemoteMountsThroughTheHelper(t *testing.T) {
	hm := &helperMounts{}
	m, _ := remoteManager(t, hm)
	ctx := ctxT(t)
	binds, err := m.MountAll(ctx, "sb-1", clientSpecs())
	if err != nil {
		t.Fatal(err)
	}
	if len(binds) != 2 || binds[0].HostPath != "/var/lib/aerolvm-rootd/mounts/sb-1/0" || !binds[0].ReadOnly || binds[1].ContainerPath != "/share" {
		t.Fatalf("binds %+v", binds)
	}
	if got := hm.specs[0].Credentials; len(got) != 2 || got["secret_access_key"] != clientSecret {
		t.Fatalf("the helper got credentials %v", got)
	}
	if len(hm.specs[1].Credentials) != 0 {
		t.Fatalf("NFS reads no credentials, the helper got %v", hm.specs[1].Credentials)
	}
	if got := m.HostBindsFor("sb-1"); !slices.Equal(got, binds) {
		t.Fatalf("HostBindsFor %+v", got)
	}
	if err := m.Reestablish(ctx, "sb-1", clientSpecs()); err != nil {
		t.Fatal(err)
	}
	hm.report = mounts.KeepReport{Kept: []int{0}, Gone: []int{1}}
	report, err := m.KeepLive(ctx, "sb-1", clientSpecs())
	if err != nil || !slices.Equal(report.Kept, []int{0}) || !slices.Equal(report.Gone, []int{1}) {
		t.Fatalf("KeepLive %+v %v", report, err)
	}
	if err := m.UnmountAll("sb-1"); err != nil {
		t.Fatal(err)
	}
	if got := m.HostBindsFor("sb-1"); len(got) != 0 {
		t.Fatalf("binds after the unmount: %+v", got)
	}
	if !m.Discard("sb-2") {
		t.Fatal("Discard said there was nothing")
	}
	m.Sweep(map[string]struct{}{"sb-1": {}, "../bad": {}})
	want := []string{"MountAll sb-1", "Reestablish sb-1", "KeepLive sb-1", "UnmountAll sb-1", "Discard sb-2", "Sweep"}
	if got := hm.seen(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
	if _, ok := hm.keep["sb-1"]; !ok || len(hm.keep) != 1 {
		t.Fatalf("keep %v: an ID the helper would refuse is not sent", hm.keep)
	}
	if err := m.Available(); err != nil {
		t.Fatal(err)
	}
}

// What the helper would refuse is the caller's error here, and never
// sent: a refusal is a security event, and the caller's typo is not one.
func TestRemoteMountsCheckBeforeSending(t *testing.T) {
	hm := &helperMounts{}
	m, _ := remoteManager(t, hm)
	bad := clientSpecs()
	bad[1].Options = map[string]string{"opts": "vers=4,helper=/bin/sh"}
	_, err := m.MountAll(ctxT(t), "sb-1", bad)
	var refused *RefusedError
	if err == nil || errors.As(err, &refused) || !strings.Contains(err.Error(), "helper") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), clientSecret) {
		t.Fatalf("the error carries a credential: %v", err)
	}
	if len(hm.seen()) != 0 {
		t.Fatalf("sent: %v", hm.seen())
	}
	if _, err := m.MountAll(ctxT(t), "../x", clientSpecs()); err == nil || len(hm.seen()) != 0 {
		t.Fatalf("a bad ID: %v", err)
	}
	ctx := mounts.WithConsumer(ctxT(t), mounts.Consumer{UID: 5000, GID: 5000})
	if _, err := m.MountAll(ctx, "sb-1", clientSpecs()); err == nil || len(hm.seen()) != 0 {
		t.Fatalf("a WASM consumer: %v", err)
	}
}

// TestRemoteMountErrors: the helper's answers become single mode's errors,
// so the API answers as it did.
func TestRemoteMountErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want error
		text string
	}{
		{fmt.Errorf("mount sb-1: %w", mounts.ErrMountsEstablished), mounts.ErrMountsEstablished, "already established"},
		{fmt.Errorf("spawn: %w", mounts.ErrMountToolUnavailable), mounts.ErrMountToolUnavailable, "not installed"},
		{errors.New("mount 0 (s3): mount tool output: AccessDenied"), nil, "AccessDenied"},
		{fmt.Errorf("create sandbox mount dir: %w", mounts.ErrToolFolder), ErrRefused, "folder"},
	} {
		hm := &helperMounts{err: tc.err}
		m, _ := remoteManager(t, hm)
		_, err := m.MountAll(ctxT(t), "sb-1", clientSpecs())
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%v: got %v", tc.err, err)
		}
		if tc.want == nil && (strings.Contains(err.Error(), "rpc error") || errors.Is(err, ErrUnavailable)) {
			t.Errorf("%v: not plain text: %v", tc.err, err)
		}
	}
	hm := &helperMounts{err: errors.New("umount: busy")}
	m, _ := remoteManager(t, hm)
	if err := m.UnmountAll("sb-1"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("unmount: %v", err)
	}
	if m.Discard("sb-1") {
		t.Fatal("a failed discard said it tore something down")
	}
}

// A helper with no mount user lists no mount call: the node refuses
// external storage by name (501 mounts_unavailable), and a call says why.
func TestRemoteMountsHelperWithoutMounts(t *testing.T) {
	sock := sockPath(t)
	realHelper(t, sock, nil)
	c := newClient(t, sock)
	r := Mounts{Client: func() *Client { return c }}
	if err := r.Ready(); err != nil {
		t.Fatalf("before the handshake: %v", err)
	}
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(); err == nil || !strings.Contains(err.Error(), "SB_ROOTD_MOUNT_USER") {
		t.Fatalf("Ready = %v", err)
	}
	m, err := mounts.NewRemote(slog.New(slog.NewTextHandler(io.Discard, nil)), r, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Available(); !errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("Available = %v", err)
	}
	if _, err := r.Mount(ctxT(t), "sb-1", mounts.RemoteCreate, clientSpecs()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Mount = %v", err)
	}
}

// No client yet (the daemon sets it after the service exists): every call
// is ErrUnavailable, and nothing panics.
func TestRemoteMountsBeforeTheClient(t *testing.T) {
	for _, r := range []Mounts{{}, {Client: func() *Client { return nil }}} {
		if err := r.Ready(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Mount(context.Background(), "sb-1", mounts.RemoteCreate, clientSpecs()); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if _, err := r.Unmount(context.Background(), "sb-1", false); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
		if err := r.Sweep(context.Background(), nil); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if _, err := (Mounts{Client: func() *Client { return New(Config{}) }}).Mount(context.Background(), "sb-1", 0, nil); err == nil {
		t.Fatal("an unknown mode passed")
	}
}

// A mount call is bounded by the mount timeout, not the 2 s of the others:
// a mount set waits for its tools.
func TestMountCallsGetTheMountTimeout(t *testing.T) {
	c := New(Config{MountTimeout: 3 * time.Minute})
	for _, f := range []string{rootdpb.FeatureMountExternal, rootdpb.FeatureUnmountExternal, rootdpb.FeatureSweepExternalMounts} {
		ctx, cancel := c.callContext(context.Background(), f)
		dl, ok := ctx.Deadline()
		cancel()
		if !ok || time.Until(dl) < 2*time.Minute {
			t.Fatalf("%s: deadline in %v", f, time.Until(dl))
		}
	}
	if d := New(Config{}).mountTimeout; d != DefaultMountTimeout {
		t.Fatalf("default %v", d)
	}
	if onlyReadCredentials(models.MountTypeNFS, map[string]string{"x": "y"}) != nil || onlyReadCredentials(models.MountTypeS3, nil) != nil {
		t.Fatal("onlyReadCredentials")
	}
	if mountErr(nil) != nil || !errors.Is(mountErr(context.Canceled), context.Canceled) {
		t.Fatal("mountErr")
	}
}
