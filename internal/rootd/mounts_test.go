package rootd

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// fakeMounts records what the helper asks of the mount manager.
type fakeMounts struct {
	mu      sync.Mutex
	calls   []string
	specs   []models.MountSpec
	keep    map[string]struct{}
	err     error
	report  mounts.KeepReport
	had     bool
	closed  bool
	binds   []mounts.ContainerBind
	blockOn chan struct{}
}

func (f *fakeMounts) record(call string, specs []models.MountSpec) error {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	if specs != nil {
		f.specs = specs
	}
	block := f.blockOn
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	return f.err
}

func (f *fakeMounts) MountAll(_ context.Context, id string, specs []models.MountSpec) ([]mounts.ContainerBind, error) {
	if err := f.record("MountAll "+id, specs); err != nil {
		return nil, err
	}
	return f.bindsFor(id, specs), nil
}

func (f *fakeMounts) bindsFor(id string, specs []models.MountSpec) []mounts.ContainerBind {
	if f.binds != nil {
		return f.binds
	}
	var out []mounts.ContainerBind
	for i, s := range specs {
		out = append(out, mounts.ContainerBind{HostPath: fmt.Sprintf("/m/%s/%d", id, i), ContainerPath: s.Target, ReadOnly: s.ReadOnly})
	}
	return out
}

func (f *fakeMounts) Reestablish(_ context.Context, id string, specs []models.MountSpec) error {
	return f.record("Reestablish "+id, specs)
}

func (f *fakeMounts) KeepLive(_ context.Context, id string, specs []models.MountSpec) (mounts.KeepReport, error) {
	return f.report, f.record("KeepLive "+id, specs)
}

func (f *fakeMounts) HostBindsFor(id string) []mounts.ContainerBind {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bindsFor(id, f.specs)
}

func (f *fakeMounts) UnmountAll(id string) error { return f.record("UnmountAll "+id, nil) }

func (f *fakeMounts) Discard(id string) bool {
	_ = f.record("Discard "+id, nil)
	return f.had
}

func (f *fakeMounts) Sweep(keep map[string]struct{}) {
	_ = f.record("Sweep", nil)
	f.mu.Lock()
	f.keep = maps.Clone(keep)
	f.mu.Unlock()
}

func (f *fakeMounts) Close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func (f *fakeMounts) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// mountSecret is a credential no answer or refusal may carry.
const mountSecret = "s3cr3t-never-in-a-log"

func wireMount(m models.MountSpec) *rootdpb.ExternalMount {
	return &rootdpb.ExternalMount{Type: string(m.Type), Target: m.Target, Source: m.Source, Options: m.Options,
		ReadOnly: m.ReadOnly, Credentials: m.Credentials}
}

func goodWireMounts() []*rootdpb.ExternalMount {
	return []*rootdpb.ExternalMount{
		wireMount(models.MountSpec{Type: models.MountTypeNFS, Target: "/share", Source: "10.0.0.9:/export", Options: map[string]string{"opts": "vers=4.1"}}),
		wireMount(models.MountSpec{Type: models.MountTypeS3, Target: "/data", Source: "bucket", ReadOnly: true,
			Options:     map[string]string{"endpoint": "http://10.0.0.5:9000", "extra_args": "--force-path-style"},
			Credentials: map[string]string{"access_key_id": "minio", "secret_access_key": mountSecret}}),
	}
}

func mountRig(t *testing.T) (*rig, *fakeMounts, rootdpb.RootHelperClient) {
	t.Helper()
	fm := &fakeMounts{}
	r := newRig(t, func(_ *Config, o *Options) { o.Mounts = fm })
	return r, fm, rootdpb.NewRootHelperClient(r.conn)
}

func TestMountExternalModes(t *testing.T) {
	r, fm, c := mountRig(t)
	ctx := callCtx(t)
	resp, err := c.MountExternal(ctx, &rootdpb.MountExternalRequest{SandboxId: "sb-1",
		Mode: rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE, Mounts: goodWireMounts()})
	if err != nil {
		t.Fatal(err)
	}
	want := []*rootdpb.MountBind{{HostPath: "/m/sb-1/0", Target: "/share"}, {HostPath: "/m/sb-1/1", Target: "/data", ReadOnly: true}}
	if len(resp.GetBinds()) != 2 || !proto.Equal(resp.GetBinds()[0], want[0]) || !proto.Equal(resp.GetBinds()[1], want[1]) {
		t.Fatalf("binds %v", resp.GetBinds())
	}
	if got := fm.specs[1].Credentials["secret_access_key"]; got != mountSecret {
		t.Fatalf("the manager got credentials %q", got)
	}
	if _, err := c.MountExternal(ctx, &rootdpb.MountExternalRequest{SandboxId: "sb-1",
		Mode: rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_REESTABLISH, Mounts: goodWireMounts()}); err != nil {
		t.Fatal(err)
	}
	fm.report = mounts.KeepReport{Kept: []int{1}, Gone: []int{0}}
	// A running mount may keep a flag a create may not use.
	kept := goodWireMounts()
	kept[1].Options["extra_args"] = "--debug"
	resp, err = c.MountExternal(ctx, &rootdpb.MountExternalRequest{SandboxId: "sb-1",
		Mode: rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_KEEP_LIVE, Mounts: kept})
	if err != nil || !slices.Equal(resp.GetKept(), []uint32{1}) || !slices.Equal(resp.GetGone(), []uint32{0}) || resp.GetAlready() {
		t.Fatalf("keep live: %v %v", resp, err)
	}
	if got := fm.seen(); !slices.Equal(got, []string{"MountAll sb-1", "Reestablish sb-1", "KeepLive sb-1"}) {
		t.Fatalf("calls %v", got)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}

// TestMountExternalBrokenAgent: what a compromised agent could send instead
// of what its own code builds is refused by name, before the mount manager
// hears of it, and no refusal carries a credential.
func TestMountExternalBrokenAgent(t *testing.T) {
	create := rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE
	with := func(mutate func(m *rootdpb.ExternalMount)) []*rootdpb.ExternalMount {
		ms := goodWireMounts()
		mutate(ms[1])
		return ms
	}
	nfsWith := func(opts string) []*rootdpb.ExternalMount {
		ms := goodWireMounts()
		ms[0].Options["opts"] = opts
		return ms
	}
	for _, tc := range []struct {
		name   string
		req    *rootdpb.MountExternalRequest
		reason string
	}{
		{"a sandbox ID that climbs out of the mounts folder", &rootdpb.MountExternalRequest{SandboxId: "../etc", Mode: create, Mounts: goodWireMounts()}, string(rootpolicy.RuleExternalMount)},
		{"a sandbox ID that names another's folder", &rootdpb.MountExternalRequest{SandboxId: "sb-1/../sb-2", Mode: create, Mounts: goodWireMounts()}, string(rootpolicy.RuleExternalMount)},
		{"a sandbox ID that is a path", &rootdpb.MountExternalRequest{SandboxId: "/var/lib/x", Mode: create, Mounts: goodWireMounts()}, string(rootpolicy.RuleExternalMount)},
		{"no sandbox ID", &rootdpb.MountExternalRequest{Mode: create, Mounts: goodWireMounts()}, string(rootpolicy.RuleExternalMount)},
		{"no mode", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mounts: goodWireMounts()}, ReasonBadRequest},
		{"a mode the helper does not know", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: 99, Mounts: goodWireMounts()}, ReasonBadRequest},
		{"no mounts", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create}, string(rootpolicy.RuleExternalMount)},
		{"an NFS option off the list", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: nfsWith("vers=4,helper=/tmp/x")}, string(rootpolicy.RuleExternalMount)},
		{"NFS suid", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: nfsWith("suid,dev")}, string(rootpolicy.RuleExternalMount)},
		{"an extra_arg off the list", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Options["extra_args"] = "--log-directory=/etc"
		})}, string(rootpolicy.RuleExternalMount)},
		{"a credential in the arguments", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Options["extra_args"] = "--force-path-style --secret-access-key " + mountSecret
		})}, string(rootpolicy.RuleExternalMount)},
		{"a credential in the endpoint", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Options["endpoint"] = "https://minio:" + mountSecret + "@h"
		})}, string(rootpolicy.RuleExternalMount)},
		{"a credential no tool reads", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Credentials["aws_web_identity_token"] = mountSecret
		})}, string(rootpolicy.RuleExternalMount)},
		{"a source read as an option", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Type, m.Source, m.Options, m.Credentials = "sshfs", "-oProxyCommand=sh@h:/", nil, map[string]string{"private_key_pem": mountSecret}
		})}, string(rootpolicy.RuleExternalMount)},
		{"rclone's local backend", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Type, m.Source, m.Options, m.Credentials = "rclone", ":local:/etc", nil, map[string]string{"rclone_conf": "[x]\ntype = s3\n"}
		})}, string(rootpolicy.RuleExternalMount)},
		{"a mount over the sandbox's /proc", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Target = "/proc"
		})}, string(rootpolicy.RuleExternalMount)},
		{"a target that climbs", &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: with(func(m *rootdpb.ExternalMount) {
			m.Target = "/data/../../etc"
		})}, string(rootpolicy.RuleExternalMount)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, fm, c := mountRig(t)
			_, err := c.MountExternal(callCtx(t), tc.req)
			reason, refused := rootdpb.RefusalReason(err)
			if !refused || reason != tc.reason {
				t.Fatalf("got %v (refused %v, reason %q), want reason %q", err, refused, reason, tc.reason)
			}
			if strings.Contains(err.Error(), mountSecret) {
				t.Fatalf("the answer carries the credential: %v", err)
			}
			for _, ref := range r.refused() {
				if strings.Contains(ref.Detail, mountSecret) {
					t.Fatalf("the refusal record carries the credential: %v", ref)
				}
			}
			if len(fm.seen()) != 0 {
				t.Fatalf("the manager was asked: %v", fm.seen())
			}
		})
	}
	t.Run("too many mounts", func(t *testing.T) {
		_, fm, c := mountRig(t)
		many := slices.Repeat(goodWireMounts()[:1], models.MaxMountsPerSandbox+1)
		_, err := c.MountExternal(callCtx(t), &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: create, Mounts: many})
		if reason, _ := rootdpb.RefusalReason(err); reason != string(rootpolicy.RuleExternalMount) || len(fm.seen()) != 0 {
			t.Fatalf("%v", err)
		}
	})
}

// A field this helper does not know, in the request or in a mount, is a
// newer agent's narrowing: answered Unimplemented, never acted on, and no
// refusal (a version skew, not a broken agent).
func TestMountExternalUnknownFields(t *testing.T) {
	r, fm, c := mountRig(t)
	withUnknown := func(m proto.Message) {
		m.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	}
	req := &rootdpb.MountExternalRequest{SandboxId: "sb-1", Mode: rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE, Mounts: goodWireMounts()}
	withUnknown(req.Mounts[0])
	if _, err := c.MountExternal(callCtx(t), req); status.Code(err) != codes.Unimplemented {
		t.Fatalf("a mount with an unknown field: %v", err)
	}
	un := &rootdpb.UnmountExternalRequest{SandboxId: "sb-1"}
	withUnknown(un)
	if _, err := c.UnmountExternal(callCtx(t), un); status.Code(err) != codes.Unimplemented {
		t.Fatalf("an unmount with an unknown field: %v", err)
	}
	sw := &rootdpb.SweepExternalMountsRequest{}
	withUnknown(sw)
	if _, err := c.SweepExternalMounts(callCtx(t), sw); status.Code(err) != codes.Unimplemented {
		t.Fatalf("a sweep with an unknown field: %v", err)
	}
	if len(fm.seen()) != 0 || len(r.refused()) != 0 {
		t.Fatalf("calls %v refusals %v", fm.seen(), r.refused())
	}
}

// TestMountExternalFailures: each failure keeps a code of its own, so the
// agent answers as single mode does; only a folder that is not the
// helper's own is reported as a refusal.
func TestMountExternalFailures(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   codes.Code
		reason string
	}{
		{fmt.Errorf("mount sb-1: %w", mounts.ErrMountsEstablished), codes.AlreadyExists, ""},
		{fmt.Errorf("mount 0 (s3): %w", mounts.ErrMountToolUnavailable), codes.FailedPrecondition, ""},
		{fmt.Errorf("create sandbox mount dir: %w", mounts.ErrToolFolder), codes.PermissionDenied, ReasonMountFolder},
		{errors.New("mount 1 (s3): timed out waiting for mount (mount tool output: AccessDenied)"), codes.Unknown, ""},
	} {
		r, fm, c := mountRig(t)
		fm.err = tc.err
		_, err := c.MountExternal(callCtx(t), &rootdpb.MountExternalRequest{SandboxId: "sb-1",
			Mode: rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE, Mounts: goodWireMounts()})
		reason, _ := rootdpb.RefusalReason(err)
		if status.Code(err) != tc.code || reason != tc.reason || !strings.Contains(status.Convert(err).Message(), tc.err.Error()) {
			t.Errorf("%v: got %v (reason %q)", tc.err, err, reason)
		}
		if (len(r.refused()) != 0) != (tc.reason != "") {
			t.Errorf("%v: refusals %v", tc.err, r.refused())
		}
	}
}

func TestUnmountAndSweepExternal(t *testing.T) {
	r, fm, c := mountRig(t)
	ctx := callCtx(t)
	if _, err := c.UnmountExternal(ctx, &rootdpb.UnmountExternalRequest{SandboxId: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	fm.had = true
	resp, err := c.UnmountExternal(ctx, &rootdpb.UnmountExternalRequest{SandboxId: "sb-2", Discard: true})
	if err != nil || !resp.GetHad() {
		t.Fatalf("discard: %v %v", resp, err)
	}
	if _, err := c.SweepExternalMounts(ctx, &rootdpb.SweepExternalMountsRequest{Keep: []string{"sb-1", "sb-3"}}); err != nil {
		t.Fatal(err)
	}
	if got := fm.seen(); !slices.Equal(got, []string{"UnmountAll sb-1", "Discard sb-2", "Sweep"}) {
		t.Fatalf("calls %v", got)
	}
	if _, ok := fm.keep["sb-3"]; !ok || len(fm.keep) != 2 {
		t.Fatalf("keep %v", fm.keep)
	}
	// The same ID rule on every call: nothing under another name.
	if _, err := c.UnmountExternal(ctx, &rootdpb.UnmountExternalRequest{SandboxId: "../x"}); !refusedWith(err, string(rootpolicy.RuleExternalMount)) {
		t.Fatalf("unmount ../x: %v", err)
	}
	if _, err := c.SweepExternalMounts(ctx, &rootdpb.SweepExternalMountsRequest{Keep: []string{"sb-1", "a/b"}}); !refusedWith(err, string(rootpolicy.RuleExternalMount)) {
		t.Fatalf("sweep keeping a/b: %v", err)
	}
	if len(fm.seen()) != 3 || len(r.refused()) != 2 {
		t.Fatalf("calls %v refusals %v", fm.seen(), r.refused())
	}
	fm.err = errors.New("umount: device busy")
	if _, err := c.UnmountExternal(ctx, &rootdpb.UnmountExternalRequest{SandboxId: "sb-1"}); status.Code(err) != codes.Internal {
		t.Fatalf("a failed unmount: %v", err)
	}
}

func refusedWith(err error, reason string) bool {
	got, ok := rootdpb.RefusalReason(err)
	return ok && got == reason
}

// A helper with no mount user serves no mount call, and says so.
func TestMountCallsWithoutAMountUser(t *testing.T) {
	r := newRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	_, err1 := c.MountExternal(ctx, &rootdpb.MountExternalRequest{SandboxId: "sb-1"})
	_, err2 := c.UnmountExternal(ctx, &rootdpb.UnmountExternalRequest{SandboxId: "sb-1"})
	_, err3 := c.SweepExternalMounts(ctx, &rootdpb.SweepExternalMountsRequest{})
	for _, err := range []error{err1, err2, err3} {
		if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "SB_ROOTD_MOUNT_USER") {
			t.Fatalf("%v", err)
		}
	}
}

// Calls for one sandbox run one at a time (D11): an unmount waits for the
// mount in flight; another sandbox's does not.
func TestMountCallsForOneSandboxRunInOrder(t *testing.T) {
	_, fm, c := mountRig(t)
	fm.blockOn = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := c.MountExternal(callCtx(t), &rootdpb.MountExternalRequest{SandboxId: "sb-1",
			Mode: rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE, Mounts: goodWireMounts()})
		done <- err
	}()
	waitFor(t, func() bool { return len(fm.seen()) == 1 })
	other := make(chan error, 1)
	go func() {
		_, err := c.UnmountExternal(callCtx(t), &rootdpb.UnmountExternalRequest{SandboxId: "sb-2"})
		other <- err
	}()
	waitFor(t, func() bool { return len(fm.seen()) == 2 })
	same := make(chan error, 1)
	go func() {
		_, err := c.UnmountExternal(callCtx(t), &rootdpb.UnmountExternalRequest{SandboxId: "sb-1"})
		same <- err
	}()
	select {
	case err := <-same:
		t.Fatalf("the same sandbox's unmount ran beside its mount: %v", err)
	default:
	}
	close(fm.blockOn)
	for _, ch := range []chan error{done, other, same} {
		if err := <-ch; err != nil {
			t.Fatal(err)
		}
	}
	if got := fm.seen(); got[0] != "MountAll sb-1" || got[2] != "UnmountAll sb-1" {
		t.Fatalf("order %v", got)
	}
}

// The helper closes its mount manager when it stops: the supervisor goes,
// the mounts and their tools stay for the next helper to adopt.
func TestShutdownClosesTheMountManager(t *testing.T) {
	fm := &fakeMounts{}
	r := newRig(t, func(_ *Config, o *Options) { o.Mounts = fm })
	r.srv.Shutdown(callCtx(t))
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if !fm.closed {
		t.Fatal("not closed")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
