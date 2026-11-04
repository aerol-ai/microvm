package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// envCanary stands in for a secret. It must reach the guest through set_env
// and nowhere else: not a rootfs file, not a log line, not an error.
const envCanary = "bank-canary-5c1e9d"

// opVsockDialer fakes the guest agent per op: it decodes each line the
// driver writes and answers with reply(op, nth) (nth counts that op from 1).
// "" means {"ok":true}; "EOF" closes the conn without an ack, as a guest
// whose ack was lost would.
type opVsockDialer struct {
	mu       sync.Mutex
	ops      []string
	payloads map[string][]json.RawMessage
	cids     []uint32
	reply    func(op string, nth int) string
	dialErr  func(dial int) error
	dials    int
}

func newOpVsockDialer() *opVsockDialer {
	return &opVsockDialer{payloads: map[string][]json.RawMessage{}}
}

func (d *opVsockDialer) Dial(_ context.Context, _ string, cid, _ uint32) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials++
	if d.dialErr != nil {
		if err := d.dialErr(d.dials); err != nil {
			return nil, err
		}
	}
	d.cids = append(d.cids, cid)
	return &opVsockConn{parent: d}, nil
}

func (d *opVsockDialer) opList() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.ops)
}

func (d *opVsockDialer) envPushes(t *testing.T) []map[string]string {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []map[string]string
	for _, raw := range d.payloads[guestEnvOp] {
		var data struct {
			Env map[string]string `json:"env"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			t.Fatalf("decode set_env payload: %v", err)
		}
		out = append(out, data.Env)
	}
	return out
}

type opVsockConn struct {
	parent *opVsockDialer
	reply  *bytes.Reader
	closed bool
}

func (c *opVsockConn) Write(p []byte) (int, error) {
	var msg struct {
		Op   string          `json:"op"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(p), &msg); err != nil {
		return 0, err
	}
	d := c.parent
	d.mu.Lock()
	d.ops = append(d.ops, msg.Op)
	d.payloads[msg.Op] = append(d.payloads[msg.Op], msg.Data)
	nth := len(d.payloads[msg.Op])
	answer := ""
	if d.reply != nil {
		answer = d.reply(msg.Op, nth)
	}
	d.mu.Unlock()
	switch {
	case answer == "":
		answer = `{"ok":true}` + "\n"
	case answer == "EOF":
		answer = ""
	case !strings.HasSuffix(answer, "\n"):
		answer += "\n"
	}
	c.reply = bytes.NewReader([]byte(answer))
	return len(p), nil
}

func (c *opVsockConn) Read(p []byte) (int, error) {
	if c.closed || c.reply == nil {
		return 0, io.EOF
	}
	return c.reply.Read(p)
}

func (c *opVsockConn) Close() error { c.closed = true; return nil }

// injectRecordingRootfs records the files the driver bakes into a cold-boot
// rootfs, so a test can prove the env is not among them.
type injectRecordingRootfs struct {
	fakeRootfs
	inject []InjectFile
}

func (b *injectRecordingRootfs) Build(ctx context.Context, req RootfsBuildRequest) (*RootfsResult, error) {
	b.mu.Lock()
	b.inject = append(b.inject, req.InjectFiles...)
	b.mu.Unlock()
	return b.fakeRootfs.Build(ctx, req)
}

// lockedBuffer is a log sink safe to read while the driver's background
// goroutines (the toolbox TCP probe) may still be writing.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// envFixture is newDriverFixture with the per-op guest fake, a recording
// rootfs builder, a configured toolbox binary (so the agent files are
// injected as in production) and a captured logger.
func envFixture(t *testing.T) (*driverFixture, *opVsockDialer, *injectRecordingRootfs, *lockedBuffer) {
	t.Helper()
	f := newDriverFixture(t)
	vsock := newOpVsockDialer()
	f.driver.SetVsockDialer(vsock)
	rootfs := &injectRecordingRootfs{}
	f.driver.SetRootfsBuilder(rootfs)
	bin := filepath.Join(t.TempDir(), "toolboxd")
	if err := os.WriteFile(bin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.driver.cfg.ToolboxBinaryPath = bin
	logs := &lockedBuffer{}
	f.driver.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// The out-of-band TCP probe would dial the fake guest IP for real.
	f.driver.toolboxTCPProbe = func(context.Context, string, string, *TapSlot, bool) {}
	return f, vsock, rootfs, logs
}

func bankEnv() map[string]string {
	return map[string]string{"BANK_SECRET": envCanary, "REGION": "eu-west-1"}
}

// stageSnapshotTemplate wires a snapshot-bearing (hasSnapshot) or rootfs-only
// template and returns its CID.
func stageSnapshotTemplate(t *testing.T, f *driverFixture, hasSnapshot bool) uint32 {
	t.Helper()
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.ext4")
	mem := filepath.Join(dir, "snapshot.memory")
	state := filepath.Join(dir, "snapshot.state")
	for _, p := range []string{rootfs, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: hasSnapshot,
		snapshotMemoryPath: mem, snapshotStatePath: state, snapshotVsockCID: 200,
	})
	return 200
}

// assertNoCanary fails if the secret reached any host-side text.
func assertNoCanary(t *testing.T, where string, text string) {
	t.Helper()
	if strings.Contains(text, envCanary) {
		t.Fatalf("the env value leaked into %s: %q", where, text)
	}
}

// TestCreateDeliversEnvOnEveryBootPath is the regression for UC-331: on
// origin/main a Firecracker guest never received its create-time env. Every
// path that boots a guest for a create must now push it, after the boot
// handshake, to the CID the guest actually listens on, and never through
// the rootfs or a log line.
func TestCreateDeliversEnvOnEveryBootPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stage   func(t *testing.T, f *driverFixture) (templateID string, wantCID uint32)
		wantOps []string
	}{
		{
			name:    "cold boot from an OCI image",
			stage:   func(*testing.T, *driverFixture) (string, uint32) { return "", 3 },
			wantOps: []string{"ping", "post_resume", guestEnvOp, guestAdoptOp},
		},
		{
			name: "cold boot from a template rootfs",
			stage: func(t *testing.T, f *driverFixture) (string, uint32) {
				stageSnapshotTemplate(t, f, false)
				return "tpl-rootfs", 3
			},
			wantOps: []string{"ping", "post_resume", guestEnvOp, guestAdoptOp},
		},
		{
			name: "snapshot load from a template",
			stage: func(t *testing.T, f *driverFixture) (string, uint32) {
				return "tpl-snap", stageSnapshotTemplate(t, f, true)
			},
			wantOps: []string{"ping", "post_resume", guestEnvOp, guestAdoptOp},
		},
		{
			name: "warm-pool acquire",
			stage: func(t *testing.T, f *driverFixture) (string, uint32) {
				stageWarmFixture(t, f)
				stageWarmTemplate(t, f, false)
				return "tpl-warm", 200
			},
			wantOps: []string{"ping", "post_resume", guestEnvOp, guestAdoptOp},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, vsock, rootfs, logs := envFixture(t)
			templateID, wantCID := tc.stage(t, f)
			ctx, timing := createtiming.With(context.Background())

			_, err := f.driver.Create(ctx, models.CreateSandboxRequest{
				Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: templateID, Env: bankEnv(),
			}, "sb-env", "tok", nil)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if got := vsock.opList(); !slices.Equal(got, tc.wantOps) {
				t.Fatalf("vsock ops = %v, want %v", got, tc.wantOps)
			}
			pushes := vsock.envPushes(t)
			if len(pushes) != 1 || !maps.Equal(pushes[0], bankEnv()) {
				t.Fatalf("set_env pushes = %v, want exactly the create env once", pushes)
			}
			vsock.mu.Lock()
			if last := vsock.cids[len(vsock.cids)-1]; last != wantCID {
				t.Fatalf("set_env dialed cid %d, want %d (the CID the guest listens on)", last, wantCID)
			}
			vsock.mu.Unlock()
			if !slices.ContainsFunc(timing.Stages(), func(s createtiming.Stage) bool { return s.Name == "fc_env" }) {
				t.Fatalf("no fc_env stage recorded: %+v", timing.Stages())
			}
			for _, file := range rootfs.inject {
				assertNoCanary(t, "the rootfs file "+file.GuestPath, string(file.Content))
			}
			assertNoCanary(t, "the driver log", logs.String())
			if !strings.Contains(logs.String(), "keys=2") {
				t.Fatalf("expected a key-count log line, got %q", logs.String())
			}
		})
	}
}

// An env-less create sends no set_env: no added round trip, and it keeps
// working on templates captured before the agent knew the op.
func TestCreateWithoutEnvSendsNoSetEnv(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	ctx, timing := createtiming.With(context.Background())
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128}, "sb-noenv", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := vsock.opList(); !slices.Equal(got, []string{"ping", "post_resume", guestAdoptOp}) {
		t.Fatalf("vsock ops = %v, want [ping post_resume adopt]", got)
	}
	if slices.ContainsFunc(timing.Stages(), func(s createtiming.Stage) bool { return s.Name == "fc_env" }) {
		t.Fatal("an env-less create recorded fc_env")
	}
}

// A guest agent older than set_env (a template whose disk was built before
// this change) answers "unknown op". The create must fail with a re-create
// hint and tear the VM down, not come up without its secrets.
func TestCreateFailsClosedWhenTheAgentCannotTakeEnv(t *testing.T) {
	oldAgent := func(op string, _ int) string {
		if op == guestEnvOp {
			return `{"error":"unknown op \"set_env\""}`
		}
		return ""
	}
	t.Run("cold snapshot load", func(t *testing.T) {
		f, vsock, _, logs := envFixture(t)
		vsock.reply = oldAgent
		stageSnapshotTemplate(t, f, true)
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", MemoryMB: 128, TemplateID: "tpl-old", Env: bankEnv(),
		}, "sb-old-agent", "tok", nil)
		if !errors.Is(err, models.ErrRuntimeNotImplemented) || !strings.Contains(err.Error(), "re-create the template") {
			t.Fatalf("err = %v, want a not-implemented error with a re-create hint", err)
		}
		if n := strings.Count(strings.Join(vsock.opList(), ","), guestEnvOp); n != 1 {
			t.Fatalf("set_env sent %d times; a rejection is final and must not be retried", n)
		}
		if !f.vmm.shutdown || f.pool.release != 1 || f.tapHost.removeCalls != 1 {
			t.Fatalf("rollback incomplete: vmm shutdown=%v pool release=%d tap remove=%d", f.vmm.shutdown, f.pool.release, f.tapHost.removeCalls)
		}
		f.driver.mu.Lock()
		_, registered := f.driver.vmms["sb-old-agent"]
		f.driver.mu.Unlock()
		if registered {
			t.Fatal("a failed create left the VMM registered")
		}
		assertNoCanary(t, "the error", err.Error())
		assertNoCanary(t, "the driver log", logs.String())
	})
	t.Run("warm acquire", func(t *testing.T) {
		f, vsock, _, _ := envFixture(t)
		vsock.reply = oldAgent
		pool, handle := stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", MemoryMB: 128, TemplateID: "tpl-warm", Env: bankEnv(),
		}, "sb-old-warm", "tok", nil)
		if !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v, want not implemented", err)
		}
		pool.mu.Lock()
		releases := slices.Clone(pool.releaseCalls)
		pool.mu.Unlock()
		if !slices.Equal(releases, []string{"sb-old-warm"}) || handle.shutdowns != 1 {
			t.Fatalf("warm rollback incomplete: releases=%v shutdowns=%d", releases, handle.shutdowns)
		}
	})
}

// A push whose ack is lost is re-sent, and the guest (which replaces rather
// than merges, see cmd/toolboxd/sandboxenv) converges on the same env. The
// re-sent payload must be identical.
func TestCreateResendsEnvAfterALostAck(t *testing.T) {
	f, vsock, _, logs := envFixture(t)
	vsock.reply = func(op string, nth int) string {
		if op == guestEnvOp && nth == 1 {
			return "EOF"
		}
		return ""
	}
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", MemoryMB: 128, Env: bankEnv(),
	}, "sb-retry", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	pushes := vsock.envPushes(t)
	if len(pushes) != 2 || !maps.Equal(pushes[0], pushes[1]) || !maps.Equal(pushes[0], bankEnv()) {
		t.Fatalf("pushes = %v, want the same env twice", pushes)
	}
	if !strings.Contains(logs.String(), "attempts=2") {
		t.Fatalf("expected attempts=2 in the log, got %q", logs.String())
	}
}

// A guest that never acks fails the create after a bounded number of
// attempts, and the error names neither key nor value.
func TestCreateFailsWhenEnvDeliveryNeverAcks(t *testing.T) {
	f, vsock, _, logs := envFixture(t)
	vsock.dialErr = func(dial int) error {
		if dial > 2 { // ping and post_resume dial fine; every set_env dial fails
			return errors.New("vsock: connection reset (fake)")
		}
		return nil
	}
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", MemoryMB: 128, Env: bankEnv(),
	}, "sb-noack", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "deliver sandbox env (2 keys, 3 attempts)") {
		t.Fatalf("err = %v, want a delivery failure after 3 attempts", err)
	}
	vsock.mu.Lock()
	dials := vsock.dials
	vsock.mu.Unlock()
	if dials != 2+guestEnvAttempts {
		t.Fatalf("dials = %d, want %d", dials, 2+guestEnvAttempts)
	}
	if f.pool.release != 1 || !f.vmm.shutdown {
		t.Fatalf("rollback incomplete: release=%d shutdown=%v", f.pool.release, f.vmm.shutdown)
	}
	assertNoCanary(t, "the error", err.Error())
	assertNoCanary(t, "the driver log", logs.String())
}

// An env the agent would refuse fails before anything is allocated, and the
// error does not quote the key (which may hold a pasted secret).
func TestCreateRejectsInvalidEnvBeforeAllocating(t *testing.T) {
	for _, env := range []map[string]string{
		{"": "v"},
		{"TOKEN=" + envCanary: "v"},
		{"K": envCanary + "\x00"},
	} {
		f, vsock, _, _ := envFixture(t)
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128, Env: env}, "sb-bad-env", "tok", nil)
		if !errors.Is(err, errGuestEnvInvalid) {
			t.Fatalf("Create(%q) err = %v, want errGuestEnvInvalid", env, err)
		}
		assertNoCanary(t, "the error", err.Error())
		if f.pool.alloc != 0 || vsock.dials != 0 {
			t.Fatalf("an invalid env allocated resources: alloc=%d dials=%d", f.pool.alloc, vsock.dials)
		}
	}
}

func TestSendVsockOpAckDecodesTheAck(t *testing.T) {
	for _, tc := range []struct {
		name, reply, want string
		rejected          bool
	}{
		{name: "ok", reply: ""},
		{name: "error", reply: `{"error":"nope"}`, want: "nope", rejected: true},
		{name: "not ok, no reason", reply: `{"ok":false}`, want: "ok=false", rejected: true},
		{name: "garbage", reply: "not json\n", want: "decode ack"},
		{name: "no ack", reply: "EOF", want: "read ack"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, vsock, _, _ := envFixture(t)
			vsock.reply = func(string, int) string { return tc.reply }
			err := f.driver.sendVsockOpAck(context.Background(), "/run/v.sock", 3, guestEnvOp, map[string]any{"env": map[string]string{}})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			var rej *guestRejectedError
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.As(err, &rej) != tc.rejected {
				t.Fatalf("err = %v, want %q (rejected=%v)", err, tc.want, tc.rejected)
			}
		})
	}
	f, _, _, _ := envFixture(t)
	if err := f.driver.sendVsockOpAck(context.Background(), "/run/v.sock", 3, guestEnvOp, make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal data") {
		t.Fatalf("unmarshalable data err = %v", err)
	}
}

// The delivery stops at its own deadline rather than retrying forever.
func TestDeliverGuestEnvHonoursContextCancel(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	vsock.dialErr = func(int) error {
		cancel()
		return errors.New("vsock: refused (fake)")
	}
	err := f.driver.deliverGuestEnv(ctx, "/run/v.sock", 3, "sb-cancel", bankEnv())
	if err == nil || vsock.dials != 1 {
		t.Fatalf("err = %v dials = %d; want one attempt then stop", err, vsock.dials)
	}
}

// toolboxd is PID 1 in every Firecracker guest: toolboxd-init execs it, so a
// toolboxd exit panics the guest instead of restarting the agent without the
// env it holds in memory. That is why the env needs no in-guest persistence;
// this guards the exec.
func TestInitShimExecsToolboxdAsPID1(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(string(toolboxdInitScript)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "exec "+guestToolboxPath {
		t.Fatalf("toolboxd-init ends with %q, want %q", last, "exec "+guestToolboxPath)
	}
}
