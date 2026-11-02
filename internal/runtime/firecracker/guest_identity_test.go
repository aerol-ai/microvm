package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// tokenCanary stands in for a sandbox's toolbox token. It must reach the
// guest through adopt and never a log line, an error, or a file the driver
// writes for a template-backed guest.
const tokenCanary = "tok-canary-7f3e1b2a"

type adoptPayload struct {
	SandboxID string `json:"sandbox_id"`
	Token     string `json:"token"`
}

func (d *opVsockDialer) adoptPushes(t *testing.T) []adoptPayload {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []adoptPayload
	for _, raw := range d.payloads[guestAdoptOp] {
		var p adoptPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("decode adopt payload: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// agentReply answers op with reply and acks everything else.
func agentReply(op, reply string) func(string, int) string {
	return func(got string, _ int) string {
		if got == op {
			return reply
		}
		return ""
	}
}

// TestCreateAdoptsTheGuestOnEveryBootPath is the host half of the Firecracker
// toolbox auth fix. On the base branch a guest booted from a template rootfs,
// a template snapshot or a warm slot ran toolboxd with no token, so it served
// exec and files to anyone who reached port 2280. Every create must now hand
// the guest its token with the adopt op, last, on the CID the guest listens
// on; the token must not land in a log line or in a file of a template-backed
// boot.
func TestCreateAdoptsTheGuestOnEveryBootPath(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stage      func(t *testing.T, f *driverFixture) (templateID string, wantCID uint32)
		wantRootfs bool // a per-sandbox rootfs build (cold boot from an image)
	}{
		{
			name:       "cold boot from an OCI image",
			stage:      func(*testing.T, *driverFixture) (string, uint32) { return "", 3 },
			wantRootfs: true,
		},
		{
			name: "cold boot from a template rootfs",
			stage: func(t *testing.T, f *driverFixture) (string, uint32) {
				stageSnapshotTemplate(t, f, false)
				return "tpl-rootfs", 3
			},
		},
		{
			name: "snapshot load from a template",
			stage: func(t *testing.T, f *driverFixture) (string, uint32) {
				return "tpl-snap", stageSnapshotTemplate(t, f, true)
			},
		},
		{
			name: "warm-pool acquire",
			stage: func(t *testing.T, f *driverFixture) (string, uint32) {
				stageWarmFixture(t, f)
				stageWarmTemplate(t, f, false)
				return "tpl-warm", 200
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, vsock, rootfs, logs := envFixture(t)
			templateID, wantCID := tc.stage(t, f)
			ctx, timing := createtiming.With(context.Background())

			if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
				Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: templateID,
			}, "sb-adopt", tokenCanary, nil); err != nil {
				t.Fatalf("Create: %v", err)
			}
			ops := vsock.opList()
			if len(ops) == 0 || ops[len(ops)-1] != guestAdoptOp {
				t.Fatalf("vsock ops = %v, want adopt last", ops)
			}
			pushes := vsock.adoptPushes(t)
			if len(pushes) != 1 || pushes[0] != (adoptPayload{SandboxID: "sb-adopt", Token: tokenCanary}) {
				t.Fatalf("adopt pushes = %+v, want the sandbox's ID and token once", pushes)
			}
			vsock.mu.Lock()
			lastCID := vsock.cids[len(vsock.cids)-1]
			vsock.mu.Unlock()
			if lastCID != wantCID {
				t.Fatalf("adopt dialed cid %d, want %d (the CID the guest listens on)", lastCID, wantCID)
			}
			if !slices.ContainsFunc(timing.Stages(), func(s createtiming.Stage) bool { return s.Name == "fc_adopt" }) {
				t.Fatalf("no fc_adopt stage recorded: %+v", timing.Stages())
			}
			if built := len(rootfs.inject) > 0; built != tc.wantRootfs {
				t.Fatalf("rootfs built = %v, want %v", built, tc.wantRootfs)
			}
			if strings.Contains(logs.String(), tokenCanary) {
				t.Fatalf("the token reached the driver log: %q", logs.String())
			}
			if !strings.Contains(logs.String(), "guest adopted") {
				t.Fatalf("no adopt log line: %q", logs.String())
			}
		})
	}
}

// A create without a token fails before anything is allocated: the guest it
// would boot could never be adopted and would serve nothing.
func TestCreateRefusesAnEmptyTokenBeforeAllocating(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	for _, token := range []string{"", "   "} {
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128}, "sb-no-token", token, nil)
		if !errors.Is(err, errGuestTokenMissing) {
			t.Fatalf("Create(token %q) err = %v, want errGuestTokenMissing", token, err)
		}
	}
	if f.pool.alloc != 0 || vsock.dials != 0 {
		t.Fatalf("a token-less create allocated resources: alloc=%d dials=%d", f.pool.alloc, vsock.dials)
	}
}

// A guest whose toolboxd predates adopt answers "unknown op". Such an agent
// serves its API without a token, so the create fails with a rebuild hint
// and the VM is torn down instead of handed out.
func TestCreateFailsClosedWhenTheAgentCannotBeAdopted(t *testing.T) {
	oldAgent := agentReply(guestAdoptOp, `{"error":"unknown op \"adopt\""}`)
	t.Run("snapshot load", func(t *testing.T) {
		f, vsock, _, logs := envFixture(t)
		vsock.reply = oldAgent
		stageSnapshotTemplate(t, f, true)
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", MemoryMB: 128, TemplateID: "tpl-old",
		}, "sb-old-agent", tokenCanary, nil)
		if !errors.Is(err, models.ErrRuntimeNotImplemented) || !errors.Is(err, errGuestAgentPredatesAdopt) || !strings.Contains(err.Error(), "rebuild the template") {
			t.Fatalf("err = %v, want errGuestAgentPredatesAdopt with a rebuild hint", err)
		}
		if n := len(vsock.adoptPushes(t)); n != 1 {
			t.Fatalf("adopt sent %d times; a refusal is final and must not be retried", n)
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
		if strings.Contains(err.Error(), tokenCanary) || strings.Contains(logs.String(), tokenCanary) {
			t.Fatal("the token reached the error or the log")
		}
	})
	t.Run("warm acquire", func(t *testing.T) {
		f, vsock, _, _ := envFixture(t)
		vsock.reply = oldAgent
		pool, handle := stageWarmFixture(t, f)
		stageWarmTemplate(t, f, false)
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", MemoryMB: 128, TemplateID: "tpl-warm",
		}, "sb-old-warm", tokenCanary, nil)
		if !errors.Is(err, errGuestAgentPredatesAdopt) {
			t.Fatalf("err = %v, want errGuestAgentPredatesAdopt", err)
		}
		pool.mu.Lock()
		releases := slices.Clone(pool.releaseCalls)
		pool.mu.Unlock()
		if !slices.Equal(releases, []string{"sb-old-warm"}) || handle.shutdowns != 1 {
			t.Fatalf("warm rollback incomplete: releases=%v shutdowns=%d", releases, handle.shutdowns)
		}
	})
}

// A guest that already belongs to another sandbox refuses the token. The
// create fails (it is not a legacy agent, so no rebuild hint) and rolls back.
func TestCreateFailsWhenTheGuestRefusesTheToken(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	vsock.reply = agentReply(guestAdoptOp, `{"error":"adopt: this agent already holds another sandbox's identity"}`)
	stageSnapshotTemplate(t, f, true)
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", MemoryMB: 128, TemplateID: "tpl-taken",
	}, "sb-second", tokenCanary, nil)
	var rejected *guestRejectedError
	if !errors.As(err, &rejected) || errors.Is(err, errGuestAgentPredatesAdopt) || !strings.Contains(err.Error(), "another sandbox's identity") {
		t.Fatalf("err = %v, want the guest's refusal", err)
	}
	if !f.vmm.shutdown || f.pool.release != 1 {
		t.Fatalf("rollback incomplete: shutdown=%v release=%d", f.vmm.shutdown, f.pool.release)
	}
}

// A lost ack is re-sent with the same payload; the guest keeps the first
// token, so the retry converges.
func TestCreateResendsAdoptAfterALostAck(t *testing.T) {
	f, vsock, _, logs := envFixture(t)
	vsock.reply = func(op string, nth int) string {
		if op == guestAdoptOp && nth == 1 {
			return "EOF"
		}
		return ""
	}
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128}, "sb-retry", tokenCanary, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	pushes := vsock.adoptPushes(t)
	if len(pushes) != 2 || pushes[0] != pushes[1] {
		t.Fatalf("adopt pushes = %+v, want the same payload twice", pushes)
	}
	if !strings.Contains(logs.String(), "attempts=2") {
		t.Fatalf("expected attempts=2 in the log, got %q", logs.String())
	}
}

// A guest that never acks fails the create after a bounded number of
// attempts.
func TestCreateFailsWhenAdoptNeverAcks(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	vsock.dialErr = func(dial int) error {
		if dial > 2 { // ping and post_resume dial fine; every adopt dial fails
			return errors.New("vsock: connection reset (fake)")
		}
		return nil
	}
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128}, "sb-noack", tokenCanary, nil)
	if err == nil || !strings.Contains(err.Error(), "adopt guest (3 attempts)") || strings.Contains(err.Error(), tokenCanary) {
		t.Fatalf("err = %v, want an adopt failure after 3 attempts", err)
	}
	if f.pool.release != 1 || !f.vmm.shutdown {
		t.Fatalf("rollback incomplete: release=%d shutdown=%v", f.pool.release, f.vmm.shutdown)
	}
}

// stopForRestart creates and stops a sandbox, then swaps in a fresh per-op
// guest fake for the restore.
func stopForRestart(t *testing.T, id string) (*driverFixture, *opVsockDialer) {
	t.Helper()
	f, _, _, _ := envFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128}, id, tokenCanary, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.driver.Stop(ctx, id); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	vsock := newOpVsockDialer()
	f.driver.SetVsockDialer(vsock)
	f.vmm.shutdown = false
	return f, vsock
}

// Stop→start restores the guest's memory, which already holds the token it
// was adopted with; StartWithIdentity re-sends it, and the guest converges.
func TestStartWithIdentityAdoptsTheRestoredGuest(t *testing.T) {
	f, vsock := stopForRestart(t, "sb-restart")
	ctx, timing := createtiming.With(context.Background())
	state, err := f.driver.StartWithIdentity(ctx, "sb-restart", "sb-restart", tokenCanary)
	if err != nil {
		t.Fatalf("StartWithIdentity: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v", state)
	}
	if got := vsock.opList(); !slices.Equal(got, []string{"ping", "post_resume", guestAdoptOp}) {
		t.Fatalf("restore ops = %v, want [ping post_resume adopt]", got)
	}
	if pushes := vsock.adoptPushes(t); len(pushes) != 1 || pushes[0] != (adoptPayload{SandboxID: "sb-restart", Token: tokenCanary}) {
		t.Fatalf("adopt pushes = %+v", pushes)
	}
	if !slices.ContainsFunc(timing.Stages(), func(s createtiming.Stage) bool { return s.Name == "fc_adopt" }) {
		t.Fatal("no fc_adopt stage on restore")
	}
	// Already running: no second restore, no second adopt.
	if _, err := f.driver.StartWithIdentity(ctx, "sb-restart", "sb-restart", tokenCanary); err != nil {
		t.Fatalf("second StartWithIdentity: %v", err)
	}
	if n := len(vsock.adoptPushes(t)); n != 1 {
		t.Fatalf("a running sandbox was adopted again (%d pushes)", n)
	}
}

// A stopped guest whose memory holds a toolboxd from before adopt is not
// started: it would serve without a token. The VM is shut down again and the
// snapshot stays on disk.
func TestStartRefusesAGuestThatCannotBeAdopted(t *testing.T) {
	f, vsock := stopForRestart(t, "sb-legacy")
	vsock.reply = agentReply(guestAdoptOp, `{"error":"unknown op \"adopt\""}`)
	removesBefore := f.tapHost.removeCalls
	_, err := f.driver.StartWithIdentity(context.Background(), "sb-legacy", "sb-legacy", tokenCanary)
	if !errors.Is(err, errGuestAgentPredatesAdopt) || !strings.Contains(err.Error(), "destroy it and create a new one") {
		t.Fatalf("err = %v, want errGuestAgentPredatesAdopt with the start remedy", err)
	}
	if !f.vmm.shutdown || f.tapHost.removeCalls != removesBefore+1 {
		t.Fatalf("the refused guest kept running: shutdown=%v tap removes=%d", f.vmm.shutdown, f.tapHost.removeCalls-removesBefore)
	}
	f.driver.mu.Lock()
	_, registered := f.driver.vmms["sb-legacy"]
	f.driver.mu.Unlock()
	if registered {
		t.Fatal("a refused start left the VMM registered")
	}
	if _, err := f.driver.readSandboxSnapshotManifest("sb-legacy"); err != nil {
		t.Fatalf("the stopped snapshot was lost: %v", err)
	}
}

// Without a token a restore is refused before anything is spawned, and a
// runtime reference that is not the sandbox is refused.
func TestStartWithoutATokenRestoresNothing(t *testing.T) {
	f, vsock := stopForRestart(t, "sb-notoken")
	if _, err := f.driver.Start(context.Background(), "sb-notoken"); !errors.Is(err, errGuestTokenMissing) {
		t.Fatalf("Start without a token err = %v, want errGuestTokenMissing", err)
	}
	if vsock.dials != 0 {
		t.Fatalf("a token-less start reached the guest (%d dials)", vsock.dials)
	}
	if _, err := f.driver.StartWithIdentity(context.Background(), "other", "sb-notoken", tokenCanary); err == nil || !strings.Contains(err.Error(), "does not name sandbox") {
		t.Fatalf("mismatched ref err = %v", err)
	}
}

// The template snapshot is what every clone resumes from, so its guest must
// never be adopted: a token captured in its memory would be every clone's.
func TestSnapshotTemplateNeverAdoptsTheGuest(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("ROOTFS"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: "tpl-capture", RootfsPath: rootfs,
		OutMemoryPath: filepath.Join(dir, "snapshot.memory"), OutStatePath: filepath.Join(dir, "snapshot.state"),
		GuestCID: 200, MemoryMB: 128, VCPU: 1,
	}); err != nil {
		t.Fatalf("SnapshotTemplate: %v", err)
	}
	if ops := vsock.opList(); slices.Contains(ops, guestAdoptOp) || slices.Contains(ops, guestEnvOp) {
		t.Fatalf("template capture sent %v; a template guest must stay without identity or env", ops)
	}
}

// The template's disk gets the agent with an empty token: the token arrives
// per sandbox over vsock, never from the template.
func TestTemplateInjectFilesCarryNoToken(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "toolboxd")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range ColdBootInjectFiles(bin, "", nil) {
		if f.GuestPath == guestEnvPath && !strings.Contains(string(f.Content), "SB_TOOLBOX_TOKEN=''\n") {
			t.Fatalf("template env file = %q, want an empty token", f.Content)
		}
	}
}

// adoptGuest refuses an empty token itself, whichever caller forgot to check.
func TestAdoptGuestRefusesAnEmptyToken(t *testing.T) {
	f, vsock, _, _ := envFixture(t)
	if err := f.driver.adoptGuest(context.Background(), "/run/v.sock", 3, "sb", " ", adoptRemedyCreate); !errors.Is(err, errGuestTokenMissing) {
		t.Fatalf("err = %v, want errGuestTokenMissing", err)
	}
	if vsock.dials != 0 {
		t.Fatalf("an empty token reached the guest (%d dials)", vsock.dials)
	}
}
