package service

import (
	"bytes"
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Mount-tool flags run as root on the host, so extra_args, opts and rclone's
// backends are allow lists. A create with anything off them is refused
// before any work, naming the mount and the flag, and so is a replay of a
// stored spec: a refused flag is only harmless if it never runs.
func TestCreateSandboxRefusesMountToolOptionsOffTheAllowList(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)

	cases := []struct {
		name   string
		mounts []models.MountSpec
		want   string
	}{
		{"s3 log directory", []models.MountSpec{{
			Type: models.MountTypeS3, Target: "/data", Source: "bucket",
			Options: map[string]string{"extra_args": "--allow-delete --log-directory=/etc/cron.d"},
		}}, `mount 0: options.extra_args flag "--log-directory" is not allowed`},
		{"nfs helper", []models.MountSpec{
			{Type: models.MountTypeS3, Target: "/a", Source: "bucket", Options: map[string]string{"extra_args": "--allow-delete"}},
			{Type: models.MountTypeNFS, Target: "/b", Source: "h:/e", Options: map[string]string{"opts": "vers=4.1,helper=evil"}},
		}, `mount 1: options.opts entry "helper" is not allowed`},
		{"rclone local backend", []models.MountSpec{{
			Type: models.MountTypeRclone, Target: "/data", Source: ":local:/etc",
			Credentials: map[string]string{"rclone_conf": "#"},
		}}, `mount 0: rclone source uses rclone backend "local", which is not allowed`},
		{"rclone ssh command", []models.MountSpec{{
			Type: models.MountTypeRclone, Target: "/data", Source: "box:data",
			Credentials: map[string]string{"rclone_conf": "[box]\ntype = sftp\nhost = h\nssh = sh -c id\n"},
		}}, `mount 0: credentials.rclone_conf section "box" option "ssh" is not allowed`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Mounts: tc.mounts})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CreateSandbox() error = %v, want %q", err, tc.want)
			}
			if rt.createCalls != 0 {
				t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
			}
			if err := svc.validateCreateMounts(contextWithStoredSpecReplay(ctx), tc.mounts, "sb-replayed", nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stored-spec replay = %v, want it refused too", err)
			}
		})
	}

	// A credential-shaped flag is named as a credential first: that error
	// says where the value belongs, which the allow list's does not.
	secret := []models.MountSpec{{
		Type: models.MountTypeS3, Target: "/data", Source: "bucket",
		Options: map[string]string{"extra_args": "--s3-secret-access-key=XYZ"},
	}}
	if err := svc.validateCreateMounts(ctx, secret, "", nil); err == nil || !strings.Contains(err.Error(), "put it in credentials") {
		t.Fatalf("validateCreateMounts() = %v, want the credential placement error", err)
	}

	ok := []models.MountSpec{
		{Type: models.MountTypeS3, Target: "/a", Source: "bucket", Options: map[string]string{"extra_args": "--allow-delete --uid 1000"}},
		{Type: models.MountTypeNFS, Target: "/b", Source: "h:/e", Options: map[string]string{"opts": "vers=4.1,hard"}},
	}
	if err := svc.validateCreateMounts(ctx, ok, "", nil); err != nil {
		t.Fatalf("allowed flags = %v", err)
	}
}

// A platform volume's mount is the operator's, built from configuration
// daemon start checks, so the caller's allow list does not judge it: not
// the mounts a create just made from platform volumes, not a sandbox's
// stored ones (which may carry what the operator set before the check
// existed), and not a rebuild's. The same options on a mount no platform
// volume names are the caller's, and refused.
func TestPlatformVolumeMountsSkipTheCallerAllowList(t *testing.T) {
	ctx := context.Background()
	svc := enabledVolumeService(t)
	svc.cfg.PlatformVolumes = config.PlatformVolumesConfig{
		Enabled: true, Backend: config.PlatformVolumesBackendNFS, NFSServer: "nfs.example", NFSExport: "/exports",
		// A value from before the boot check: it would stop the daemon now.
		NFSOptions: "defaults,vers=4.1",
	}
	req := models.CreateSandboxRequest{Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}}}
	atts, err := svc.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker)
	if err != nil || len(atts) != 1 || len(req.Mounts) != 1 {
		t.Fatalf("resolvePlatformVolumes = %v %v, mounts %v", atts, err, req.Mounts)
	}
	if err := svc.validateCreateMounts(ctx, req.Mounts, "", atts); err != nil {
		t.Fatalf("the create's own platform mount = %v, want it skipped", err)
	}
	if err := svc.validateCreateMounts(rebuildContext(ctx), req.Mounts, "sb-r", nil); err != nil {
		t.Fatalf("a rebuild's platform mount = %v, want it skipped", err)
	}
	if err := svc.validateCreateMounts(ctx, req.Mounts, "", nil); err == nil || !strings.Contains(err.Error(), `mount 0: options.opts entry "defaults" is not allowed`) {
		t.Fatalf("the same options as a caller's mount = %v, want refused", err)
	}

	// Stored: the attachment records name it, read only when a mount fails.
	stored := atts[0]
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{stored}}
	if err := svc.checkCallerMountTools(ctx, "sb-v", req.Mounts, nil); err != nil {
		t.Fatalf("a stored platform mount = %v, want it skipped", err)
	}
	moved := req.Mounts[0]
	moved.Target = "/elsewhere"
	if err := svc.checkCallerMountTools(ctx, "sb-v", []models.MountSpec{moved}, nil); err == nil {
		t.Fatal("a mount no attachment names passed")
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandboxErr: errors.New("control plane unreachable")}
	if err := svc.checkCallerMountTools(ctx, "sb-v", req.Mounts, nil); err == nil || !strings.Contains(err.Error(), "platform volume records could not be read") {
		t.Fatalf("unreadable records = %v, want refused", err)
	}
	clean := []models.MountSpec{{Type: models.MountTypeS3, Source: "b", Target: "/d"}}
	if err := svc.checkCallerMountTools(ctx, "sb-v", clean, nil); err != nil {
		t.Fatalf("a passing mount read the records: %v", err)
	}
}

// The failover recreate path for real: a node rebuilding an operator's
// sandbox mounts its platform volume with this node's configuration, and
// the caller's allow list does not stop it (the boot check owns those
// values). It gets as far as running mount-s3, which this test host lacks.
func TestRecreatePlatformVolumePassesTheMountChecks(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no mount-s3 here: the create stops at running it
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.OperatorVolumeScope = "op-main"
	svc.cfg.PlatformVolumes = config.PlatformVolumesConfig{
		Enabled: true, Backend: config.PlatformVolumesBackendS3, S3Bucket: "vols", S3Prefix: "pfx",
		S3Region: "eu west", // what the boot check would refuse: not the caller's to fix
	}
	spec := models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "vols/pfx/op-main/data", Target: "/data"}}}
	err := svc.RecreateSandbox(ctx, "sb-pv", spec, cluster.PlacementSecrets{}, nil)
	if !errors.Is(err, mounts.ErrMountToolUnavailable) {
		t.Fatalf("recreate = %v, want it to reach mount-s3", err)
	}
	if strings.Contains(err.Error(), "is not allowed") || strings.Contains(err.Error(), "takes a plain name") {
		t.Fatalf("recreate judged the platform mount as the caller's: %v", err)
	}
}

// Start and restart re-run a sandbox's stored mounts through the same
// lists. A spec stored before them, with a flag they now refuse, is not run
// again: the start fails naming the mount and the flag, and the runtime is
// never asked to start the sandbox.
func TestStartSandboxRefusesStoredMountToolOptions(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cipher = newTestCipher(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-old-flag", Image: "alpine:3.20", Status: models.SandboxStatusStopped, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-old-flag", ContainerIP: "10.0.0.23", CPU: 1, MemoryMB: 256, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	sealed, err := svc.sealMounts([]models.MountSpec{{
		Type: models.MountTypeS3, Target: "/data", Source: "bucket",
		Options: map[string]string{"extra_args": "--allow-delete --log-directory=/etc/cron.d"},
	}})
	if err != nil {
		t.Fatalf("sealMounts: %v", err)
	}
	if err := st.PutMounts(ctx, "sb-old-flag", sealed); err != nil {
		t.Fatalf("PutMounts: %v", err)
	}
	_, err = svc.StartSandbox(ctx, "sb-old-flag")
	if err == nil || !strings.Contains(err.Error(), `reestablish mounts: mount 0: options.extra_args flag "--log-directory" is not allowed`) {
		t.Fatalf("StartSandbox() = %v, want the stored flag refused", err)
	}
	if len(rt.startRefs) != 0 {
		t.Fatalf("runtime started %v", rt.startRefs)
	}
	if binds := svc.mounts.HostBindsFor("sb-old-flag"); len(binds) != 0 {
		t.Fatalf("mounts left tracked: %v", binds)
	}

	// The helper the passivated WASM start shares refuses the same way, and
	// passes a spec the lists accept on to the mount manager. (A sandbox
	// still running at a restart goes through reestablishRunningMounts.)
	if err := svc.reestablishMounts(ctx, "sb-old-flag", []models.MountSpec{{
		Type: models.MountTypeRclone, Target: "/r", Source: ":local:/", Credentials: map[string]string{"rclone_conf": "#"},
	}}); err == nil || !strings.Contains(err.Error(), `backend "local"`) {
		t.Fatalf("reestablishMounts(rclone local) = %v", err)
	}
	if err := svc.reestablishMounts(ctx, "sb-bogus", []models.MountSpec{{Type: "bogus", Target: "/x", Source: "b"}}); err == nil || strings.Contains(err.Error(), "is not allowed") {
		t.Fatalf("reestablishMounts(passing spec) = %v, want the manager's own error", err)
	}
}

// restartMounts stands in for the mount manager where a restart takes over
// a running sandbox's mounts (Service.testRunningMounts). It records which
// way reestablishRunningMounts went, keeps what it is asked to keep as live
// mounts would be kept, and reports a teardown only while a previous
// sandboxd's mounts are there to tear down.
type restartMounts struct {
	mu      sync.Mutex
	calls   []string
	kept    map[string][]models.MountSpec
	left    map[string]bool
	keepErr error
}

func newRestartMounts(leftFor string) *restartMounts {
	return &restartMounts{kept: map[string][]models.MountSpec{}, left: map[string]bool{leftFor: true}}
}

func (r *restartMounts) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *restartMounts) Reestablish(context.Context, string, []models.MountSpec) error {
	r.record("reestablish")
	return nil
}

func (r *restartMounts) KeepLive(_ context.Context, id string, specs []models.MountSpec) (mounts.KeepReport, error) {
	r.record("keep")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keepErr != nil {
		return mounts.KeepReport{}, r.keepErr
	}
	if _, ok := r.kept[id]; ok {
		return mounts.KeepReport{Already: true}, nil
	}
	r.kept[id] = specs
	var report mounts.KeepReport
	for i := range specs {
		report.Kept = append(report.Kept, i)
	}
	return report, nil
}

func (r *restartMounts) Discard(id string) bool {
	r.record("discard")
	r.mu.Lock()
	defer r.mu.Unlock()
	_, kept := r.kept[id]
	found := kept || r.left[id]
	delete(r.kept, id)
	delete(r.left, id)
	return found
}

func (r *restartMounts) HostBindsFor(id string) []mounts.ContainerBind {
	r.mu.Lock()
	defer r.mu.Unlock()
	var binds []mounts.ContainerBind
	for i, s := range r.kept[id] {
		binds = append(binds, mounts.ContainerBind{HostPath: fmt.Sprintf("/mounts/%s/%d", id, i), ContainerPath: s.Target})
	}
	return binds
}

func (r *restartMounts) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func refusedRunningCount(outcome string) int64 {
	if v, ok := mountsRefusedRunning.Get(outcome).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

// runningMountCase is one running sandbox a restart finds, by its stored
// mounts, and what must become of them.
type runningMountCase struct {
	name      string
	mounts    []models.MountSpec
	volumeErr error    // the sandbox's platform volume records cannot be read
	want      string   // "reestablish", "keep", "discard", or "" for untouched
	action    string   // the system action recorded, "" for none
	names     []string // in the record's reason and the log line: the refused options
}

func runningMountCases() []runningMountCase {
	s3 := func(target, extra string) models.MountSpec {
		return models.MountSpec{Type: models.MountTypeS3, Source: "bucket", Target: target, Options: map[string]string{"extra_args": extra}}
	}
	nfs := func(target, opts string) models.MountSpec {
		return models.MountSpec{Type: models.MountTypeNFS, Source: "h:/e", Target: target, Options: map[string]string{"opts": opts}}
	}
	return []runningMountCase{
		{name: "allowed options are reestablished as before",
			mounts: []models.MountSpec{s3("/a", "--allow-delete --uid 1000"), nfs("/b", "vers=4.1,hard")}, want: "reestablish"},
		{name: "an s3 cache folder is kept",
			mounts: []models.MountSpec{s3("/a", "--allow-delete --cache /var/cache/s3 --max-cache-size 1024")},
			want:   "keep", action: systemActionMountsRefusedKept, names: []string{"mount 0", "--cache"}},
		{name: "nfs defaults, bg and fsc are kept",
			mounts: []models.MountSpec{nfs("/b", "defaults,bg,fsc,vers=4.1")},
			want:   "keep", action: systemActionMountsRefusedKept, names: []string{"mount 0", "defaults"}},
		{name: "one refused mount among allowed ones keeps the set",
			mounts: []models.MountSpec{s3("/a", "--allow-delete"), nfs("/b", "rw,bg")},
			want:   "keep", action: systemActionMountsRefusedKept, names: []string{"mount 1", "bg"}},
		{name: "an s3 log folder is torn down",
			mounts: []models.MountSpec{s3("/a", "--log-directory=/etc/cron.d")},
			want:   "discard", action: systemActionMountsRefusedRemoved, names: []string{"mount 0", "--log-directory"}},
		{name: "an rclone host folder is torn down",
			mounts: []models.MountSpec{{Type: models.MountTypeRclone, Target: "/r", Source: ":local:/", Credentials: map[string]string{"rclone_conf": "#"}}},
			want:   "discard", action: systemActionMountsRefusedRemoved, names: []string{"mount 0", "local"}},
		{name: "a kept flag beside one that may not run on is torn down",
			mounts: []models.MountSpec{s3("/a", "--cache /c"), s3("/b", "--profile default")},
			want:   "discard", action: systemActionMountsRefusedRemoved, names: []string{"mount 0", "--cache", "mount 1", "--profile"}},
		{name: "unreadable platform volume records leave the mounts untouched",
			mounts: []models.MountSpec{nfs("/b", "bg")}, volumeErr: errors.New("control plane unreachable")},
	}
}

// seedRunningMounts stores sandbox id's mounts sealed, as a create would.
func seedRunningMounts(t *testing.T, svc *Service, st interface {
	PutMounts(context.Context, string, []byte) error
}, id string, specs []models.MountSpec) {
	t.Helper()
	sealed, err := svc.sealMounts(specs)
	if err != nil {
		t.Fatalf("sealMounts: %v", err)
	}
	if err := st.PutMounts(context.Background(), id, sealed); err != nil {
		t.Fatalf("PutMounts: %v", err)
	}
}

// checkRunningMountOutcome checks one case after the restart's passes: the
// mount manager calls, one system action record and one count per
// sandboxd (not per pass), and a log line naming the sandbox and options.
func checkRunningMountOutcome(t *testing.T, tc runningMountCase, set *restartMounts, sink *memSecretAuditSink, logs string, id, caller string, passes int, before map[string]int64) {
	t.Helper()
	var wantCalls []string
	if tc.want != "" {
		for range passes {
			wantCalls = append(wantCalls, tc.want)
		}
	}
	if got := set.seen(); !slices.Equal(got, wantCalls) {
		t.Fatalf("mount manager calls = %v, want %v", got, wantCalls)
	}
	records := systemRecords(sink, id)
	if tc.action == "" {
		if len(records) != 0 {
			t.Fatalf("records = %+v, want none", records)
		}
	} else {
		if len(records) != 1 {
			t.Fatalf("records = %+v, want one %s record", records, tc.action)
		}
		wantRecords(t, records, auditRecord{ref: sys(tc.action), reason: records[0].reason, caller: caller, result: "ok"})
		for _, name := range tc.names {
			if !strings.Contains(records[0].reason, name) {
				t.Fatalf("record reason %q does not name %q", records[0].reason, name)
			}
		}
	}
	for outcome, action := range map[string]string{"kept": systemActionMountsRefusedKept, "removed": systemActionMountsRefusedRemoved} {
		want := before[outcome]
		if tc.action == action {
			want++
		}
		if got := refusedRunningCount(outcome); got != want {
			t.Fatalf("aerolvm_mounts_refused_running_total{%s} = %d, want %d", outcome, got, want)
		}
	}
	if tc.action != "" {
		if !strings.Contains(logs, "sandbox_id="+id) {
			t.Fatalf("no log line names the sandbox:\n%s", logs)
		}
		for _, name := range tc.names {
			if !strings.Contains(logs, name) {
				t.Fatalf("the log does not name %q:\n%s", name, logs)
			}
		}
	}
}

// The boot reconcile (and every pass after it) after an upgrade, for a
// sandbox still running: a stored mount the allow lists now refuse is kept
// as it runs when its refused flags do no harm while the tool runs, so the
// sandbox does not lose its storage; it is torn down when they do. Either
// way it is logged, counted and recorded once, naming the sandbox and the
// options, so an operator can find it before it restarts. Allowed mounts
// are reestablished as before.
func TestReconcileKeepsRunningMountsWithRefusedOptions(t *testing.T) {
	const id = "sb-run"
	for _, tc := range runningMountCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
				id: {Status: models.SandboxStatusStarted, ContainerID: "ctr-run"},
			}}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.cipher = newTestCipher(t)
			var logs bytes.Buffer
			svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
			sink := captureAudit(svc)
			set := newRestartMounts(id)
			svc.testRunningMounts = set
			if tc.volumeErr != nil {
				svc.testVolumeMeta = &scriptedVolumeMeta{forSandboxErr: tc.volumeErr}
			}
			now := time.Now().UTC()
			if err := st.Create(ctx, &models.Sandbox{
				ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
				ContainerID: "ctr-run", ContainerIP: "10.0.0.31", CPU: 1, MemoryMB: 256, DiskGB: 5,
				CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
			}); err != nil {
				t.Fatalf("seed sandbox: %v", err)
			}
			seedRunningMounts(t, svc, st, id, tc.mounts)
			before := map[string]int64{"kept": refusedRunningCount("kept"), "removed": refusedRunningCount("removed")}

			for range 2 {
				if err := svc.Reconcile(ctx); err != nil {
					t.Fatalf("Reconcile: %v", err)
				}
			}
			checkRunningMountOutcome(t, tc, set, sink, logs.String(), id, "system:reconcile", 2, before)
			if tc.volumeErr != nil && !strings.Contains(logs.String(), "platform volume records could not be read") {
				t.Fatalf("the unreadable records were not logged:\n%s", logs.String())
			}
			got, err := st.Get(ctx, id)
			if err != nil || got.Status != models.SandboxStatusStarted {
				t.Fatalf("sandbox = %+v, %v; it must stay running", got, err)
			}
		})
	}
}

// The WASM adopt at boot, for the same cases: a kept mount reaches the
// adopted instance as its bind, so the sandbox keeps its storage; a mount
// torn down leaves the sandbox to reconcile, as before, rather than run
// with its mount paths unbacked.
func TestAdoptWasmSandboxesKeepsRunningMountsWithRefusedOptions(t *testing.T) {
	const id = "sb-wasm-run"
	for _, tc := range runningMountCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &adoptingWasmRuntime{adoptable: map[string]bool{id: true}}
			svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.cfg.EnableWasm = true
			svc.SetWasmRuntime(rt)
			svc.cipher = newTestCipher(t)
			var logs bytes.Buffer
			svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
			sink := captureAudit(svc)
			set := newRestartMounts(id)
			svc.testRunningMounts = set
			if tc.volumeErr != nil {
				svc.testVolumeMeta = &scriptedVolumeMeta{forSandboxErr: tc.volumeErr}
			}
			now := time.Now().UTC()
			if err := st.Create(ctx, &models.Sandbox{ID: id, Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			seedRunningMounts(t, svc, st, id, tc.mounts)
			before := map[string]int64{"kept": refusedRunningCount("kept"), "removed": refusedRunningCount("removed")}

			report := svc.AdoptWasmSandboxes(ctx)
			checkRunningMountOutcome(t, tc, set, sink, logs.String(), id, "system:boot-restore", 1, before)
			adopted := tc.want == "reestablish" || tc.want == "keep"
			if (report.Adopted == 1) != adopted || len(rt.adopted) != report.Adopted {
				t.Fatalf("report = %+v adopted %v, want adopted = %v", report, rt.adopted, adopted)
			}
			if tc.want == "keep" {
				binds := rt.binds[id]
				if len(binds) != len(tc.mounts) {
					t.Fatalf("the adopted instance got binds %+v, want one per kept mount", binds)
				}
				for i, b := range binds {
					if b.ContainerPath != tc.mounts[i].Target {
						t.Fatalf("bind %d = %+v, want target %s", i, b, tc.mounts[i].Target)
					}
				}
			}
		})
	}
}

// The restart with the real mount manager, which no previous sandboxd's
// helper serves here: a running sandbox's mount folder, and what was left
// in it, stays for a refused flag that may run on (nothing in it is live,
// so nothing is kept, and nothing is mounted either) and is cleared for
// one that may not.
func TestReconcileRunningMountFolderWithTheRealManager(t *testing.T) {
	const id = "sb-real"
	cases := []struct {
		name, extra string
		folderStays bool
	}{
		{"a cache folder flag leaves it", "--allow-delete --cache /var/cache/s3", true},
		{"a log folder flag clears it", "--log-directory=/etc/cron.d", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
				id: {Status: models.SandboxStatusStarted, ContainerID: "ctr-real"},
			}}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.cipher = newTestCipher(t)
			root := t.TempDir()
			mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{RootDir: root, CredDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(mgr.Close)
			svc.mounts = mgr
			left := filepath.Join(root, id, "0", "object")
			if err := os.MkdirAll(filepath.Dir(left), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(left, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if err := st.Create(ctx, &models.Sandbox{
				ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
				ContainerID: "ctr-real", ContainerIP: "10.0.0.32", CPU: 1, MemoryMB: 256, DiskGB: 5,
				CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
			}); err != nil {
				t.Fatalf("seed sandbox: %v", err)
			}
			seedRunningMounts(t, svc, st, id, []models.MountSpec{{
				Type: models.MountTypeS3, Target: "/data", Source: "bucket", Options: map[string]string{"extra_args": tc.extra},
			}})
			if err := svc.Reconcile(ctx); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			_, err = os.Stat(left)
			if tc.folderStays && err != nil {
				t.Fatalf("the running sandbox's mount folder was cleared: %v", err)
			}
			if !tc.folderStays && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the mount folder of a mount that may not run on was left: %v", err)
			}
		})
	}
}

// A platform volume's stored mount is the operator's: a running sandbox's
// is reestablished as before even with options the caller lists refuse.
// A KeepLive that fails reports its error and records nothing.
func TestReestablishRunningMountsPlatformVolumeAndKeepFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	sink := captureAudit(svc)
	spec := models.MountSpec{Type: models.MountTypeNFS, Source: "nfs.example:/exports/op/data", Target: "/workspace", Options: map[string]string{"opts": "defaults,helper=x"}}

	set := newRestartMounts("sb-pv")
	svc.testRunningMounts = set
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{{Source: spec.Source, Target: spec.Target}}}
	if err := svc.reestablishRunningMounts(ctx, "sb-pv", []models.MountSpec{spec}); err != nil {
		t.Fatalf("platform volume mount = %v", err)
	}
	if got := set.seen(); !slices.Equal(got, []string{"reestablish"}) {
		t.Fatalf("calls = %v, want the platform mount reestablished", got)
	}

	set = newRestartMounts("sb-kf")
	set.keepErr = errors.New("mount sb-kf: busy")
	svc.testRunningMounts = set
	svc.testVolumeMeta = nil
	kept := models.MountSpec{Type: models.MountTypeNFS, Source: "h:/e", Target: "/b", Options: map[string]string{"opts": "bg"}}
	if err := svc.reestablishRunningMounts(ctx, "sb-kf", []models.MountSpec{kept}); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("KeepLive failure = %v, want it returned", err)
	}
	if records := systemRecords(sink, "sb-kf"); len(records) != 0 {
		t.Fatalf("a failed keep was recorded as kept: %+v", records)
	}
}
