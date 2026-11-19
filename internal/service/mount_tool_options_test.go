package service

import (
	"context"
	"errors"
	"strings"
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

	// The helper the reconcile and WASM adopt paths share refuses the same
	// way, and passes a spec the lists accept on to the mount manager.
	if err := svc.reestablishMounts(ctx, "sb-old-flag", []models.MountSpec{{
		Type: models.MountTypeRclone, Target: "/r", Source: ":local:/", Credentials: map[string]string{"rclone_conf": "#"},
	}}); err == nil || !strings.Contains(err.Error(), `backend "local"`) {
		t.Fatalf("reestablishMounts(rclone local) = %v", err)
	}
	if err := svc.reestablishMounts(ctx, "sb-bogus", []models.MountSpec{{Type: "bogus", Target: "/x", Source: "b"}}); err == nil || strings.Contains(err.Error(), "is not allowed") {
		t.Fatalf("reestablishMounts(passing spec) = %v, want the manager's own error", err)
	}
}
