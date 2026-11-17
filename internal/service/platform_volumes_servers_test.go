package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// volumeServer is a cluster server whose servers sign (or not), with the
// platform-volume settings of the workers, its rows in the Noop's table.
func volumeServer(t *testing.T, signing bool) (*Service, *signingServer) {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster, svc.cfg.NodeRole = true, config.NodeRoleServer
	svc.cfg.PlatformVolumes = config.PlatformVolumesConfig{Enabled: true, Backend: config.PlatformVolumesBackendS3, S3Bucket: "vols", S3Prefix: "pfx"}
	c := newSigningServer("srv-1")
	if signing {
		c.rec = &cluster.ServerSigning{Sealed: []byte("x"), SinceUnixNano: 1}
	}
	svc.AttachCluster(c)
	return svc, c
}

// Once servers sign, a server makes the rows a create's platform volumes
// need, for the caller's own account, from its own settings; undo removes
// those it made that nothing is attached to.
func TestMakeCreateVolumeRows(t *testing.T) {
	ctx := teamCtx("payments")
	tenant := volumes.TenantForOwnerRef("team:payments")
	req := models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{
		{Name: "data", Path: "/data"}, {Name: "data", Path: "/data2"}, {Name: "kept", Path: "/kept"},
	}}
	svc, c := volumeServer(t, true)
	if _, _, err := c.VolumeUpsert(context.Background(), models.Volume{ID: "vol-kept", Tenant: tenant, Name: "kept", Backend: "s3", Source: "vols/pfx/" + tenant + "/kept"}, 0); err != nil {
		t.Fatal(err)
	}
	undo, err := svc.MakeCreateVolumeRows(ctx, req)
	if err != nil || undo == nil {
		t.Fatalf("make: %v, undo %v", err, undo != nil)
	}
	row, err := c.VolumeByName(context.Background(), tenant, "data")
	if err != nil || row.Source != "vols/pfx/"+tenant+"/data" {
		t.Fatalf("row %+v, %v", row, err)
	}
	undo()
	if _, err := c.VolumeByName(context.Background(), tenant, "data"); !errors.Is(err, cluster.ErrUnknownVolume) {
		t.Fatalf("undo left the row it made: %v", err)
	}
	if _, err := c.VolumeByName(context.Background(), tenant, "kept"); err != nil {
		t.Fatalf("undo removed a row it did not make: %v", err)
	}
	// Only rows it made: nothing to undo.
	if undo, err := svc.MakeCreateVolumeRows(ctx, models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{{Name: "kept", Path: "/k"}}}); err != nil || undo != nil {
		t.Fatalf("existing only: %v, %v", err, undo != nil)
	}
	// A later reference refused: the rows this call made go.
	_, err = svc.MakeCreateVolumeRows(ctx, models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{
		{Name: "fresh", Path: "/f"}, {Name: "kept", Path: "/k", DeleteWithSandbox: true},
	}})
	if !errors.Is(err, models.ErrPlatformVolumeConflict) {
		t.Fatalf("conflict = %v", err)
	}
	if _, err := c.VolumeByName(context.Background(), tenant, "fresh"); !errors.Is(err, cluster.ErrUnknownVolume) {
		t.Fatalf("a refused create left its row: %v", err)
	}
	if _, err := svc.MakeCreateVolumeRows(ctx, models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{{Name: "../x", Path: "/x"}}}); err == nil {
		t.Fatal("a bad name was taken")
	}
	// A row the store cannot make: the caller's answer.
	svc.testVolumeMeta = &scriptedVolumeMeta{getOrCreateErr: errors.New("leader gone")}
	if _, err := svc.MakeCreateVolumeRows(ctx, req); err == nil {
		t.Fatal("a failed row write passed")
	}
	svc.testVolumeMeta = nil
	// An operator with no operator scope and no admin token has no account.
	svc.cfg.PATToken, svc.cfg.OperatorVolumeScope = "", ""
	if _, err := svc.MakeCreateVolumeRows(controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess()), req); err == nil {
		t.Fatal("no scope passed")
	}
	svc.cfg.PlatformVolumes.Enabled = false
	if _, err := svc.MakeCreateVolumeRows(ctx, req); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
}

// A server makes no rows before servers sign, a worker never, and a create
// with no platform volume needs none.
func TestMakeCreateVolumeRowsOnlyOnASigningServer(t *testing.T) {
	req := models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}}}
	for name, svc := range map[string]*Service{
		"not signing": func() *Service { s, _ := volumeServer(t, false); return s }(),
		"a worker":    func() *Service { s, _ := volumeServer(t, true); s.cfg.NodeRole = config.NodeRoleWorker; return s }(),
	} {
		if undo, err := svc.MakeCreateVolumeRows(teamCtx("payments"), req); err != nil || undo != nil {
			t.Errorf("%s: %v, %v", name, err, undo != nil)
		}
	}
	svc, _ := volumeServer(t, true)
	if undo, err := svc.MakeCreateVolumeRows(teamCtx("payments"), models.CreateSandboxRequest{}); err != nil || undo != nil {
		t.Fatalf("no volumes: %v", err)
	}
	if !svc.IsClusterServer() || (*Service)(nil).IsClusterServer() {
		t.Fatal("IsClusterServer")
	}
}

// A worker sends a create that names a platform volume to a server once
// servers sign.
func TestCreateVolumeRowsGoToServers(t *testing.T) {
	req := models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}}}
	_, before, _, _, _ := signingPair(t)
	before.cfg.NodeRole = config.NodeRoleWorker
	if before.CreateVolumeRowsGoToServers(req) {
		t.Fatal("sent before servers sign")
	}
	server, worker, _, _, _ := signingPair(t)
	worker.cfg.NodeRole = config.NodeRoleWorker
	turnOnServerSigning(t, server, time.Now())
	if !worker.CreateVolumeRowsGoToServers(req) || worker.CreateVolumeRowsGoToServers(models.CreateSandboxRequest{}) {
		t.Fatal("a worker's create with a volume stays")
	}
	server.cfg.NodeRole = config.NodeRoleServer
	if server.CreateVolumeRowsGoToServers(req) {
		t.Fatal("a server sent its own create on")
	}
}

// The leader's refusal of a worker's row reaches the caller as a conflict
// that says where to send the create.
func TestWorkerRowRefusalSaysWhereToSendTheCreate(t *testing.T) {
	svc, _ := volumeServer(t, true)
	svc.testVolumeMeta = &scriptedVolumeMeta{getOrCreateErr: fmt.Errorf("relay: %w", cluster.ErrPeerProposalRefused)}
	_, _, err := svc.getOrCreateVolumeRow(teamCtx("payments"), svc.cfg.PlatformVolumes, "t-x", "data", models.PlatformVolumeMount{Name: "data"})
	if !errors.Is(err, models.ErrPlatformVolumeConflict) {
		t.Fatalf("refusal = %v", err)
	}
	svc.testVolumeMeta = &scriptedVolumeMeta{getOrCreateErr: errors.New("leader gone")}
	if _, _, err := svc.getOrCreateVolumeRow(teamCtx("payments"), svc.cfg.PlatformVolumes, "t-x", "data", models.PlatformVolumeMount{Name: "data"}); errors.Is(err, models.ErrPlatformVolumeConflict) {
		t.Fatalf("another failure read as a refusal: %v", err)
	}
}
