package cluster

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClusterVolumeClientRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}

	c, cleanup := newTestCluster(t, "ldr-vol-client", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	v := models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	row, created, err := c.VolumeUpsert(ctx, v, 0)
	if err != nil || !created || row.ID != "vol-1" {
		t.Fatalf("VolumeUpsert = %+v created=%v err=%v", row, created, err)
	}
	if _, created, err := c.VolumeUpsert(ctx, v, 0); err != nil || created {
		t.Fatalf("idempotent VolumeUpsert created=%v err=%v", created, err)
	}
	if got, err := c.VolumeByID(ctx, "t-a", "vol-1"); err != nil || got.Name != "data" {
		t.Fatalf("VolumeByID = %+v, %v", got, err)
	}
	vols, err := c.VolumesForTenant(ctx, "t-a")
	if err != nil || len(vols) != 1 {
		t.Fatalf("VolumesForTenant = %+v, %v", vols, err)
	}
	if exists, err := c.VolumeExistsForSource(ctx, "bucket/t-a/data"); err != nil || !exists {
		t.Fatalf("VolumeExistsForSource = %v, %v", exists, err)
	}

	attach := models.VolumeAttachment{
		Tenant: "t-a", VolumeID: "vol-1", SandboxID: "sb-1", Target: "/data", Source: "bucket/t-a/data",
	}
	if err := c.PutVolumeAttachments(ctx, []models.VolumeAttachment{attach}); err != nil {
		t.Fatalf("PutVolumeAttachments: %v", err)
	}
	count, err := c.VolumeAttachmentCount(ctx, "t-a", "vol-1")
	if err != nil || count != 1 {
		t.Fatalf("VolumeAttachmentCount = %d, %v", count, err)
	}
	if err := c.VolumeDelete(ctx, "t-a", "vol-1"); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("VolumeDelete attached = %v, want ErrVolumeInUse", err)
	}
	if err := c.DeleteVolumeAttachmentsForSandbox(ctx, "sb-1"); err != nil {
		t.Fatalf("DeleteVolumeAttachmentsForSandbox: %v", err)
	}
	if err := c.VolumeDelete(ctx, "t-a", "vol-1"); err != nil {
		t.Fatalf("VolumeDelete: %v", err)
	}
	if _, err := c.VolumeByID(ctx, "t-a", "vol-1"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("VolumeByID after delete = %v", err)
	}
}

func TestClusterVolumeUpsertReadbackOnFollower(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}

	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	leaderAPIURL := "http://" + apiListener.Addr().String()

	leader, cleanupLeader := newTestClusterWithAPI(t, "ldr-vol-rb", true, nil, leaderAPIURL)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	srv := startInternalApplyServer(t, leader, apiListener)
	defer srv.Close()

	follower, cleanupFollower := newTestCluster(t, "fol-vol-rb", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, "fol-vol-rb", 20*time.Second)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.HasPrefix(follower.LeaderAPIURL(), "http://") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := follower.LeaderAPIURL(); !strings.HasPrefix(got, "http://") {
		t.Fatalf("follower never resolved leader API URL (got %q)", got)
	}

	ctx := context.Background()
	v := models.Volume{ID: "vol-rb", Tenant: "t-a", Name: "logs", Backend: "s3", Source: "bucket/t-a/logs"}
	row, created, err := follower.VolumeUpsert(ctx, v, 0)
	if err != nil || !created || row.ID != "vol-rb" {
		t.Fatalf("follower VolumeUpsert = %+v created=%v err=%v", row, created, err)
	}
}

func TestClusterVolumeClientValidation(t *testing.T) {
	c := &Cluster{}
	ctx := context.Background()

	_, _, err := c.VolumeUpsert(ctx, models.Volume{Tenant: "t-a", Name: "n"}, 0)
	if err == nil {
		t.Fatal("VolumeUpsert missing id/backend: expected error")
	}
	if err := c.VolumeDelete(ctx, "", "vol-1"); err == nil {
		t.Fatal("VolumeDelete empty tenant: expected error")
	}
	if err := c.PutVolumeAttachments(ctx, nil); err != nil {
		t.Fatalf("PutVolumeAttachments empty: %v", err)
	}
	if err := c.DeleteVolumeAttachmentsForSandbox(ctx, "  "); err != nil {
		t.Fatalf("DeleteVolumeAttachmentsForSandbox whitespace: %v", err)
	}
}
