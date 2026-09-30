package cluster

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestCov96AuditACLIndexRebuildsFromMap(t *testing.T) {
	f := &placementFSM{
		auditACLs: map[string]AuditACL{
			"sb/inc": {
				SandboxID:       "sb",
				IncarnationID:   "inc",
				OwnerRef:        "acct",
				ExpiresUnix:     1_700_000_000,
				RetainedVersion: 4,
			},
			"sb/older": {
				SandboxID:       "sb",
				IncarnationID:   "older",
				ExpiresUnix:     1_600_000_000,
				RetainedVersion: 2,
			},
		},
	}
	f.ensureAuditACLIndexesLocked()
	if f.auditACLByVersion == nil || f.auditACLByExpiry == nil {
		t.Fatal("indexes were not built")
	}
	if f.auditACLByVersion.Len() != 2 {
		t.Fatalf("version index len = %d", f.auditACLByVersion.Len())
	}
	if got := f.auditACLLatest["sb"]; got == "" {
		t.Fatal("latest pointer was not rebuilt")
	}
	// Already-built indexes are left alone.
	f.ensureAuditACLIndexesLocked()
}

func TestCov96SnapshotReleaseAndCatalogCap(t *testing.T) {
	(&fsmSnapshot{}).Release()
	if MaxArtifactCatalogRowsPerNode() <= 0 {
		t.Fatal("catalog cap")
	}
}

func TestCov96SecretFanoutNilCluster(t *testing.T) {
	ctx := context.Background()
	blob := secrets.SecretBlob{SandboxID: "sb", Ref: "ref"}
	if _, err := (*Cluster)(nil).PushSecretBlobToAnyPeer(ctx, blob, []string{"peer"}); err == nil {
		t.Fatal("nil cluster with a remote recipient")
	}
	if _, err := (*Cluster)(nil).PushSecretBlobToAnyPeer(ctx, blob, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Cluster{}).PushSecretBlobToAnyPeer(ctx, blob, []string{"peer"}); err == nil {
		t.Fatal("cluster without gossip")
	}
	if _, err := (&Cluster{nodeID: "self"}).PushSecretBlobToAnyPeer(ctx, blob, []string{"self"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (*Agent)(nil).PushSecretBlobToAnyPeer(ctx, blob, []string{"peer"}); err == nil {
		t.Fatal("nil agent with a remote recipient")
	}
	if _, err := (&Agent{}).PushSecretBlobToAnyPeer(ctx, blob, []string{"peer"}); err == nil {
		t.Fatal("agent without gossip")
	}
	if _, err := (*Cluster)(nil).DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); err == nil {
		t.Fatal("nil cluster delete")
	}
	if _, err := (&Cluster{}).DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); err == nil {
		t.Fatal("cluster delete without gossip")
	}
	if _, err := (*Agent)(nil).DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); err == nil {
		t.Fatal("nil agent delete")
	}
	if _, err := (&Agent{}).DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); err == nil {
		t.Fatal("agent delete without gossip")
	}
}
