package cluster

import (
	"context"
	"testing"
	"time"
)

func TestClusterAuditACLReadWrappersAndExpiry(t *testing.T) {
	ctx := context.Background()
	if acl, ok, err := (*Cluster)(nil).AuditACLForSandbox(ctx, "sb"); err != nil || ok || acl.SandboxID != "" || acl.OwnerRef != "" {
		t.Fatalf("nil cluster ACL = %+v %v %v", acl, ok, err)
	}
	if owner, ok, err := (*Cluster)(nil).AuditOwnerRef(ctx, "sb"); err != nil || ok || owner != "" {
		t.Fatalf("nil cluster owner = %q %v %v", owner, ok, err)
	}

	fsm := newPlacementFSM()
	fsm.auditACLs["sb"] = AuditACL{
		SandboxID: "sb", OwnerRef: "tenant-a", IncarnationID: "inc-a",
		AuditNodeIDs: []string{"node-a", "node-b"}, ExpiresUnix: time.Now().Add(time.Hour).Unix(),
	}
	c := &Cluster{fsm: fsm}
	acl, ok, err := c.AuditACLForSandbox(ctx, " sb ")
	if err != nil || !ok || acl.OwnerRef != "tenant-a" || acl.IncarnationID != "inc-a" {
		t.Fatalf("cluster ACL = %+v %v %v", acl, ok, err)
	}
	acl.AuditNodeIDs[0] = "mutated"
	again, ok, err := c.AuditACLForSandbox(ctx, "sb")
	if err != nil || !ok || again.AuditNodeIDs[0] != "node-a" {
		t.Fatalf("cluster ACL was not cloned: %+v %v %v", again, ok, err)
	}
	owner, ok, err := c.AuditOwnerRef(ctx, "sb")
	if err != nil || !ok || owner != "tenant-a" {
		t.Fatalf("cluster owner = %q %v %v", owner, ok, err)
	}
	if err := c.PruneAuditACL(ctx, time.Now()); err != nil {
		t.Fatalf("cluster without raft prune = %v", err)
	}
	if err := c.PruneAuditACL(ctx, time.Time{}); err != nil {
		t.Fatalf("zero-cutoff prune = %v", err)
	}

	if got := auditACLExpiryUnix(0); got != 0 {
		t.Fatalf("disabled expiry = %d", got)
	}
	before := time.Now().Add(23*time.Hour + 59*time.Minute).Unix()
	after := time.Now().Add(24*time.Hour + time.Minute).Unix()
	if got := auditACLExpiryUnix(1); got < before || got > after {
		t.Fatalf("one-day expiry = %d, want [%d,%d]", got, before, after)
	}
}
