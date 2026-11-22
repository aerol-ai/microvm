package rootd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/xfsquota"
)

// Part "disk_quota" (M1 PR 7, plan §3.3 "Disk"): a hard limit on a
// container's writable layer, the XFS project quota sandboxd sets itself in
// privilege mode single (internal/runtime/containerd disk_quota.go).
//
//   - The folder comes from containerd's answer for the container's own
//     snapshot (snapshot.go): the snapshot's own folder,
//     <snapshotter root>/snapshots/<n>, which holds its writable layer and
//     overlayfs's work folder (rootpolicy.WritableLayer). Nothing outside
//     the snapshotter's root can be named.
//   - The project is <n> in AerolVM's own range (rootpolicy.QuotaProject),
//     never an operator's other XFS projects on the same volume.
//   - The bytes are bounded (rootpolicy.CheckQuotaBytes): at least a
//     gigabyte, so a request cannot lift a limit with zero.
//
// A create sends it with the container's other parts, before anything runs
// in the layer; a resize sends it alone.

// QuotaOps is the XFS project quota surface (Options.Quota): xfsquota.Ops,
// or a test's fake.
type QuotaOps interface {
	Enforced(dir string) error
	Assign(dir string, id uint32) error
	Limit(dir string, id uint32, bytes uint64) error
}

// quotaReady latches the check that the snapshots' filesystem enforces
// project quotas: a volume mounted without them accepts every limit and
// enforces none. A failed check is not latched (the lazy-latch shape of
// Service.EnsureLayer4Ready).
type quotaReady struct {
	ok atomic.Bool
	mu sync.Mutex
}

func (q *quotaReady) check(ops QuotaOps, dir string) error {
	if q.ok.Load() {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ok.Load() {
		return nil
	}
	if err := ops.Enforced(dir); err != nil {
		return err
	}
	q.ok.Store(true)
	return nil
}

// diskQuota sets part disk_quota on container id's writable layer.
func (c *containerCalls) diskQuota(ctx context.Context, id string, bytes uint64) error {
	ms, _, err := c.activeSnapshot(ctx, id)
	if err != nil {
		return err
	}
	dir, n, err := rootpolicy.WritableLayer(c.policy, ms)
	if err != nil {
		return refusedRule(codes.InvalidArgument, err)
	}
	project, err := rootpolicy.QuotaProject(n)
	if err != nil {
		return refusedRule(codes.InvalidArgument, err)
	}
	if err := c.ready.check(c.quota, dir); err != nil {
		return &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf(
			"root helper: disk limit: %s does not enforce project quotas (XFS mounted with prjquota, Linux 5.14 or later): %v", dir, err)}
	}
	if err := c.quota.Assign(dir, project); err != nil {
		return fmt.Errorf("root helper: disk limit: project %d on %s: %w", project, dir, err)
	}
	if err := c.quota.Limit(dir, project, bytes); err != nil {
		return fmt.Errorf("root helper: disk limit: %d bytes on project %d: %w", bytes, project, err)
	}
	return nil
}

// defaultQuota is the kernel's XFS project quotas.
var defaultQuota QuotaOps = xfsquota.Ops{}
