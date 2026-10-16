// Package auditwitness supplies an off-node audit witness to the open-source
// build: a controlplane.Witness that writes each audit hash-chain head to an
// S3 bucket with Object Lock, so the node that wrote a head can never change
// or remove it (plans/open-audit-witness.md).
//
// Enterprise mode refuses to boot on a placeholder witness. Until this
// package, only a managed build's provider could satisfy that gate; now
// SB_AUDIT_WITNESS_BACKEND=s3 does. A provider-supplied witness still wins:
// pkg/daemon only calls Open when the provider brought none.
//
// There is deliberately no backend registry (D1): Open switches on the name,
// and a second backend is one more case.
package auditwitness

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// BackendS3 is the only backend in v1. The setting is SB_AUDIT_WITNESS_BACKEND.
const BackendS3 = "s3"

// DefaultPrefix is the key prefix when SB_AUDIT_WITNESS_S3_PREFIX is unset.
const DefaultPrefix = "witness/"

// StandaloneNodeID is the id every single server falls back to without
// SB_NODE_ID. Two servers sharing a bucket would write the same keys under
// it, so the witness never reads or writes it (D3, D24).
const StandaloneNodeID = "standalone"

// bootDeadline bounds every boot check together. Without it an unreachable
// endpoint (a missing VPC endpoint, say) stalls boot for the SDK's dial
// timeout times its retries and then reports a bare dial error that never
// mentions the witness (D9).
const bootDeadline = 30 * time.Second

// Config selects and configures the witness. internal/config builds it from
// the environment; this package only validates and opens.
type Config struct {
	Backend string
	// NodeID is SB_NODE_ID. It names the canary key; heads carry their own.
	NodeID string
	// RetentionDays is SB_SECRET_AUDIT_RETENTION_DAYS: a witnessed head must
	// stay locked at least as long as the local records it vouches for.
	RetentionDays int
	S3            auditexport.S3Config
}

// Open builds the configured witness and refuses to return one whose bucket
// would not really protect what it stores. Every boot check runs under one
// 30 s deadline; a failure names the check, the bucket and the fix.
func Open(ctx context.Context, cfg Config) (controlplane.Witness, error) {
	switch strings.TrimSpace(cfg.Backend) {
	case BackendS3:
	case "":
		return nil, errors.New("audit witness: no backend configured (SB_AUDIT_WITNESS_BACKEND)")
	default:
		return nil, fmt.Errorf("audit witness: unknown backend %q (SB_AUDIT_WITNESS_BACKEND supports %q)", cfg.Backend, BackendS3)
	}
	if err := validateNodeID(cfg.NodeID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.S3.Bucket) == "" {
		return nil, errors.New("audit witness s3: SB_AUDIT_WITNESS_S3_BUCKET is required")
	}
	ctx, cancel := context.WithTimeout(ctx, bootDeadline)
	defer cancel()
	client, err := auditexport.NewS3Client(ctx, cfg.S3)
	if err != nil {
		return nil, fmt.Errorf("audit witness s3: %w", err)
	}
	w := newS3Witness(client, cfg)
	if err := w.bootChecks(ctx, bootDeadline); err != nil {
		return nil, err
	}
	return w, nil
}

func validateNodeID(id string) error {
	switch strings.TrimSpace(id) {
	case "":
		return errors.New("audit witness: SB_NODE_ID is required: heads are stored per node id, and it must be unique among servers sharing the bucket")
	case StandaloneNodeID:
		return fmt.Errorf("audit witness: SB_NODE_ID must not be %q: every single server defaults to it, so servers sharing the bucket would overwrite each other's heads", StandaloneNodeID)
	}
	return nil
}
