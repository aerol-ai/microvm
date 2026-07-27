package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// defaultTemplateBuildTimeout is the fallback when
// cfg.FirecrackerTemplateBuildTimeout is unset/zero (mostly in unit tests
// that construct a Service against a partial Config). Production daemons
// always carry a non-zero timeout out of config.Load.
const defaultTemplateBuildTimeout = 45 * time.Minute

// snapshotMemoryFilename / snapshotStateFilename / templateManifestFilename
// are the on-disk names the snapshot phase writes alongside rootfs.ext4.
// Hardcoded (rather than configurable) because debug runbooks reference
// them by name — turning them into knobs would let two operators on
// adjacent hosts see different layouts.
const (
	snapshotMemoryFilename   = "snapshot.memory"
	snapshotStateFilename    = "snapshot.state"
	templateManifestFilename = "manifest.json"
)

// TemplateBuildRequest is the small struct passed to TemplateBuilder.
// Mirrors pkg/oci.BuildRequest by name and shape so the production
// adapter is a one-field cast; declared locally so the service package
// does not import pkg/oci (which would pull internal/runtime/firecracker
// concerns into the service-layer dependency graph). Exported so the
// adapter in cmd/sandboxd can implement the interface.
type TemplateBuildRequest struct {
	ImageRef   string
	OutPath    string
	MinSizeMiB int
	Tag        string
}

// TemplateBuildResult is the subset of pkg/oci.Result the template
// service actually consumes; carried as a separate struct so the
// interface stays minimal.
type TemplateBuildResult struct {
	RootfsPath string
	StagingDir string
	SizeBytes  int64
}

// TemplateBuilder is the seam the template service uses to invoke the
// OCI→ext4 pipeline. Production wires this to pkg/oci.Builder via a
// thin adapter in cmd/sandboxd/main.go; tests stub it to skip real
// subprocesses. The interface intentionally mirrors pkg/oci's surface
// — keeping the shapes identical means the adapter is trivial and the
// service's mental model matches the real builder.
type TemplateBuilder interface {
	Build(ctx context.Context, req TemplateBuildRequest) (*TemplateBuildResult, error)
}

// TemplateSnapshotRequest is the input for the Phase 3 snapshot phase.
// RootfsPath is the absolute on-disk location of the rootfs.ext4 produced
// by the rootfs phase; the snapshotter mounts it as the boot drive. Out*
// paths are absolute file paths under the per-template dir where the
// snapshotter writes snapshot.memory and snapshot.state. GuestCID is the
// host-side AF_VSOCK CID the snapshotter will configure the transient
// template VMM with — re-used by every later clone load so the snapshot
// state's vsock device stays consistent. MemoryMB/VCPU are the transient
// VMM's resource budget; they also become the resumed clone's effective
// resources (Firecracker bakes them into the snapshot state).
type TemplateSnapshotRequest struct {
	TemplateID    string
	RootfsPath    string
	OutMemoryPath string
	OutStatePath  string
	GuestCID      uint32
	MemoryMB      int
	VCPU          int
}

// TemplateSnapshotResult is what the snapshot phase returns. Checksum is
// "sha256:<hex>|sha256:<hex>" (memory|state) so a later load can verify
// integrity in O(read) without re-decoding the format. The two size
// fields are reported separately for operator-facing metrics; the store
// persists their sum.
type TemplateSnapshotResult struct {
	MemorySizeBytes int64
	StateSizeBytes  int64
	Checksum        string
}

// TemplateSnapshotter is the seam the template service uses to capture
// the Phase 3 snapshot. Production wires this to *firecracker.Driver via
// an adapter in cmd/sandboxd/main.go; the driver owns the transient VMM
// lifecycle because it already owns the VMM/network seams. Tests stub it
// to skip the real Firecracker subprocess.
type TemplateSnapshotter interface {
	SnapshotTemplate(ctx context.Context, req TemplateSnapshotRequest) (*TemplateSnapshotResult, error)
}

// TemplateCIDAllocator reserves the per-template host-side AF_VSOCK CID
// the snapshot is captured with and that every later clone reuses. The
// production impl wraps *internal/network/tap.Pool's Allocate/Release —
// the same primitive used for per-sandbox slot allocation — keyed by a
// synthetic "template:<id>" sandbox id so the pool's per-id PK gives us
// idempotent reservation. Declared in the service package so template.go
// does not have to import internal/network/tap.
type TemplateCIDAllocator interface {
	AllocateForTemplate(ctx context.Context, templateID string) (uint32, error)
	ReleaseForTemplate(ctx context.Context, templateID string) error
}

// SetTemplateBuilder is the bootstrap-time wiring hook called once from
// main.go after the daemon has constructed pkg/oci.Builder. Idempotent:
// passing nil disables template create (the handler returns 503) without
// tearing down existing template rows.
func (s *Service) SetTemplateBuilder(b TemplateBuilder) {
	s.templateBuilder = b
}

// SetTemplateSnapshotter wires the Phase 3 snapshot-capture seam. Nil
// disables the second build phase — new templates still get a rootfs but
// land in status=ready_no_snapshot, and CreateSandbox cold-boots from
// them. Useful for hosts where the snapshotter is misbehaving.
func (s *Service) SetTemplateSnapshotter(snap TemplateSnapshotter) {
	s.templateSnapshotter = snap
}

// SetTemplateCIDAllocator wires the per-template CID reservation seam.
// Nil disables the snapshot phase (same effect as a nil snapshotter):
// without a reserved CID the snapshot would clash with the next sandbox
// slot allocation. The setter is separate so main.go can wire the two
// independently — handy when one of them is being swapped out.
func (s *Service) SetTemplateCIDAllocator(a TemplateCIDAllocator) {
	s.templateCIDAllocator = a
}

// CreateTemplate accepts a build request, persists a PENDING row, and
// kicks off the background build. The handler renders the returned row
// as 202 — callers poll GET /v1/templates/{id} to observe the
// READY/FAILED transition. Build errors do NOT bubble back through the
// API; they land in the row's last_error so the operator sees them on
// poll. This matches the snapshot-push reconciler's async shape.
func (s *Service) CreateTemplate(ctx context.Context, req models.CreateTemplateRequest) (*models.Template, error) {
	if !s.cfg.EnableFirecracker {
		return nil, fmt.Errorf("template create requires SB_ENABLE_FIRECRACKER: %w", models.ErrRuntimeNotImplemented)
	}
	if s.templateBuilder == nil {
		return nil, errors.New("template builder is not configured")
	}
	image := strings.TrimSpace(req.Image)
	if image == "" {
		return nil, errors.New("image is required")
	}
	if req.MinSizeMiB < 0 {
		return nil, errors.New("min_size_mib must be >= 0")
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		generated, err := generateTemplateID()
		if err != nil {
			return nil, fmt.Errorf("generate template id: %w", err)
		}
		id = generated
	}

	now := time.Now().UTC()
	template := &models.Template{
		ID:         id,
		Image:      image,
		Status:     models.TemplateStatusPending,
		MinSizeMiB: req.MinSizeMiB,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.CreateTemplate(ctx, template); err != nil {
		return nil, err
	}

	s.kickTemplateBuild(template)
	return template, nil
}

// kickTemplateBuild spawns the per-request build goroutine. Two-phase
// pipeline (PR-A): the rootfs phase runs the OCI→ext4 pipeline as
// before; the snapshot phase (when wired and not gated off) boots a
// transient VMM, captures snapshot.memory + snapshot.state, and stamps
// the integrity checksum. Status transitions reflect the phase:
//
//	pending → building_rootfs → snapshotting → ready
//	pending → building_rootfs → failed                  (rootfs broke)
//	pending → building_rootfs → snapshotting → ready_no_snapshot
//	                                            (rootfs OK, snapshot broke)
//	pending → building_rootfs → ready_no_snapshot
//	                                  (snapshotter or allocator not wired)
//
// Detached context + absolute timeout match kickSnapshotPushReconciler:
// the goroutine outlives the HTTP handler and a wedged subprocess /
// hung VMM cannot pin it forever. ready_no_snapshot is the
// rootfs-only fallback — CreateSandbox still works, just via cold-boot.
func (s *Service) kickTemplateBuild(template *models.Template) {
	id := template.ID
	dir := filepath.Join(s.cfg.FirecrackerTemplatesDir, id)
	rootfsOut := filepath.Join(dir, "rootfs.ext4")
	memOut := filepath.Join(dir, snapshotMemoryFilename)
	stateOut := filepath.Join(dir, snapshotStateFilename)

	timeout := s.cfg.FirecrackerTemplateBuildTimeout
	if timeout <= 0 {
		timeout = defaultTemplateBuildTimeout
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// ----- Phase A: rootfs -----
		if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusBuildingRootfs, "", "", 0); uerr != nil {
			s.logger.Warn("template build: status update to building_rootfs failed", "template_id", id, "error", uerr)
			// Continue: a stale status row is recoverable; bailing now
			// leaves the on-disk artifacts unbuilt with no chance of
			// recovery on the next request.
		}

		var (
			result *TemplateBuildResult
			err    error
		)
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			err = fmt.Errorf("mkdir template dir: %w", mkErr)
		} else {
			result, err = s.templateBuilder.Build(ctx, TemplateBuildRequest{
				ImageRef:   template.Image,
				OutPath:    rootfsOut,
				MinSizeMiB: template.MinSizeMiB,
				Tag:        "latest",
			})
		}
		if err != nil {
			// Rootfs phase failed: drop the half-built artifact dir,
			// mark FAILED, return. No snapshot artifacts exist yet.
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				s.logger.Warn("template build: rootfs failure cleanup failed", "template_id", id, "error", rmErr)
			}
			if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusFailed, "", err.Error(), 0); uerr != nil {
				s.logger.Warn("template build: status update to failed failed", "template_id", id, "error", uerr)
			}
			s.logger.Info("audit template build finished", "template_id", id, "status", models.TemplateStatusFailed, "phase", "rootfs", "error", err.Error())
			return
		}

		var rootfsSizeBytes int64
		if result != nil {
			rootfsSizeBytes = result.SizeBytes
			if result.StagingDir != "" {
				if rmErr := os.RemoveAll(result.StagingDir); rmErr != nil {
					s.logger.Warn("template build: staging cleanup failed", "template_id", id, "error", rmErr)
				}
			}
		}

		// ----- Decide whether to enter the snapshot phase -----
		// Skip when gated off OR when either seam is missing. The
		// ready_no_snapshot terminal state is correct in both cases:
		// the rootfs is on disk, CreateSandbox cold-boots from it.
		snapshotEligible := s.cfg.FirecrackerSnapshotEnabled &&
			s.templateSnapshotter != nil &&
			s.templateCIDAllocator != nil
		if !snapshotEligible {
			reason := "snapshot phase disabled"
			if s.templateSnapshotter == nil {
				reason = "snapshotter seam not wired"
			} else if s.templateCIDAllocator == nil {
				reason = "cid allocator seam not wired"
			} else if !s.cfg.FirecrackerSnapshotEnabled {
				reason = "SB_FIRECRACKER_SNAPSHOT_ENABLED=false"
			}
			s.logger.Info("template build: skipping snapshot phase", "template_id", id, "reason", reason)
			if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusReadyNoSnapshot, rootfsOut, "", rootfsSizeBytes); uerr != nil {
				s.logger.Warn("template build: status update to ready_no_snapshot failed", "template_id", id, "error", uerr)
			}
			s.logger.Info("audit template build finished", "template_id", id, "status", models.TemplateStatusReadyNoSnapshot, "size_bytes", rootfsSizeBytes)
			return
		}

		// Reserve a host-side CID for this template before flipping to
		// snapshotting — a failure here means we never advertised the
		// transitional state, which keeps the row visible as "rootfs
		// just landed" while the operator investigates.
		cid, cidErr := s.templateCIDAllocator.AllocateForTemplate(ctx, id)
		if cidErr != nil {
			s.logger.Warn("template build: cid allocate failed; cold-boot only", "template_id", id, "error", cidErr)
			snapErrMsg := fmt.Sprintf("cid allocate: %s", cidErr.Error())
			if uerr := s.store.UpdateTemplateSnapshotFailed(ctx, id, snapErrMsg); uerr != nil {
				s.logger.Warn("template build: snapshot_error update failed", "template_id", id, "error", uerr)
			}
			if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusReadyNoSnapshot, rootfsOut, "", rootfsSizeBytes); uerr != nil {
				s.logger.Warn("template build: status update to ready_no_snapshot failed", "template_id", id, "error", uerr)
			}
			s.logger.Info("audit template build finished", "template_id", id, "status", models.TemplateStatusReadyNoSnapshot, "size_bytes", rootfsSizeBytes)
			return
		}

		// ----- Phase B: snapshot -----
		if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusSnapshotting, rootfsOut, "", rootfsSizeBytes); uerr != nil {
			s.logger.Warn("template build: status update to snapshotting failed", "template_id", id, "error", uerr)
		}
		snap, snapErr := s.templateSnapshotter.SnapshotTemplate(ctx, TemplateSnapshotRequest{
			TemplateID:    id,
			RootfsPath:    rootfsOut,
			OutMemoryPath: memOut,
			OutStatePath:  stateOut,
			GuestCID:      cid,
			MemoryMB:      s.cfg.FirecrackerTemplateMemoryMB,
			VCPU:          s.cfg.FirecrackerTemplateVCPU,
		})
		if snapErr != nil {
			// Snapshot phase failed but rootfs is fine. Release the CID
			// so the next snapshot attempt (after a manual recovery)
			// gets a clean slot, mark ready_no_snapshot, capture the
			// error on the row.
			if relErr := s.templateCIDAllocator.ReleaseForTemplate(ctx, id); relErr != nil {
				s.logger.Warn("template build: cid release after snapshot failure failed", "template_id", id, "error", relErr)
			}
			if uerr := s.store.UpdateTemplateSnapshotFailed(ctx, id, snapErr.Error()); uerr != nil {
				s.logger.Warn("template build: snapshot_error update failed", "template_id", id, "error", uerr)
			}
			if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusReadyNoSnapshot, rootfsOut, "", rootfsSizeBytes); uerr != nil {
				s.logger.Warn("template build: status update to ready_no_snapshot failed", "template_id", id, "error", uerr)
			}
			s.logger.Info("audit template build finished", "template_id", id, "status", models.TemplateStatusReadyNoSnapshot, "size_bytes", rootfsSizeBytes, "snapshot_error", snapErr.Error())
			return
		}

		// Both phases succeeded. Persist snapshot fields first, then
		// flip the status — a crash between the two would leave the
		// snapshot fields populated under status=snapshotting, which is
		// observably wrong but harmless (the next request still works
		// against the rootfs).
		snapshotSize := snap.MemorySizeBytes + snap.StateSizeBytes
		// hasOverlay=true: every PR-B snapshot capture includes the
		// overlay drive placeholder, so this template is safe to clone
		// with an OverlaySizeGB request. PR-A templates that pre-dated
		// the placeholder logic keep has_overlay=0 via the column
		// default, and the runtime rejects an overlay request against
		// them with a clear "rebuild template" error.
		if uerr := s.store.UpdateTemplateSnapshotReady(ctx, id, memOut, stateOut, snapshotSize, snap.Checksum, cid, true); uerr != nil {
			s.logger.Warn("template build: snapshot ready update failed", "template_id", id, "error", uerr)
			// Don't try to roll back — the on-disk artifacts are valid,
			// the row is just stale. Operators can re-trigger the build.
		}
		if uerr := s.store.UpdateTemplateStatus(ctx, id, models.TemplateStatusReady, rootfsOut, "", rootfsSizeBytes); uerr != nil {
			s.logger.Warn("template build: final status update failed", "template_id", id, "error", uerr)
		}
		// Phase 6 PR 6-B.1: flag the just-built template for AOCR push so
		// peer nodes can pull it (consumer side lands in PR 6-B.2). When
		// the pusher isn't wired (single-node / push disabled) both calls
		// are cheap no-ops, keeping single-node behavior byte-identical.
		// Order matters: mark-then-kick so the reconciler tick sees the
		// row in push_state=pending instead of racing the UPDATE.
		if s.markTemplateForPush(ctx, id) {
			s.kickTemplateArtifactPushReconciler(id)
		}
		// manifest.json is operator-facing debug aid; truth of record
		// lives in the SQLite row, so write failures are logged-and-go.
		if mErr := writeTemplateManifest(filepath.Join(dir, templateManifestFilename), templateManifest{
			SourceImage:      template.Image,
			SnapshotChecksum: snap.Checksum,
			VsockCID:         cid,
			CreatedAt:        time.Now().UTC(),
		}); mErr != nil {
			s.logger.Warn("template build: manifest write failed", "template_id", id, "error", mErr)
		}
		s.logger.Info("audit template build finished", "template_id", id, "status", models.TemplateStatusReady, "size_bytes", rootfsSizeBytes, "snapshot_size_bytes", snapshotSize, "vsock_cid", cid)
	}()
}

// templateManifest is the on-disk operator-facing summary. JSON-encoded
// so `cat manifest.json | jq` works during incident response. The struct
// is unexported because nothing outside this package should depend on
// its shape — the SQLite row is the contract.
type templateManifest struct {
	SourceImage      string    `json:"source_image"`
	SnapshotChecksum string    `json:"snapshot_checksum"`
	VsockCID         uint32    `json:"vsock_cid"`
	CreatedAt        time.Time `json:"created_at"`
}

func writeTemplateManifest(path string, m templateManifest) error {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0o644)
}

// GetTemplate is the read path behind GET /v1/templates/{id}. Returns the
// store row unchanged — status is whatever the build goroutine last
// wrote, so a freshly-created template reads as PENDING until the
// goroutine flips it.
func (s *Service) GetTemplate(ctx context.Context, id string) (*models.Template, error) {
	return s.store.GetTemplate(ctx, id)
}

// ListTemplates is the read path behind GET /v1/templates. Returns rows
// in newest-first order matching the snapshot list shape.
func (s *Service) ListTemplates(ctx context.Context) ([]*models.Template, error) {
	return s.store.ListTemplates(ctx)
}

// DeleteTemplate refuses when an active sandbox still references the
// template — yanking the rootfs out from under a running Firecracker
// guest would surface as a delayed I/O error inside the guest, hours
// after the operator's action. The 409 forces the operator to destroy
// the sandbox first. Best-effort artifact cleanup runs before the row
// delete: a half-cleaned dir on disk is fine (GC catches it), a missing
// row with an orphan dir is the painful case (no one will ever clean
// it). Pending rows are also rejected — a delete that races the build
// goroutine would leave the goroutine writing to a directory the
// operator believed was gone.
func (s *Service) DeleteTemplate(ctx context.Context, id string) error {
	template, err := s.store.GetTemplate(ctx, id)
	if err != nil {
		return err
	}
	// Reject the intermediate states too — the build goroutine is
	// still writing to dir on disk and will overwrite the row's status
	// after we return. Letting the delete proceed would race the
	// goroutine into either resurrecting the row (status update wins)
	// or being unable to find its own files (delete wins).
	switch template.Status {
	case models.TemplateStatusPending, models.TemplateStatusBuildingRootfs, models.TemplateStatusSnapshotting:
		return fmt.Errorf("template %q is still building (%s): %w", id, template.Status, store.ErrTemplateInUse)
	}
	referenced, err := s.store.IsTemplateReferenced(ctx, id)
	if err != nil {
		return err
	}
	if referenced {
		return store.ErrTemplateInUse
	}
	vmmReferenced, err := s.store.IsTemplateReferencedByVMM(ctx, id)
	if err != nil {
		return err
	}
	if vmmReferenced {
		return store.ErrTemplateInUse
	}
	// Release the per-template CID reservation before dropping the row.
	// The allocator is keyed on the template id, so a delete-then-recreate
	// cycle gets a fresh slot (idempotent re-reservation against a stale
	// row would otherwise fail).
	if template.HasSnapshot && s.templateCIDAllocator != nil {
		if relErr := s.templateCIDAllocator.ReleaseForTemplate(ctx, id); relErr != nil {
			s.logger.Warn("template delete: cid release failed", "template_id", id, "error", relErr)
		}
	}
	if template.RootfsPath != "" {
		dir := filepath.Dir(template.RootfsPath)
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			s.logger.Warn("template delete: rootfs cleanup failed", "template_id", id, "error", rmErr)
		}
	}
	return s.store.DeleteTemplate(ctx, id)
}

// StartTemplateGC launches the periodic janitor that drops unreferenced
// templates. Shape mirrors StartBuiltImageGC verbatim: ticker +
// context-cancellation, per-tick bounded sweep context, best-effort log
// on failures. No-op when SB_ENABLE_FIRECRACKER=false (templates can't
// exist on those nodes) or when the GC enable knob is off — the latter
// gives operators a way to pause cleanup during a forensic window
// without recompiling.
func (s *Service) StartTemplateGC(ctx context.Context) {
	if !s.cfg.EnableFirecracker {
		return
	}
	if !s.cfg.FirecrackerTemplateGCEnabled {
		return
	}
	interval := s.cfg.FirecrackerTemplateGCInterval
	if interval <= 0 {
		return
	}
	s.startPeriodic(ctx, interval, 30*time.Second, func(c context.Context) {
		s.runTemplateGC(c, time.Now())
	})
}

// runTemplateGC is one pass of the template janitor. Split from
// StartTemplateGC so tests can drive a single deterministic tick
// without a ticker. olderThanNow is "wall clock now from the caller's
// perspective"; the cutoff is now - TTL. Failures are logged, not
// returned — the next tick retries.
func (s *Service) runTemplateGC(ctx context.Context, now time.Time) {
	cutoff := now.UTC().Add(-s.cfg.FirecrackerTemplateGCTTL)
	templates, err := s.store.ListGCEligibleTemplates(ctx, cutoff)
	if err != nil {
		s.logger.Warn("template gc list failed", "error", err)
		return
	}
	if s.testAfterTemplateGCList != nil {
		s.testAfterTemplateGCList()
	}
	for _, t := range templates {
		// Double-check IsTemplateReferenced under the same context — a
		// CreateSandbox(template_id=t.id) that landed between the list
		// query and this loop would otherwise lose its template out from
		// under it. The list query also filters by reference; the check
		// here is the belt-and-suspenders.
		referenced, err := s.store.IsTemplateReferenced(ctx, t.ID)
		if err != nil {
			s.logger.Warn("template gc reference check failed", "template_id", t.ID, "error", err)
			continue
		}
		if referenced {
			continue
		}
		if s.testAfterTemplateGCSandboxRefCheck != nil {
			s.testAfterTemplateGCSandboxRefCheck()
		}
		vmmReferenced, err := s.store.IsTemplateReferencedByVMM(ctx, t.ID)
		if err != nil {
			s.logger.Warn("template gc vmm reference check failed", "template_id", t.ID, "error", err)
			continue
		}
		if vmmReferenced {
			continue
		}
		if s.testAfterTemplateGCVMMRefCheck != nil {
			s.testAfterTemplateGCVMMRefCheck()
		}
		// Release the per-template CID before the row goes. Same shape as
		// DeleteTemplate — the GC sweeper's responsibilities are a strict
		// superset of the API-driven delete.
		if t.HasSnapshot && s.templateCIDAllocator != nil {
			if relErr := s.templateCIDAllocator.ReleaseForTemplate(ctx, t.ID); relErr != nil {
				s.logger.Warn("template gc cid release failed", "template_id", t.ID, "error", relErr)
			}
		}
		if t.RootfsPath != "" {
			dir := filepath.Dir(t.RootfsPath)
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				s.logger.Warn("template gc rootfs cleanup failed", "template_id", t.ID, "error", rmErr)
				// Continue to delete the row anyway — a stale dir is
				// recoverable (operator can rm -rf), a stale row pointing
				// at a missing file is much worse.
			}
		}
		if err := s.store.DeleteTemplate(ctx, t.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("template gc row delete failed", "template_id", t.ID, "error", err)
			continue
		}
		s.logger.Info("audit template gc removed", "template_id", t.ID, "status", t.Status, "updated_at", t.UpdatedAt)
	}
}

// generateTemplateID returns "tpl-<16 hex chars>". Same shape as
// generateSandboxID — different prefix so a glance at the ID
// immediately distinguishes a template from a sandbox.
func generateTemplateID() (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return "tpl-" + hex.EncodeToString(buf), nil
}
