package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// templateBuildTimeout caps how long a single async build goroutine may
// run before its context is cancelled. Half an hour is comfortably above
// every real-world skopeo+umoci+mkfs pipeline we've measured on the
// fattest CUDA bases; the cap exists to bound stuck builds (network
// stall to the registry, runaway mkfs on a corrupt rootfs) rather than
// to fail healthy ones.
const templateBuildTimeout = 30 * time.Minute

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

// SetTemplateBuilder is the bootstrap-time wiring hook called once from
// main.go after the daemon has constructed pkg/oci.Builder. Idempotent:
// passing nil disables template create (the handler returns 503) without
// tearing down existing template rows.
func (s *Service) SetTemplateBuilder(b TemplateBuilder) {
	s.templateBuilder = b
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

// kickTemplateBuild spawns the per-request build goroutine. Same shape as
// kickSnapshotPushReconciler: detach from the request context (the
// goroutine outlives the HTTP handler), apply an absolute timeout so a
// wedged subprocess can't pin the goroutine forever, and surface the
// result through UpdateTemplateStatus. Best-effort cleanup of the
// staging directory regardless of outcome.
func (s *Service) kickTemplateBuild(template *models.Template) {
	id := template.ID
	dir := filepath.Join(s.cfg.FirecrackerTemplatesDir, id)
	outPath := filepath.Join(dir, "rootfs.ext4")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), templateBuildTimeout)
		defer cancel()

		var (
			result *TemplateBuildResult
			err    error
		)
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			err = fmt.Errorf("mkdir template dir: %w", mkErr)
		} else {
			result, err = s.templateBuilder.Build(ctx, TemplateBuildRequest{
				ImageRef:   template.Image,
				OutPath:    outPath,
				MinSizeMiB: template.MinSizeMiB,
				Tag:        "latest",
			})
		}

		status := models.TemplateStatusReady
		rootfsPath := outPath
		var sizeBytes int64
		var lastErr string
		if err != nil {
			status = models.TemplateStatusFailed
			lastErr = err.Error()
			// Drop the half-built artifact dir on failure — the row remains
			// for the operator to inspect, but the bytes do not. GC owns the
			// row teardown once nothing references it.
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				s.logger.Warn("template build: cleanup failed", "template_id", id, "error", rmErr)
			}
			rootfsPath = ""
		} else if result != nil {
			sizeBytes = result.SizeBytes
			// Always best-effort drop the OCI/umoci staging tree —
			// rootfs.ext4 has been written to dir/, the staging tree is
			// pure intermediate state.
			if result.StagingDir != "" {
				if rmErr := os.RemoveAll(result.StagingDir); rmErr != nil {
					s.logger.Warn("template build: staging cleanup failed", "template_id", id, "error", rmErr)
				}
			}
		}

		if uerr := s.store.UpdateTemplateStatus(ctx, id, status, rootfsPath, lastErr, sizeBytes); uerr != nil {
			s.logger.Warn("template build: status update failed", "template_id", id, "status", status, "error", uerr)
			return
		}
		s.logger.Info("audit template build finished", "template_id", id, "status", status, "size_bytes", sizeBytes)
	}()
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
	if template.Status == models.TemplateStatusPending {
		return fmt.Errorf("template %q is still building: %w", id, store.ErrTemplateInUse)
	}
	referenced, err := s.store.IsTemplateReferenced(ctx, id)
	if err != nil {
		return err
	}
	if referenced {
		return store.ErrTemplateInUse
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
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				s.runTemplateGC(sweepCtx, time.Now())
				cancel()
			}
		}
	}()
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
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "tpl-" + hex.EncodeToString(buf), nil
}
