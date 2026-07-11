package clustercreate

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	HeaderTarget = "X-Cluster-Create-Target"
	HeaderID     = "X-Cluster-Create-ID"

	ReservationTTL = 120 * time.Second
)

type ErrorWriter func(w http.ResponseWriter, status int, message string)

type Decision struct {
	ReservationID string
}

type PrepareOptions struct {
	PreferredSandboxID string
}

func Prepare(w http.ResponseWriter, r *http.Request, svc *service.Service, req models.CreateSandboxRequest, writeError ErrorWriter, opts PrepareOptions) (Decision, bool) {
	if writeError == nil {
		writeError = func(w http.ResponseWriter, status int, message string) {
			http.Error(w, message, status)
		}
	}
	if svc == nil {
		return Decision{}, true
	}
	c := svc.Cluster()
	if c == nil {
		return Decision{}, true
	}

	if targetNodeID := strings.TrimSpace(r.Header.Get(HeaderTarget)); targetNodeID != "" {
		if targetNodeID != c.SelfNodeID() {
			service.RecordFacadeIdempotencyConflict("cluster.create.forward")
			writeError(w, http.StatusMisdirectedRequest, "cluster: forwarded create reached wrong target")
			return Decision{}, false
		}
		if service.ImageRequiresLocalPlacement(req) {
			return Decision{}, true
		}
		sandboxID := strings.TrimSpace(r.Header.Get(HeaderID))
		if sandboxID == "" {
			writeError(w, http.StatusBadRequest, "cluster: forwarded create missing "+HeaderID)
			return Decision{}, false
		}
		return Decision{ReservationID: sandboxID}, true
	}

	if err := svc.NormalizeCreateImageDistribution(r.Context(), &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return Decision{}, false
	}
	if err := service.NormalizeCreateFailover(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return Decision{}, false
	}
	if service.ImageRequiresLocalPlacement(req) {
		if clusterCreateSelfCanOwnSandbox(c) {
			if c.IsNodeDrained(c.SelfNodeID()) {
				writeError(w, http.StatusServiceUnavailable, cluster.ErrNoPlacementTarget.Error())
				return Decision{}, false
			}
			return Decision{}, true
		}
		target, err := c.SelectPlacement(CapacityRequestFromCreate(req))
		if err != nil {
			if errors.Is(err, cluster.ErrNoPlacementTarget) || errors.Is(err, cluster.ErrInvalidTopology) {
				if errors.Is(err, cluster.ErrInvalidTopology) {
					w.Header().Set("Retry-After", "300")
				} else {
					w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
				}
				writeError(w, http.StatusServiceUnavailable, err.Error())
				return Decision{}, false
			}
			writeError(w, http.StatusInternalServerError, "placement: "+err.Error())
			return Decision{}, false
		}
		if target.IsSelf {
			if c.IsNodeDrained(c.SelfNodeID()) {
				writeError(w, http.StatusServiceUnavailable, cluster.ErrNoPlacementTarget.Error())
				return Decision{}, false
			}
			return Decision{}, true
		}
		if target.APIURL == "" && target.InternalURL == "" {
			writeError(w, http.StatusServiceUnavailable, cluster.ErrNoPlacementTarget.Error())
			return Decision{}, false
		}
		r.Header.Set(HeaderTarget, target.NodeID)
		r.Header.Del(HeaderID)
		c.ForwardHTTP(cluster.Endpoint{InternalURL: target.InternalURL, APIURL: target.APIURL}, w, r)
		return Decision{}, false
	}

	target, err := c.SelectPlacement(CapacityRequestFromCreate(req))
	if err != nil {
		if errors.Is(err, cluster.ErrNoPlacementTarget) || errors.Is(err, cluster.ErrInvalidTopology) {
			if errors.Is(err, cluster.ErrInvalidTopology) {
				w.Header().Set("Retry-After", "300")
			} else {
				w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
			}
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return Decision{}, false
		}
		writeError(w, http.StatusInternalServerError, "placement: "+err.Error())
		return Decision{}, false
	}
	sandboxID := strings.TrimSpace(opts.PreferredSandboxID)
	if sandboxID == "" {
		var err error
		sandboxID, err = service.GenerateSandboxID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "cluster: generate sandbox id: "+err.Error())
			return Decision{}, false
		}
	}
	redacted := service.RedactClusterSecrets(req)
	commitCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	err = c.ReserveOnTarget(commitCtx, sandboxID, target, &redacted, cluster.PlacementSecrets{}, ReservationTTL)
	cancel()
	if err != nil {
		if opts.PreferredSandboxID != "" && errors.Is(err, cluster.ErrReservationConflict) {
			service.RecordFacadeIdempotencyConflict("cluster.create.reservation")
			handled, local := routeExistingPlacement(w, r, c, sandboxID, writeError)
			if local {
				return Decision{ReservationID: sandboxID}, true
			}
			if handled {
				return Decision{}, false
			}
		}
		if errors.Is(err, cluster.ErrNameConflict) {
			service.RecordFacadeIdempotencyConflict("cluster.create.name")
			writeError(w, http.StatusConflict, "sandbox name already in use cluster-wide")
			return Decision{}, false
		}
		if errors.Is(err, cluster.ErrReservationConflict) {
			service.RecordFacadeIdempotencyConflict("cluster.create.reservation")
			writeError(w, http.StatusConflict, "cluster: reservation conflict on sandbox id")
			return Decision{}, false
		}
		if errors.Is(err, cluster.ErrCreateBackpressure) {
			w.Header().Set("Retry-After", strconv.Itoa(cluster.CreateBackpressureRetryAfterSeconds))
			writeError(w, http.StatusTooManyRequests, err.Error())
			return Decision{}, false
		}
		if errors.Is(err, cluster.ErrCapacityExceeded) || errors.Is(err, cluster.ErrNoPlacementTarget) {
			w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return Decision{}, false
		}
		// Oversized specs are a caller problem, not a cluster problem: the
		// recovery payload rides inline in the raft entry and has a hard size
		// cap with no fallback delivery path.
		if errors.Is(err, cluster.ErrRecoveryPayloadTooLarge) {
			writeError(w, http.StatusBadRequest, "sandbox spec too large to replicate across the cluster: "+err.Error())
			return Decision{}, false
		}
		writeError(w, http.StatusServiceUnavailable, "cluster: reserve placement failed: "+err.Error())
		return Decision{}, false
	}
	r.Header.Set(HeaderTarget, target.NodeID)
	r.Header.Set(HeaderID, sandboxID)
	if target.IsSelf {
		service.RecordCreateReservationState("reserve_local")
		return Decision{ReservationID: sandboxID}, true
	}
	service.RecordCreateReservationState("reserve_remote")
	c.ForwardHTTP(cluster.Endpoint{InternalURL: target.InternalURL, APIURL: target.APIURL}, w, r)
	return Decision{}, false
}

func routeExistingPlacement(w http.ResponseWriter, r *http.Request, c cluster.Client, sandboxID string, writeError ErrorWriter) (handled bool, local bool) {
	owner, err := c.OwnerOf(sandboxID)
	if err != nil {
		return false, false
	}
	r.Header.Set(HeaderTarget, owner.NodeID)
	r.Header.Set(HeaderID, sandboxID)
	if owner.IsSelf {
		return false, true
	}
	if owner.APIURL == "" && owner.InternalURL == "" {
		service.RecordRouteMiss()
		writeError(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" URL unknown")
		return true, false
	}
	c.ForwardHTTP(cluster.Endpoint{InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	return true, false
}

type CreateOptions struct {
	PromoteWithSpec bool
}

func CreateOnSelectedNode(ctx context.Context, svc *service.Service, logger *slog.Logger, req models.CreateSandboxRequest, reservationID string, opts CreateOptions) (*models.CreateSandboxResponse, error) {
	if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		return nil, err
	}
	if err := service.NormalizeCreateFailover(&req); err != nil {
		return nil, err
	}
	c := svc.Cluster()

	// Reserved path: overlap CreateSandboxWithID with the secrets seal, then
	// promote after both legs join (the row must stay Reserved during the
	// create — see OverlapCreateAndPromote). Resolve platform volumes first —
	// store lookups only, no container — so PromoteWithSpec carries concrete
	// MountSpecs (plans/warm-create-latency-tier1.5-seal-promote-overlap.md).
	if reservationID != "" {
		service.RecordCreateReservationState("promote_local")
		if err := svc.ResolvePlatformVolumesForReplication(ctx, &req); err != nil {
			if c != nil {
				cancelReservation(context.Background(), c, logger, reservationID)
			}
			return nil, err
		}
		return OverlapCreateAndPromote(ctx, svc, logger, req, reservationID, OverlapOptions{
			PromoteWithSpec: opts.PromoteWithSpec,
		})
	}

	service.RecordCreateReservationState("self_local")
	resp, err := svc.CreateSandbox(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := svc.ResolvePlatformVolumesForReplication(ctx, &req); err != nil {
		rollbackCreate(context.Background(), svc, c, logger, resp.Sandbox.ID, reservationID)
		return nil, err
	}

	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	secrets, sealErr := svc.PutClusterSecretsForRecipient(commitCtx, resp.Sandbox.ID, req, c.SelfNodeID())
	if sealErr != nil {
		rollbackCreate(context.Background(), svc, c, logger, resp.Sandbox.ID, reservationID)
		return nil, sealErr
	}
	redacted := service.RedactClusterSecrets(req)
	if promoteErr := c.RecordPlacement(commitCtx, resp.Sandbox.ID, &redacted, secrets); promoteErr != nil {
		rollbackCreate(context.Background(), svc, c, logger, resp.Sandbox.ID, reservationID)
		return nil, promoteErr
	}
	return resp, nil
}

func DeletePlacementBestEffort(ctx context.Context, svc *service.Service, logger *slog.Logger, sandboxID string) {
	if svc == nil || sandboxID == "" {
		return
	}
	c := svc.Cluster()
	if c == nil {
		return
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.DeletePlacement(commitCtx, sandboxID); err != nil && logger != nil {
		logger.Warn("cluster: delete placement after facade rollback failed", "sandbox_id", sandboxID, "err", err)
	}
}

func CancelReservationBestEffort(ctx context.Context, svc *service.Service, logger *slog.Logger, sandboxID string) {
	if svc == nil || sandboxID == "" {
		return
	}
	c := svc.Cluster()
	if c == nil {
		return
	}
	cancelReservation(ctx, c, logger, sandboxID)
}

func CapacityRequestFromCreate(req models.CreateSandboxRequest) capacity.Request {
	cpu := req.CPU
	mem := req.MemoryMB
	disk := req.DiskGB
	if cpu <= 0 {
		cpu = models.DefaultCPU
	}
	if mem <= 0 {
		mem = models.DefaultMemoryMB
	}
	if disk <= 0 {
		disk = models.DefaultDiskGB
	}
	runtimeName := strings.TrimSpace(req.Runtime)
	templateID := strings.TrimSpace(req.TemplateID)
	if templateID != "" && runtimeName == "" {
		runtimeName = models.RuntimeFirecracker
	}
	if runtimeName == "" {
		runtimeName = models.RuntimeDocker
	}
	out := capacity.Request{
		CPU:        cpu,
		MemoryMB:   mem,
		DiskGB:     diskGBForCapacity(disk, runtimeName, req.OverlaySizeGB),
		Runtime:    runtimeName,
		TemplateID: templateID,
		ModuleRef:  models.ModuleRefForCreate(req),
	}
	if runtimeName == models.RuntimeWasm {
		out.MemoryMB += 8
	}
	if req.GPUs != nil {
		want := req.GPUs.Count
		if want <= 0 {
			want = 1
		}
		out.GPUs = want
		out.GPUVendor = string(req.GPUs.Vendor)
	}
	return out
}

func diskGBForCapacity(base int, runtimeName string, overlaySizeGB int) int {
	if runtimeName == models.RuntimeFirecracker && overlaySizeGB > 0 {
		return base + overlaySizeGB
	}
	return base
}

func clusterCreateSelfCanOwnSandbox(c cluster.Client) bool {
	if c == nil {
		return true
	}
	selfID := c.SelfNodeID()
	for _, m := range c.Members() {
		if m.NodeID == selfID {
			return cluster.CanOwnSandboxRole(m.Role)
		}
	}
	return true
}

func rollbackCreate(ctx context.Context, svc *service.Service, c cluster.Client, logger *slog.Logger, sandboxID, reservationID string) {
	if err := svc.DestroySandbox(ctx, sandboxID); err != nil && logger != nil {
		logger.Error("cluster: rollback destroy failed", "sandbox_id", sandboxID, "err", err)
	}
	if reservationID != "" && c != nil {
		cancelReservation(ctx, c, logger, reservationID)
	}
	DeletePlacementBestEffort(ctx, svc, logger, sandboxID)
}

func cancelReservation(ctx context.Context, c cluster.Client, logger *slog.Logger, sandboxID string) {
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.CancelReservation(commitCtx, sandboxID); err != nil && logger != nil {
		logger.Warn("cluster: cancel reservation failed", "sandbox_id", sandboxID, "err", err)
	}
}
