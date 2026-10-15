package apihttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// ErrKind names the few service errors a facade words differently for its own
// SDK (otherwise it uses Classification.Message verbatim). Every other error
// is ErrKindOther.
type ErrKind int

const (
	ErrKindOther ErrKind = iota
	ErrKindNotFound
	ErrKindSandboxNameConflict
	ErrKindSnapshotNameConflict
	ErrKindSandboxExists
	// ErrKindSandboxNotRunning / ErrKindSandboxNotResumable are the two
	// lifecycle-precondition 409s (pause a non-running sandbox, resume a
	// non-stopped one); a facade words them for its own SDK ("devbox is not
	// running" vs "Sandbox is not running").
	ErrKindSandboxNotRunning
	ErrKindSandboxNotResumable
	// ErrKindUnclassified is the catch-all 400: an error no sentinel matched.
	// A facade may keep its own default wording for it.
	ErrKindUnclassified
)

// Classification is one service error's HTTP rendering, independent of which
// surface serves it: the single source of truth every facade's error writer
// shares (plan D1). A facade turns it into its own envelope shape and adds any
// envelope-specific header (Runloop's x-should-retry), but never decides the
// status, the Retry-After or whether to log.
type Classification struct {
	Status     int
	Code       string // models.ErrorResponse.Code; "" when none
	Message    string // canonical message, already truncated
	RetryAfter int    // seconds; 0 = no Retry-After header
	Kind       ErrKind
	LogLevel   slog.Level
	Log        bool // emit LogLevel with the error; false = no log line
}

func truncate(message string) string {
	if len(message) > 200 {
		return message[:200]
	}
	return message
}

// Classify maps a service-layer error to its HTTP rendering. The mapping is
// the one that used to live inline in WriteStoreAwareError; it now has one
// home so v1, Daytona, E2B and Runloop cannot drift (plan D1).
func Classify(err error) Classification {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Classification{Status: http.StatusNotFound, Message: "sandbox not found", Kind: ErrKindNotFound}

	// Fleet admission verdicts (managed builds only). Denied is a definite
	// 403; unavailable is a retryable 503.
	case errors.Is(err, controlplane.ErrAdmissionDenied):
		return Classification{Status: http.StatusForbidden, Message: "account access is not currently permitted"}
	case errors.Is(err, controlplane.ErrAdmissionUnavailable):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: admissionRetryAfterSeconds, Message: "fleet access validation temporarily unavailable; retry shortly"}

	// A sandbox whose container engine is not wired on this node: host
	// wiring state, not client fault. 503+Retry-After so SDKs back off.
	case errors.Is(err, models.ErrContainerEngineNotRegistered):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: admissionRetryAfterSeconds, Message: "container engine for this sandbox is not available on this node; retry shortly"}

	// Lifecycle-precondition conflicts (pause/resume). Each facade words them
	// for its own SDK via the Kind.
	case errors.Is(err, service.ErrSandboxNotRunning):
		return Classification{Status: http.StatusConflict, Message: err.Error(), Kind: ErrKindSandboxNotRunning}
	case errors.Is(err, service.ErrSandboxNotResumable):
		return Classification{Status: http.StatusConflict, Message: err.Error(), Kind: ErrKindSandboxNotResumable}

	// Wake-aware proxy sentinels.
	case errors.Is(err, service.ErrSandboxManuallyStopped):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, service.ErrWakeCircuitOpen):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: 60, Message: err.Error()}

	case errors.Is(err, service.ErrSecretAuditBusy):
		return Classification{Status: http.StatusTooManyRequests, RetryAfter: 1, Message: service.ErrSecretAuditBusy.Error()}
	case errors.Is(err, service.ErrSecretAuditChainBroken):
		return Classification{Status: http.StatusServiceUnavailable, Message: service.ErrSecretAuditChainBroken.Error()}
	case errors.Is(err, service.ErrClusterFinalizationUnavailable):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: 5, Message: service.ErrClusterFinalizationUnavailable.Error()}

	// An option this runtime/build can't honor is 501, not 400.
	case errors.Is(err, models.ErrRuntimeNotImplemented):
		return Classification{Status: http.StatusNotImplemented, Message: err.Error()}

	// Egress sentinels (plans/egress-domain-filtering.md).
	case errors.Is(err, service.ErrEgressOperatorConfigInvalid):
		return Classification{Status: http.StatusServiceUnavailable, Code: models.ErrorCodeEgressOperatorConfigInvalid, Message: err.Error()}
	case errors.Is(err, service.ErrEgressGatewayUnavailable), errors.Is(err, cluster.ErrNoEgressGatewayTarget):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: 5, Code: models.ErrorCodeEgressGatewayUnavailable, Message: err.Error()}
	case errors.Is(err, service.ErrEgressSpecCommitFailed):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: 5, Code: models.ErrorCodeEgressSpecCommitFailed, Message: err.Error()}
	case errors.Is(err, service.ErrEgressApplyFailedHeld):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: 5, Code: models.ErrorCodeEgressApplyFailedHeld, Message: err.Error()}
	case errors.Is(err, service.ErrEgressProfileNotFound):
		return Classification{Status: http.StatusNotFound, Message: "egress profile not found"}
	case errors.Is(err, service.ErrEgressProfilesConflict), errors.Is(err, service.ErrEgressLearnConflict):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, service.ErrEgressProfileInUse):
		return Classification{Status: http.StatusConflict, Code: models.ErrorCodeEgressProfileInUse, Message: err.Error()}
	case errors.Is(err, service.ErrEgressProfileCapExceeded):
		return Classification{Status: http.StatusConflict, Code: models.ErrorCodeEgressProfileCapExceeded, Message: err.Error()}
	case errors.Is(err, service.ErrEgressProfileUnavailable):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: 5, Message: err.Error()}
	case errors.Is(err, service.ErrEgressInspectRecreate), errors.Is(err, service.ErrEgressInjectRecreate):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, service.ErrEgressPolicyBusy):
		return Classification{Status: http.StatusConflict, RetryAfter: 1, Message: err.Error()}
	case errors.Is(err, service.ErrPublicTrafficDisabled):
		return Classification{Status: http.StatusConflict, Message: err.Error()}

	case errors.Is(err, store.ErrSandboxNameConflict):
		return Classification{Status: http.StatusConflict, Message: "sandbox name already in use", Kind: ErrKindSandboxNameConflict}
	case errors.Is(err, models.ErrSandboxExists):
		return Classification{Status: http.StatusConflict, Message: "sandbox already exists", Kind: ErrKindSandboxExists}
	case errors.Is(err, store.ErrSnapshotNameConflict):
		return Classification{Status: http.StatusConflict, Message: "snapshot name already in use", Kind: ErrKindSnapshotNameConflict}

	// Image builds (service.BuildImage): one status per failure.
	case errors.Is(err, service.ErrBuildTimeout):
		return Classification{Status: http.StatusGatewayTimeout, Message: err.Error()}
	case errors.Is(err, service.ErrBuildFailed):
		return Classification{Status: http.StatusBadGateway, Message: err.Error()}
	case errors.Is(err, service.ErrBuilderUnavailable):
		return Classification{Status: http.StatusServiceUnavailable, Message: err.Error()}
	case errors.Is(err, service.ErrBuildNotImplemented):
		return Classification{Status: http.StatusNotImplemented, Message: err.Error()}
	case errors.Is(err, service.ErrBuildInvalid):
		return Classification{Status: http.StatusBadRequest, Message: err.Error()}

	// Firecracker template + wasm module + js bundle sentinels.
	case errors.Is(err, store.ErrTemplateIDConflict), errors.Is(err, store.ErrTemplateInUse):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, store.ErrWasmModuleIDConflict), errors.Is(err, store.ErrWasmModuleInUse):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, store.ErrJSBundleInUse):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, models.ErrTemplateNotRebuildable):
		return Classification{Status: http.StatusPreconditionFailed, Message: err.Error()}

	// Platform-volume sentinels (plans/e2b-volume-mounts.md).
	case errors.Is(err, models.ErrPlatformVolumesDisabled):
		return Classification{Status: http.StatusPreconditionFailed, Message: err.Error()}
	case errors.Is(err, models.ErrPlatformVolumesUnsupportedRuntime):
		return Classification{Status: http.StatusBadRequest, Message: err.Error()}
	case errors.Is(err, models.ErrPlatformVolumeQuota):
		return Classification{Status: http.StatusConflict, Message: err.Error()}

	// Custom-domain sentinels (plans/custom-domains.md).
	case errors.Is(err, models.ErrCustomDomainNotSupported):
		return Classification{Status: http.StatusPreconditionFailed, Message: err.Error()}
	case errors.Is(err, models.ErrCustomDomainProtocolConflict),
		errors.Is(err, models.ErrCustomDomainPerSandboxCap),
		errors.Is(err, store.ErrCustomDomainConflict),
		errors.Is(err, store.ErrCustomDomainPortMismatch):
		return Classification{Status: http.StatusConflict, Message: err.Error()}
	case errors.Is(err, models.ErrCustomDomainInvalidTargetPort),
		errors.Is(err, service.ErrWasmCustomDomainPortNotExposed):
		return Classification{Status: http.StatusBadRequest, Message: err.Error()}
	case errors.Is(err, models.ErrCustomDomainVerificationFailed):
		return Classification{Status: http.StatusForbidden, Message: err.Error()}

	// WASM module resolution taxonomy.
	case errors.Is(err, wasmmod.ErrModuleNotFound):
		return Classification{Status: http.StatusNotFound, Message: err.Error()}
	case errors.Is(err, wasmmod.ErrRegistryNotAllowed), errors.Is(err, wasmmod.ErrModuleDigestMismatch):
		return Classification{Status: http.StatusForbidden, Message: err.Error()}
	case errors.Is(err, wasmmod.ErrRegistryAuth):
		return Classification{Status: http.StatusUnauthorized, Message: err.Error()}
	case errors.Is(err, wasmmod.ErrModuleTooLarge):
		return Classification{Status: http.StatusRequestEntityTooLarge, Message: err.Error()}
	case errors.Is(err, wasmmod.ErrComponentModelUnsupported):
		return Classification{Status: http.StatusUnprocessableEntity, Message: err.Error()}
	case errors.Is(err, wasmmod.ErrRegistryUnavailable):
		return Classification{Status: http.StatusBadGateway, RetryAfter: 5, Message: err.Error()}

	// Capacity / placement.
	case errors.Is(err, capacity.ErrCapacityExceeded), errors.Is(err, cluster.ErrCapacityExceeded):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: cluster.CapacityRetryAfterSeconds, Message: truncate(err.Error()), LogLevel: slog.LevelInfo, Log: true}
	case errors.Is(err, cluster.ErrCreateBackpressure):
		return Classification{Status: http.StatusTooManyRequests, RetryAfter: cluster.CreateBackpressureRetryAfterSeconds, Message: err.Error()}
	case errors.Is(err, cluster.ErrInvalidTopology):
		return Classification{Status: http.StatusServiceUnavailable, RetryAfter: cluster.InvalidTopologyRetryAfterSeconds, Message: err.Error()}
	case errors.Is(err, cluster.ErrNoPlacementTarget):
		return Classification{Status: http.StatusServiceUnavailable, Message: err.Error()}

	default:
		return Classification{Status: http.StatusBadRequest, Message: truncate(err.Error()), Kind: ErrKindUnclassified, LogLevel: slog.LevelWarn, Log: true}
	}
}

// Apply sets the Retry-After header and emits the classification's log line.
func (c Classification) Apply(logger *slog.Logger, err error) {
	if c.Log && logger != nil {
		msg := "request failed"
		if c.LogLevel == slog.LevelInfo {
			msg = "capacity rejected"
		}
		logger.Log(context.Background(), c.LogLevel, msg, "error", err)
	}
}

func (c Classification) SetRetryAfter(w http.ResponseWriter) {
	if c.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(c.RetryAfter))
	}
}
