package models

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Host-level container engine identifiers. Distinct from Sandbox.Runtime (OCI
// runtime type: docker/gvisor/firecracker/wasm). Engine selects which daemon
// on the host realizes OCI sandboxes (dockerd vs native containerd).
const (
	ContainerEngineDocker     = "docker"
	ContainerEngineContainerd = "containerd"
)

// ResolveContainerEngine normalizes SB_CONTAINER_ENGINE. Empty or unknown
// values default to docker so pre-migration hosts behave identically.
func ResolveContainerEngine(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ContainerEngineDocker:
		return ContainerEngineDocker, nil
	case ContainerEngineContainerd:
		return ContainerEngineContainerd, nil
	default:
		return "", fmt.Errorf("unsupported container engine %q (allowed: %s, %s)",
			value, ContainerEngineDocker, ContainerEngineContainerd)
	}
}

// SandboxEngine returns the engine that owns this sandbox's container lifecycle.
// Legacy rows with an empty engine column resolve to docker.
func SandboxEngine(sandbox *Sandbox) string {
	if sandbox == nil || strings.TrimSpace(sandbox.Engine) == "" {
		return ContainerEngineDocker
	}
	return sandbox.Engine
}

// ValidateRuntimeRequest enforces runtime policy shared by dockerd and
// containerd drivers. Privileged mode, GPU vendor, and disk quota warnings
// must not fork per engine.
func ValidateRuntimeRequest(req CreateSandboxRequest, effectiveRuntime string, privileged bool, logf func(string, ...any)) error {
	if effectiveRuntime == RuntimeGvisor && privileged {
		return fmt.Errorf("runtime %q is incompatible with privileged containers", effectiveRuntime)
	}
	if req.GPUs != nil && effectiveRuntime == RuntimeGvisor {
		return fmt.Errorf(
			"GPU access is not supported with the %q runtime: gVisor's user-space kernel "+
				"cannot safely pass through host GPU drivers; use the %q runtime for GPU workloads",
			RuntimeGvisor, RuntimeDocker,
		)
	}
	if req.DiskGB > 0 && effectiveRuntime == RuntimeGvisor && logf != nil {
		logf("ignoring disk quota: gvisor does not support StorageOpt size", "disk_gb", req.DiskGB)
	}
	return nil
}

// DiskGBEnforced reports whether the host engine actually applies CreateSandbox
// DiskGB as a storage quota. dockerd may (xfs+pquota StorageOpt); containerd
// overlayfs and gVisor do not today — callers should warn, not fail.
func DiskGBEnforced(engine, runtime string) bool {
	if runtime == RuntimeGvisor {
		return false
	}
	return ResolveContainerEngineOrDocker(engine) == ContainerEngineDocker
}

// ResolveContainerEngineOrDocker is ResolveContainerEngine that never errors —
// unknown/empty → docker (boot-path safe).
func ResolveContainerEngineOrDocker(value string) string {
	eng, err := ResolveContainerEngine(value)
	if err != nil {
		return ContainerEngineDocker
	}
	return eng
}

// ErrContainerEngineNotRegistered is returned when a sandbox row points at an
// engine driver that was not wired at daemon boot (e.g. containerd row on a
// docker-only node).
var ErrContainerEngineNotRegistered = errors.New("container engine driver not registered on this node")

// ErrImagePullUnavailable marks a create whose image pull failed for a
// reason that passes: the registry rate-limited it, failed (5xx, refused
// connection), took too long, or failed so recently that the per-image
// backoff refused to ask it again. The API answers 503 with Retry-After
// (ErrorCodeImagePullUnavailable), so SDKs back off and retry; a missing
// image or refused credentials stay the caller's 400. Engines wrap with
// docker.TransientPullError.
var ErrImagePullUnavailable = errors.New("image registry unavailable")

// ImagePullUnavailableError is ErrImagePullUnavailable with the failure and
// how long the node waits before it asks the registry again (its
// SB_IMAGE_PULL_FAILURE_BACKOFF), which the API sends as Retry-After.
type ImagePullUnavailableError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *ImagePullUnavailableError) Error() string {
	return ErrImagePullUnavailable.Error() + ": " + e.Err.Error()
}

// Unwrap lists the failure first: a reader that walks one branch down to
// the cause (docker's pull-error class) meets the failure, not the mark.
func (e *ImagePullUnavailableError) Unwrap() []error { return []error{e.Err, ErrImagePullUnavailable} }

// PullRetryAfter is the wait the API sends as Retry-After; zero leaves the
// API's default.
func (e *ImagePullUnavailableError) PullRetryAfter() time.Duration { return e.RetryAfter }

// ErrBuildKitUnavailable is returned by image-build endpoints when the host
// engine is containerd but buildkitd is not wired yet (Phase 3). Clear error,
// never a hang — see plans/containerd-engine.md §7.4.
var ErrBuildKitUnavailable = errors.New("image build on containerd requires BuildKit; buildkitd is not configured on this daemon")
