package runloop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

const (
	// defaultImage backs a create that names no blueprint or snapshot,
	// matching Runloop's Ubuntu default devbox.
	defaultImage = "ubuntu:22.04"
	// blueprintMapEnv maps Runloop blueprint names/ids onto images, the
	// counterpart of SB_E2B_TEMPLATE_MAP_JSON. The "default" key overrides
	// the image a create with no blueprint gets.
	blueprintMapEnv     = "SB_RUNLOOP_BLUEPRINT_MAP_JSON"
	defaultBlueprintKey = "default"

	// defaultKeepAliveSeconds and maxKeepAliveSeconds are Runloop's
	// keep_alive_time_seconds default and cap: a devbox with no idle policy
	// shuts down an hour after create unless the caller asked otherwise.
	defaultKeepAliveSeconds = 3600
	maxKeepAliveSeconds     = 172800

	// devboxIDPurpose separates the devbox id's keyed digest from every
	// other use of the server key. Changing it changes the id every create
	// derives, so a retry spanning the change would make a second devbox.
	devboxIDPurpose = "runloop.devbox-id/v1"
	// legacyDevboxIDWindow is how long after start a create still looks for
	// a devbox under the unkeyed id older servers derived. Both SDKs give a
	// create 30s and reuse its x-request-id only across the automatic
	// retries of that one call, which back off for seconds, so a retry
	// chain that began before an upgrade restart is over within a few
	// minutes. Past the window the unkeyed id is never computed.
	legacyDevboxIDWindow = 4 * time.Minute
)

// resourceSizes is Runloop's resource_size_request table (cpu, GiB memory,
// GiB disk).
var resourceSizes = map[string]struct {
	cpu      float64
	memoryGB int
	diskGB   int
}{
	"X_SMALL":  {0.5, 1, 4},
	"SMALL":    {1, 2, 4},
	"MEDIUM":   {2, 4, 8},
	"LARGE":    {2, 8, 16},
	"X_LARGE":  {4, 16, 16},
	"XX_LARGE": {8, 32, 16},
}

// devboxBlob is the facade-private state persisted in
// sandbox_compat_state. Everything with a native column (metadata → tags,
// env, resources, lifecycle) is read back from the sandbox row instead.
type devboxBlob struct {
	Name             string           `json:"name,omitempty"`
	BlueprintID      string           `json:"blueprint_id,omitempty"`
	SnapshotID       string           `json:"snapshot_id,omitempty"`
	LaunchParameters launchParameters `json:"launch_parameters"`
}

func decodeDevboxBlob(state *models.SandboxCompatState) (devboxBlob, error) {
	var blob devboxBlob
	if state == nil || strings.TrimSpace(state.StateJSON) == "" {
		return blob, nil
	}
	if err := json.Unmarshal([]byte(state.StateJSON), &blob); err != nil {
		return devboxBlob{}, fmt.Errorf("decode runloop devbox state: %w", err)
	}
	return blob, nil
}

func encodeDevboxBlob(blob devboxBlob) (string, error) {
	encoded, err := json.Marshal(blob)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// devboxIDs are the ids one create's x-request-id derives.
type devboxIDs struct {
	// current is the id under the server's current key: a new devbox is
	// made under it.
	current string
	// earlier are ids an earlier attempt of the same create may have used:
	// one per other key the server holds (a key rotation in progress) and,
	// for a short while after start, the unkeyed id older servers derived.
	// They are looked up, never created.
	earlier []string
}

// requestDigester is the part of the service a devbox id needs.
type requestDigester interface {
	RequestDigests(purpose string, data []byte) ([]secrets.KeyedDigest, error)
}

// devboxIDsForRequest derives the devbox id from the SDK's x-request-id,
// which both SDKs reuse across every automatic retry of one call. The body
// is folded in so a caller that pins x-request-id to a constant (it is
// settable through RUNLOOP_CUSTOM_HEADERS) still gets one devbox per
// distinct create rather than every create collapsing onto the first.
// Owner-qualified so two tenants can never derive the same id.
//
// The body carries the create's env values and the id is public, so a
// plain hash would let anyone who knows the request id test guessed env
// values offline. The id is "sb-" and the first 64 bits of an HMAC under a
// key derived from the server key instead: the same on every node that
// shares the key, and new only when the key is rotated.
func devboxIDsForRequest(d requestDigester, ownerRef, requestID string, body []byte, withLegacy bool) (devboxIDs, error) {
	if d == nil {
		return devboxIDs{}, errors.New("devbox id needs the server key")
	}
	data := make([]byte, 0, len(ownerRef)+len(requestID)+len(body)+2)
	data = append(data, ownerRef...)
	data = append(data, 0)
	data = append(data, requestID...)
	data = append(data, 0)
	data = append(data, body...)
	digests, err := d.RequestDigests(devboxIDPurpose, data)
	if err != nil {
		return devboxIDs{}, err
	}
	if len(digests) == 0 {
		return devboxIDs{}, errors.New("devbox id: the server key ring is empty")
	}
	var out devboxIDs
	for i, digest := range digests {
		id := "sb-" + hex.EncodeToString(digest.Sum[:8])
		if i == 0 {
			out.current = id
			continue
		}
		out.earlier = append(out.earlier, id)
	}
	if withLegacy {
		h := sha256.New()
		h.Write([]byte("runloop.create\x00"))
		h.Write(data)
		out.earlier = append(out.earlier, "sb-"+hex.EncodeToString(h.Sum(nil)[:8]))
	}
	return out, nil
}

// shortHash is a path- and session-name-safe digest for ids derived from
// caller-controlled strings (shell names, execution keys).
func shortHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// devboxStatus maps the native sandbox status onto Runloop's enum.
func devboxStatus(status models.SandboxStatus) string {
	switch status {
	case models.SandboxStatusCreating, models.SandboxStatusAwaitingRuntime:
		return statusProvisioning
	case models.SandboxStatusStarted:
		return statusRunning
	case models.SandboxStatusStopped, models.SandboxStatusPassivated:
		return statusSuspended
	case models.SandboxStatusDestroyed:
		return statusShutdown
	default:
		return statusFailure
	}
}

func unixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func intPtr(value int) *int { return &value }

func boolPtr(value bool) *bool { return &value }

func cloneStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func newDevboxView(sandbox *models.Sandbox, blob devboxBlob) devboxView {
	status := devboxStatus(sandbox.Status)
	view := devboxView{
		ID:               sandbox.ID,
		Status:           status,
		CreateTimeMs:     unixMillis(sandbox.CreatedAt),
		Capabilities:     []string{},
		LaunchParameters: blob.LaunchParameters,
		Metadata:         cloneStringMap(sandbox.Tags),
		StateTransitions: []stateTransition{},
		Name:             stringPtr(blob.Name),
		BlueprintID:      stringPtr(blob.BlueprintID),
		SnapshotID:       stringPtr(blob.SnapshotID),
		InitiatorType:    "api",
	}
	if status == statusFailure {
		view.FailureReason = stringPtr("execution_failed")
	}
	return view
}

// provisioningView answers for a devbox whose create is still in flight:
// the sandbox row may not exist yet, or exist without its facade state, so
// only the request is known.
func provisioningView(id string, created time.Time, blob devboxBlob, metadata map[string]string) devboxView {
	return devboxView{
		ID:               id,
		Status:           statusProvisioning,
		CreateTimeMs:     unixMillis(created),
		Capabilities:     []string{},
		LaunchParameters: blob.LaunchParameters,
		Metadata:         cloneStringMap(metadata),
		StateTransitions: []stateTransition{},
		Name:             stringPtr(blob.Name),
		BlueprintID:      stringPtr(blob.BlueprintID),
		SnapshotID:       stringPtr(blob.SnapshotID),
		InitiatorType:    "api",
	}
}

func loadBlueprintMap(raw string, logger *slog.Logger) map[string]string {
	blueprints := map[string]string{defaultBlueprintKey: defaultImage}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return blueprints
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		if logger != nil {
			logger.Warn("invalid "+blueprintMapEnv+", using defaults", "error", err)
		}
		return blueprints
	}
	for key, value := range parsed {
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key != "" && value != "" {
			blueprints[key] = value
		}
	}
	return blueprints
}

// unsupportedCreateFields lists the create fields this facade cannot honour.
// They are refused rather than dropped: a devbox that silently lacks its
// secrets, mounts, or entrypoint fails later in a way that is much harder
// to trace back to the facade.
func unsupportedCreateFields(req createDevboxRequest) []string {
	var fields []string
	if req.Entrypoint != nil && strings.TrimSpace(*req.Entrypoint) != "" {
		fields = append(fields, "entrypoint")
	}
	if len(req.Secrets) > 0 {
		fields = append(fields, "secrets")
	}
	if len(req.FileMounts) > 0 {
		fields = append(fields, "file_mounts")
	}
	for name, raw := range map[string]json.RawMessage{
		"mounts":      req.Mounts,
		"code_mounts": req.CodeMounts,
		"tunnel":      req.Tunnel,
		"gateways":    req.Gateways,
		"mcp":         req.MCP,
	} {
		if rawPresent(raw) {
			fields = append(fields, name)
		}
	}
	if lp := req.LaunchParameters; lp != nil {
		if len(lp.LaunchCommands) > 0 {
			fields = append(fields, "launch_parameters.launch_commands")
		}
		if rawPresent(lp.UserParameters) {
			fields = append(fields, "launch_parameters.user_parameters")
		}
		if lp.NetworkPolicyID != nil && strings.TrimSpace(*lp.NetworkPolicyID) != "" {
			fields = append(fields, "launch_parameters.network_policy_id")
		}
		if len(lp.RequiredServices) > 0 {
			fields = append(fields, "launch_parameters.required_services")
		}
		if lp.ProvisioningTier != nil && *lp.ProvisioningTier == "flex" {
			fields = append(fields, "launch_parameters.provisioning_tier=flex")
		}
		if lc := lp.Lifecycle; lc != nil {
			if rawPresent(lc.LifecycleHooks) {
				fields = append(fields, "launch_parameters.lifecycle.lifecycle_hooks")
			}
			if rt := lc.ResumeTriggers; rt != nil && ((rt.HTTP != nil && *rt.HTTP) || (rt.AxonEvent != nil && *rt.AxonEvent)) {
				fields = append(fields, "launch_parameters.lifecycle.resume_triggers")
			}
		}
	}
	sort.Strings(fields)
	return fields
}

func rawPresent(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "{}", "[]":
		return false
	}
	return true
}

// resources translates resource_size_request / custom_* into native sizes.
// Zero values leave the operator's defaults in place.
func resources(lp *launchParameters) (cpu float64, memoryMB, diskGB int, err error) {
	if lp == nil || lp.ResourceSizeRequest == nil || *lp.ResourceSizeRequest == "" {
		if lp != nil && (lp.CustomCPUCores != nil || lp.CustomGBMemory != nil || lp.CustomDiskSize != nil) {
			return 0, 0, 0, badRequest("custom_cpu_cores, custom_gb_memory and custom_disk_size require resource_size_request=CUSTOM_SIZE")
		}
		return 0, 0, 0, nil
	}
	size := strings.ToUpper(strings.TrimSpace(*lp.ResourceSizeRequest))
	if size == "CUSTOM_SIZE" {
		if lp.CustomCPUCores == nil || lp.CustomGBMemory == nil {
			return 0, 0, 0, badRequest("CUSTOM_SIZE requires custom_cpu_cores and custom_gb_memory")
		}
		if *lp.CustomCPUCores <= 0 || *lp.CustomGBMemory <= 0 {
			return 0, 0, 0, badRequest("custom_cpu_cores and custom_gb_memory must be positive")
		}
		cpu, memoryMB = *lp.CustomCPUCores, *lp.CustomGBMemory*1024
		if lp.CustomDiskSize != nil {
			if *lp.CustomDiskSize <= 0 {
				return 0, 0, 0, badRequest("custom_disk_size must be positive")
			}
			diskGB = *lp.CustomDiskSize
		}
		return cpu, memoryMB, diskGB, nil
	}
	preset, ok := resourceSizes[size]
	if !ok {
		return 0, 0, 0, badRequest(fmt.Sprintf("unknown resource_size_request %q", *lp.ResourceSizeRequest))
	}
	return preset.cpu, preset.memoryGB * 1024, preset.diskGB, nil
}

// lifecycleFor maps Runloop's idle policy and keep-alive TTL onto the
// native lifecycle. after_idle wins over keep_alive_time_seconds, which
// Runloop documents as ignored once an idle policy is set.
func lifecycleFor(lp *launchParameters) (*models.Lifecycle, error) {
	var idle *afterIdle
	if lp != nil {
		idle = lp.AfterIdle
		if lp.Lifecycle != nil && lp.Lifecycle.AfterIdle != nil {
			if idle != nil && *idle != *lp.Lifecycle.AfterIdle {
				return nil, badRequest("launch_parameters.after_idle and launch_parameters.lifecycle.after_idle disagree")
			}
			idle = lp.Lifecycle.AfterIdle
		}
	}
	if idle != nil {
		if idle.IdleTimeSeconds <= 0 {
			return nil, badRequest("after_idle.idle_time_seconds must be positive")
		}
		after := time.Duration(idle.IdleTimeSeconds) * time.Second
		switch idle.OnIdle {
		case "shutdown":
			return &models.Lifecycle{DestroyIfIdleFor: after}, nil
		case "suspend":
			return &models.Lifecycle{StopIfIdleFor: after}, nil
		default:
			return nil, badRequest(fmt.Sprintf("after_idle.on_idle must be shutdown or suspend, got %q", idle.OnIdle))
		}
	}
	keepAlive := defaultKeepAliveSeconds
	if lp != nil && lp.KeepAliveTimeSeconds != nil {
		keepAlive = *lp.KeepAliveTimeSeconds
	}
	if keepAlive <= 0 || keepAlive > maxKeepAliveSeconds {
		return nil, badRequest(fmt.Sprintf("keep_alive_time_seconds must be between 1 and %d", maxKeepAliveSeconds))
	}
	return &models.Lifecycle{DestroyAtAge: time.Duration(keepAlive) * time.Second}, nil
}
