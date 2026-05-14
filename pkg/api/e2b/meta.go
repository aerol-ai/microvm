package e2b

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	defaultClientID       = "aerolvm"
	defaultEnvdVersion    = "0.4.0"
	defaultSandboxTimeout = 300
	snapshotIDPrefix      = "snapshot_"
	e2bCreatePendingTTL   = 2 * time.Minute
	e2bCreateWaitTimeout  = 30 * time.Second
	e2bCreateReplayWindow = 10 * time.Second
	e2bCreatePollInterval = 250 * time.Millisecond
	// idempotencyScopeCreate is the scope string the generic
	// request_idempotency table uses to namespace E2B create
	// fingerprints. Pick a stable string — changing it would
	// disconnect in-flight retries from their original claims.
	idempotencyScopeCreate = "e2b.create"
)

// sandboxMeta is the in-memory shape the handlers use. Some fields are
// derived from the native sandbox row (Metadata ← sandbox.Tags, the two
// timeout fields ← sandbox.Lifecycle, AllowInternetAccess ← inverse of
// sandbox.NetworkBlockAll); the rest are facade-private echo-back state
// stored opaquely in sandbox_compat_state.state_json.
type sandboxMeta struct {
	TemplateID          string
	TemplateAlias       string
	Metadata            map[string]string
	TimeoutSeconds      int
	OnTimeout           string
	AutoResume          bool
	Secure              bool
	AllowInternetAccess *bool
	NetworkAllowOut     []string
	NetworkDenyOut      []string
	AllowPublicTraffic  *bool
	MaskRequestHost     string
}

// compatBlob is the persisted JSON shape inside sandbox_compat_state.state_json
// for the E2B facade. Only fields that have no native AerolVM equivalent
// live here — Metadata, the timeout, and the internet-access flag are
// derived from the native sandbox row on read.
type compatBlob struct {
	TemplateID         string   `json:"template_id,omitempty"`
	TemplateAlias      string   `json:"template_alias,omitempty"`
	OnTimeout          string   `json:"on_timeout,omitempty"`
	AutoResume         bool     `json:"auto_resume,omitempty"`
	Secure             bool     `json:"secure,omitempty"`
	NetworkAllowOut    []string `json:"network_allow_out,omitempty"`
	NetworkDenyOut     []string `json:"network_deny_out,omitempty"`
	AllowPublicTraffic *bool    `json:"allow_public_traffic,omitempty"`
	MaskRequestHost    string   `json:"mask_request_host,omitempty"`
}

func defaultSandboxMeta(sandbox *models.Sandbox) sandboxMeta {
	return sandboxMetaFromNative(sandbox, compatBlob{Secure: true, OnTimeout: "kill"})
}

// sandboxMetaFromNative builds the in-memory meta by combining a native
// sandbox row with the facade-private compat blob. Used on every read
// path so the response shape is consistent whether or not a compat row
// exists.
func sandboxMetaFromNative(sandbox *models.Sandbox, blob compatBlob) sandboxMeta {
	meta := sandboxMeta{
		TemplateID:         strings.TrimSpace(blob.TemplateID),
		TemplateAlias:      strings.TrimSpace(blob.TemplateAlias),
		Metadata:           map[string]string{},
		OnTimeout:          firstNonEmpty(blob.OnTimeout, "kill"),
		AutoResume:         blob.AutoResume,
		Secure:             blob.Secure,
		NetworkAllowOut:    cloneStringSlice(blob.NetworkAllowOut),
		NetworkDenyOut:     cloneStringSlice(blob.NetworkDenyOut),
		AllowPublicTraffic: cloneBoolPtr(blob.AllowPublicTraffic),
		MaskRequestHost:    strings.TrimSpace(blob.MaskRequestHost),
	}
	if meta.NetworkAllowOut == nil {
		meta.NetworkAllowOut = []string{}
	}
	if meta.NetworkDenyOut == nil {
		meta.NetworkDenyOut = []string{}
	}
	if sandbox != nil {
		if meta.TemplateID == "" {
			meta.TemplateID = strings.TrimSpace(sandbox.Image)
		}
		meta.Metadata = cloneStringMap(sandbox.Tags)
		if meta.Metadata == nil {
			meta.Metadata = map[string]string{}
		}
		if sandbox.NetworkBlockAll {
			allow := false
			meta.AllowInternetAccess = &allow
		}
		if timeoutSeconds, onTimeout := deriveTimeoutConfig(sandbox); timeoutSeconds > 0 {
			meta.TimeoutSeconds = timeoutSeconds
			if meta.OnTimeout == "" || meta.OnTimeout == "kill" {
				meta.OnTimeout = onTimeout
			}
		}
	}
	return meta
}

// sandboxMetaFromState unmarshals the compat blob and merges it with the
// sandbox row.
func sandboxMetaFromState(state *models.SandboxCompatState, sandbox *models.Sandbox) (sandboxMeta, error) {
	if state == nil || strings.TrimSpace(state.StateJSON) == "" {
		return sandboxMetaFromNative(sandbox, compatBlob{Secure: true, OnTimeout: "kill"}), nil
	}
	var blob compatBlob
	if err := json.Unmarshal([]byte(state.StateJSON), &blob); err != nil {
		return sandboxMeta{}, err
	}
	return sandboxMetaFromNative(sandbox, blob), nil
}

// sandboxMetaToState marshals just the facade-private bits into a JSON
// string suitable for sandbox_compat_state.state_json. Native bits
// (Metadata, TimeoutSeconds, AllowInternetAccess) are written through
// the native sandbox row by CreateSandbox / UpdateLifecycle.
func sandboxMetaToState(meta sandboxMeta) (string, error) {
	blob := compatBlob{
		TemplateID:         strings.TrimSpace(meta.TemplateID),
		TemplateAlias:      strings.TrimSpace(meta.TemplateAlias),
		OnTimeout:          firstNonEmpty(strings.TrimSpace(meta.OnTimeout), "kill"),
		AutoResume:         meta.AutoResume,
		Secure:             meta.Secure,
		NetworkAllowOut:    cloneStringSlice(meta.NetworkAllowOut),
		NetworkDenyOut:     cloneStringSlice(meta.NetworkDenyOut),
		AllowPublicTraffic: cloneBoolPtr(meta.AllowPublicTraffic),
		MaskRequestHost:    strings.TrimSpace(meta.MaskRequestHost),
	}
	encoded, err := json.Marshal(blob)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func deriveTimeoutConfig(sandbox *models.Sandbox) (int, string) {
	if sandbox == nil {
		return 0, "kill"
	}
	if sandbox.Lifecycle.StopAtAge > 0 {
		remaining := int(math.Ceil(time.Until(sandbox.CreatedAt.Add(sandbox.Lifecycle.StopAtAge)).Seconds()))
		if remaining < 0 {
			remaining = 0
		}
		return remaining, "pause"
	}
	if sandbox.Lifecycle.DestroyAtAge > 0 {
		remaining := int(math.Ceil(time.Until(sandbox.CreatedAt.Add(sandbox.Lifecycle.DestroyAtAge)).Seconds()))
		if remaining < 0 {
			remaining = 0
		}
		return remaining, "kill"
	}
	return 0, "kill"
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	cloned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			cloned = append(cloned, trimmed)
		}
	}
	return cloned
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func canonicalSnapshotName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	if strings.LastIndex(trimmed, ":") > strings.LastIndex(trimmed, "/") {
		return trimmed
	}
	return trimmed + ":default"
}

func defaultSnapshotName(sandboxID string) string {
	return canonicalSnapshotName("e2b/" + strings.TrimSpace(sandboxID))
}

func snapshotIDFromName(name string) string {
	canonical := canonicalSnapshotName(name)
	if canonical == "" {
		return ""
	}
	return snapshotIDPrefix + base64.RawURLEncoding.EncodeToString([]byte(canonical))
}

func snapshotNameFromID(snapshotID string) (string, bool) {
	if !strings.HasPrefix(snapshotID, snapshotIDPrefix) {
		return "", false
	}
	raw := strings.TrimPrefix(snapshotID, snapshotIDPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	name := strings.TrimSpace(string(decoded))
	if name == "" {
		return "", false
	}
	return name, true
}

type createFingerprintPayload struct {
	TemplateID          string            `json:"templateID"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	EnvVars             map[string]string `json:"envVars,omitempty"`
	TimeoutSeconds      int               `json:"timeoutSeconds"`
	OnTimeout           string            `json:"onTimeout"`
	AutoResume          bool              `json:"autoResume"`
	Secure              bool              `json:"secure"`
	AllowInternetAccess bool              `json:"allowInternetAccess"`
	NetworkBlockAll     bool              `json:"networkBlockAll"`
	NetworkAllowOut     []string          `json:"networkAllowOut,omitempty"`
	NetworkDenyOut      []string          `json:"networkDenyOut,omitempty"`
	AllowPublicTraffic  bool              `json:"allowPublicTraffic"`
	MaskRequestHost     string            `json:"maskRequestHost,omitempty"`
}

func createRequestFingerprint(templateID string, serviceReq models.CreateSandboxRequest, meta sandboxMeta) (string, error) {
	payload := createFingerprintPayload{
		TemplateID:          strings.TrimSpace(templateID),
		Metadata:            cloneStringMap(meta.Metadata),
		EnvVars:             cloneStringMap(serviceReq.Env),
		TimeoutSeconds:      meta.TimeoutSeconds,
		OnTimeout:           strings.TrimSpace(meta.OnTimeout),
		AutoResume:          meta.AutoResume,
		Secure:              meta.Secure,
		AllowInternetAccess: !serviceReq.NetworkBlockAll,
		NetworkBlockAll:     serviceReq.NetworkBlockAll,
		NetworkAllowOut:     sortedStringSlice(meta.NetworkAllowOut),
		NetworkDenyOut:      sortedStringSlice(meta.NetworkDenyOut),
		AllowPublicTraffic:  meta.AllowPublicTraffic == nil || *meta.AllowPublicTraffic,
		MaskRequestHost:     strings.TrimSpace(meta.MaskRequestHost),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "fingerprint:" + hex.EncodeToString(sum[:]), nil
}

func sortedStringSlice(values []string) []string {
	cloned := cloneStringSlice(values)
	sort.Strings(cloned)
	return cloned
}
