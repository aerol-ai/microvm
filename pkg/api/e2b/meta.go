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
)

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

func defaultSandboxMeta(sandbox *models.Sandbox) sandboxMeta {
	meta := sandboxMeta{
		Metadata:        map[string]string{},
		OnTimeout:       "kill",
		Secure:          true,
		NetworkAllowOut: []string{},
		NetworkDenyOut:  []string{},
	}
	if sandbox == nil {
		return meta
	}
	meta.TemplateID = strings.TrimSpace(sandbox.Image)
	if sandbox.NetworkBlockAll {
		allowInternet := false
		meta.AllowInternetAccess = &allowInternet
	}
	if timeoutSeconds, onTimeout := deriveTimeoutConfig(sandbox); timeoutSeconds > 0 {
		meta.TimeoutSeconds = timeoutSeconds
		meta.OnTimeout = onTimeout
	}
	return meta
}

func sandboxMetaFromStored(stored *models.E2BSandboxMetadata, sandbox *models.Sandbox) sandboxMeta {
	meta := defaultSandboxMeta(sandbox)
	if stored == nil {
		return meta
	}
	if trimmed := strings.TrimSpace(stored.TemplateID); trimmed != "" {
		meta.TemplateID = trimmed
	}
	meta.TemplateAlias = strings.TrimSpace(stored.TemplateAlias)
	meta.Metadata = cloneStringMap(stored.Metadata)
	if stored.TimeoutSeconds > 0 {
		meta.TimeoutSeconds = stored.TimeoutSeconds
	}
	if trimmed := strings.TrimSpace(stored.OnTimeout); trimmed != "" {
		meta.OnTimeout = trimmed
	}
	meta.AutoResume = stored.AutoResume
	meta.Secure = stored.Secure
	meta.AllowInternetAccess = cloneBoolPtr(stored.AllowInternetAccess)
	meta.NetworkAllowOut = cloneStringSlice(stored.NetworkAllowOut)
	meta.NetworkDenyOut = cloneStringSlice(stored.NetworkDenyOut)
	meta.AllowPublicTraffic = cloneBoolPtr(stored.AllowPublicTraffic)
	meta.MaskRequestHost = strings.TrimSpace(stored.MaskRequestHost)
	return meta
}

func sandboxMetaToStored(sandboxID string, meta sandboxMeta) models.E2BSandboxMetadata {
	return models.E2BSandboxMetadata{
		SandboxID:           strings.TrimSpace(sandboxID),
		TemplateID:          strings.TrimSpace(meta.TemplateID),
		TemplateAlias:       strings.TrimSpace(meta.TemplateAlias),
		Metadata:            cloneStringMap(meta.Metadata),
		TimeoutSeconds:      meta.TimeoutSeconds,
		OnTimeout:           strings.TrimSpace(meta.OnTimeout),
		AutoResume:          meta.AutoResume,
		Secure:              meta.Secure,
		AllowInternetAccess: cloneBoolPtr(meta.AllowInternetAccess),
		NetworkAllowOut:     cloneStringSlice(meta.NetworkAllowOut),
		NetworkDenyOut:      cloneStringSlice(meta.NetworkDenyOut),
		AllowPublicTraffic:  cloneBoolPtr(meta.AllowPublicTraffic),
		MaskRequestHost:     strings.TrimSpace(meta.MaskRequestHost),
	}
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
