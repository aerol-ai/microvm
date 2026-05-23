package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AutoImportConfig wires the post-pull auto-import path to a specific AOCR
// hooks deployment. A zero value disables auto-import; the rest of the
// service runs exactly as before. main() is expected to validate that the
// PAT + cluster ID are set when Enabled=true.
//
// See `plans/cluster-mirror-and-snapshot-distribution.md` F21 for the full
// motivation. Short version: the first time a private upstream image is
// pulled on a sandbox with `failover.policy: recreate`, sandboxd asks AOCR
// to re-mount the just-cached bytes under
// `cluster/<id>/_imported/<host>/<repo>`. Future recreates pull from the
// cluster namespace with a cluster PAT — surviving an upstream credential
// rotation that would otherwise break the F17 wrap-creds path.
type AutoImportConfig struct {
	// Enabled gates the whole feature. When false the post-pull path
	// short-circuits and the auto-importer is never built.
	Enabled bool
	// HooksBaseURL is the root URL of the AOCR hooks service (no trailing
	// slash, e.g. `https://aocr.aerol.ai`). The importer appends
	// `/v1/internal/imports`.
	HooksBaseURL string
	// ClusterID identifies this sandboxd cluster to AOCR. Goes into the
	// import request body and constrains the cluster PAT's scope.
	ClusterID string
	// ClusterPAT is the bearer token presented to the ImportAPI. Treat as
	// secret; do not log. Sourced from a file path at startup, not env.
	ClusterPAT string
	// RetentionSuffix is appended to the target tag in the cluster
	// namespace (e.g. `--idle-90d`). Empty means use the ImportAPI's
	// server-side default (`--idle-90d`).
	RetentionSuffix string
	// RequestTimeout caps a single ImportAPI call. The mount-from-repo
	// flow is normally sub-second (no byte transfer) but the timeout
	// guards against an upstream that hangs on layer enumeration.
	RequestTimeout time.Duration
}

// Validate enforces the consistency rules the rest of the service relies on.
// Returns nil for a disabled config so callers can validate unconditionally.
func (c AutoImportConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.HooksBaseURL) == "" {
		return errors.New("AutoImportConfig: HooksBaseURL required when Enabled")
	}
	if _, err := url.Parse(c.HooksBaseURL); err != nil {
		return fmt.Errorf("AutoImportConfig: HooksBaseURL invalid: %w", err)
	}
	if strings.TrimSpace(c.ClusterID) == "" {
		return errors.New("AutoImportConfig: ClusterID required when Enabled")
	}
	if strings.TrimSpace(c.ClusterPAT) == "" {
		return errors.New("AutoImportConfig: ClusterPAT required when Enabled")
	}
	if c.RetentionSuffix != "" && !strings.HasPrefix(c.RetentionSuffix, "--") {
		return fmt.Errorf("AutoImportConfig: RetentionSuffix must start with `--`, got %q", c.RetentionSuffix)
	}
	return nil
}

// AutoImportRequest is the per-sandbox import payload. Fields mirror what
// AOCR `ImportAPI` (hooks/src/controllers/ImportAPI.ts) expects on the
// wire; the JSON marshaller below pins the contract.
type AutoImportRequest struct {
	UpstreamHost   string
	UpstreamRepo   string
	UpstreamTag    string
	UpstreamDigest string
}

// AutoImportResult is what comes back. RegistryRef is the *cluster-side*
// pull reference the caller should write onto the sandbox spec (replacing
// the user's upstream ref for future recreates). AlreadyPresent=true
// means the destination tag already existed at the right digest — the
// importer treats that as success but the caller may want to suppress
// the spec mutation to avoid an unnecessary Raft write.
type AutoImportResult struct {
	RegistryRef    string
	AlreadyPresent bool
}

// AutoImporter is the leaf dependency that actually talks to AOCR. It
// holds no per-sandbox state; instantiate once at boot and reuse. Safe
// for concurrent use (it's just an http.Client wrapper).
type AutoImporter struct {
	cfg    AutoImportConfig
	client *http.Client
	// endpoint is the cached full URL so we don't re-parse on every call.
	endpoint string
}

// NewAutoImporter builds an importer. Returns nil if cfg.Enabled is false
// so callers can do `if importer == nil { return }` on the post-pull path
// without an extra config check.
func NewAutoImporter(cfg AutoImportConfig) (*AutoImporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &AutoImporter{
		cfg:      cfg,
		client:   &http.Client{Timeout: timeout},
		endpoint: strings.TrimRight(cfg.HooksBaseURL, "/") + "/v1/internal/imports",
	}, nil
}

// importBody is the on-the-wire payload. Field tags must exactly match
// the keys ImportAPI.ts validates against, otherwise the AOCR side returns
// 400 `invalid_request` — there is a regression test on both sides that
// pins these names.
type importBody struct {
	UpstreamHost     string `json:"upstream_host"`
	UpstreamRepo     string `json:"upstream_repo"`
	UpstreamTag      string `json:"upstream_tag,omitempty"`
	UpstreamDigest   string `json:"upstream_digest"`
	ClusterID        string `json:"cluster_id"`
	TargetTagSuffix  string `json:"target_tag_suffix,omitempty"`
}

// importResponse is the success shape. status is one of "imported" /
// "already_present" per ImportAPI.ts.
type importResponse struct {
	Status      string `json:"status"`
	RegistryRef string `json:"registry_ref"`
}

// Import calls the AOCR ImportAPI once. Idempotent on (upstream_digest,
// cluster_id, target_tag): re-posting an already-imported sandbox returns
// AlreadyPresent=true without an error. Network/HTTP failures return a
// wrapped error so the caller can decide whether to log+flag or surface.
func (a *AutoImporter) Import(ctx context.Context, req AutoImportRequest) (AutoImportResult, error) {
	if a == nil {
		return AutoImportResult{}, errors.New("auto-import disabled (importer is nil)")
	}
	if strings.TrimSpace(req.UpstreamHost) == "" || strings.TrimSpace(req.UpstreamRepo) == "" {
		return AutoImportResult{}, errors.New("auto-import: upstream host and repo required")
	}
	if strings.TrimSpace(req.UpstreamDigest) == "" {
		return AutoImportResult{}, errors.New("auto-import: upstream digest required (mount-from-repo is digest-keyed)")
	}

	body := importBody{
		UpstreamHost:    strings.TrimSpace(req.UpstreamHost),
		UpstreamRepo:    strings.TrimSpace(req.UpstreamRepo),
		UpstreamTag:     strings.TrimSpace(req.UpstreamTag),
		UpstreamDigest:  strings.TrimSpace(req.UpstreamDigest),
		ClusterID:       strings.TrimSpace(a.cfg.ClusterID),
		TargetTagSuffix: strings.TrimSpace(a.cfg.RetentionSuffix),
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return AutoImportResult{}, fmt.Errorf("auto-import: marshal body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return AutoImportResult{}, fmt.Errorf("auto-import: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.cfg.ClusterPAT)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return AutoImportResult{}, fmt.Errorf("auto-import: POST %s: %w", a.endpoint, err)
	}
	defer resp.Body.Close()

	// 401/403 means the cluster PAT is wrong or revoked — caller can use
	// this to surface a clear operator-visible alert rather than silently
	// retrying forever. We don't special-case it here; the wrapped error
	// message includes the status code.
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return AutoImportResult{}, fmt.Errorf("auto-import: AOCR returned HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var parsed importResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return AutoImportResult{}, fmt.Errorf("auto-import: decode response: %w", err)
	}
	if strings.TrimSpace(parsed.RegistryRef) == "" {
		return AutoImportResult{}, errors.New("auto-import: AOCR returned empty registry_ref")
	}
	return AutoImportResult{
		RegistryRef:    parsed.RegistryRef,
		AlreadyPresent: parsed.Status == "already_present",
	}, nil
}

// Endpoint is exposed for log/debug use. Returns "" for a nil importer so
// callers can log it unconditionally.
func (a *AutoImporter) Endpoint() string {
	if a == nil {
		return ""
	}
	return a.endpoint
}
