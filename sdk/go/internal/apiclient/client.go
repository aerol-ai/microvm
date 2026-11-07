package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	apiv1 "github.com/aerol-ai/microvm/sdk/go/internal/apiclient/v1"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// APIVersion selects which wire version of the sandbox daemon API to call.
// The SDK package version and the API wire version evolve independently —
// pinning the SDK doesn't pin the wire version, and vice versa.
type APIVersion string

const (
	// APIVersionV1 is the only version available today. Future versions add
	// new constants here without removing v1.
	APIVersionV1 APIVersion = "v1"

	defaultAPIVersion = APIVersionV1
)

var pathPrefixes = map[APIVersion]string{
	APIVersionV1: apiv1.PathPrefix,
}

type CreateOptions = models.CreateSandboxRequest
type ResizeOptions = models.ResizeSandboxRequest
type ExecRequest = models.ExecRequest
type ExecResult = models.ExecResult
type ExposedPort = models.ExposedPort
type ExposeResult = models.ExposePortResponse
type SandboxSnapshot = models.SandboxSnapshot
type HealthStatus = models.HealthStatus

// HeaderTeam is the request header that selects which of a credential's
// teams a request acts for. Keep in sync with pkg/api.HeaderTeam on the
// server.
const HeaderTeam = "X-AerolVM-Team"

type Client struct {
	baseURL       string
	patToken      string
	team          string
	httpClient    *http.Client
	apiVersion    APIVersion
	versionPrefix string
	retryConfig   RetryConfig

	// toolboxFeatures caches each sandbox's agent feature list from
	// /version (RequireToolboxFeatures). A miss refreshes it, because a
	// restart can bring a newer agent.
	featuresMu      sync.Mutex
	toolboxFeatures map[string]map[string]struct{}
}

type ClientOptions struct {
	PATToken string
	// Team is sent as the HeaderTeam header on every request and WebSocket
	// handshake. Empty sends no header, so the server picks the
	// credential's first matching binding.
	Team       string
	HTTPClient *http.Client
	// APIVersion pins the wire version this client speaks. Empty defaults to
	// the SDK's pinned default (v1 today). Pass APIVersionV1 explicitly to
	// guarantee stability across SDK upgrades.
	APIVersion APIVersion
	// Retry configures the policy for transient transport errors and retryable
	// HTTP status codes (421, 429, 502, 503, 504). Exec is narrower: it is
	// re-sent only when the connection never opened or on 429/503, because a
	// re-sent exec runs the command again. A 429 or 503 retry waits as long
	// as the server's Retry-After asks, up to MaxRetryAfterMs.
	Retry *RetryConfig
}

// RetryConfig specifies how the SDK should retry transient errors.
type RetryConfig struct {
	MaxRetries  *int
	BaseDelayMs *int
	MaxDelayMs  *int
	// MaxRetryAfterMs caps the wait a 429 or 503 Retry-After asks for.
	// Defaults to 30000; 0 or less ignores Retry-After.
	MaxRetryAfterMs *int
}

const (
	defaultMaxRetries  = 3
	defaultBaseDelayMs = 200
	defaultMaxDelayMs  = 5000
)

type Sandbox struct {
	models.Sandbox
	client *Client
}

func NewClient(baseURL string, config ClientOptions) *Client {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	version := config.APIVersion
	if version == "" {
		version = defaultAPIVersion
	}
	prefix, ok := pathPrefixes[version]
	if !ok {
		// Unknown versions silently fall back to default to keep this
		// constructor non-error-returning. Callers that need strictness
		// should validate APIVersion themselves before constructing.
		version = defaultAPIVersion
		prefix = pathPrefixes[defaultAPIVersion]
	}

	client := &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		patToken:      config.PATToken,
		team:          strings.TrimSpace(config.Team),
		httpClient:    httpClient,
		apiVersion:    version,
		versionPrefix: prefix,
	}
	if config.Retry != nil {
		client.retryConfig = *config.Retry
	}
	if client.retryConfig.MaxRetries == nil {
		v := defaultMaxRetries
		client.retryConfig.MaxRetries = &v
	}
	if client.retryConfig.BaseDelayMs == nil {
		v := defaultBaseDelayMs
		client.retryConfig.BaseDelayMs = &v
	}
	if client.retryConfig.MaxDelayMs == nil {
		v := defaultMaxDelayMs
		client.retryConfig.MaxDelayMs = &v
	}
	if client.retryConfig.MaxRetryAfterMs == nil {
		v := defaultMaxRetryAfterMs
		client.retryConfig.MaxRetryAfterMs = &v
	}
	return client
}

// versioned builds an API path with the active version's prefix prepended.
// Use this for every versioned call so a future wire version can be selected
// via ClientOptions.APIVersion without touching call sites.
func (c *Client) versioned(suffix string) string {
	return c.versionPrefix + suffix
}

// VersionPrefix exposes the active version's URL prefix so files in the same
// package (sessions.go, exec_stream.go) can build URLs without each
// re-implementing the helper. It is intentionally not exported outside the
// package.
func (c *Client) versionedURL() string { return c.versionPrefix }

// Create creates a sandbox under a fresh Idempotency-Key, the same on each
// of this call's automatic retries (see CreateWithIdempotencyKey).
func (c *Client) Create(ctx context.Context, opts CreateOptions) (*Sandbox, string, error) {
	return c.CreateWithIdempotencyKey(ctx, opts, "")
}

// BuildImagePushSpec is the wire shape of the per-request push directive
// sent to /v1/images/build. Mirrors the v1 server DTO; credentials are
// forwarded to the daemon as a one-shot X-Registry-Auth header on the
// underlying push call and are never persisted on the server.
type BuildImagePushSpec struct {
	Registry string
	Tag      string
	Server   string
	Username string
	Password string
}

// BuildImageResult holds the response of BuildImageWithPush.
type BuildImageResult struct {
	Image  string
	Pushed string
}

func (c *Client) BuildImage(ctx context.Context, dockerfile string) (string, error) {
	res, err := c.BuildImageWithPush(ctx, dockerfile, nil)
	if err != nil {
		return "", err
	}
	return res.Image, nil
}

// BuildImageWithPush is the variant that exposes the optional per-request
// push directive. When push is nil, behavior matches BuildImage.
func (c *Client) BuildImageWithPush(ctx context.Context, dockerfile string, push *BuildImagePushSpec) (BuildImageResult, error) {
	type buildImagePushBody struct {
		Registry string `json:"registry"`
		Tag      string `json:"tag,omitempty"`
		Server   string `json:"server,omitempty"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type buildImageRequest struct {
		DockerfileContent string              `json:"dockerfile_content"`
		Push              *buildImagePushBody `json:"push,omitempty"`
	}
	type buildImageResponse struct {
		Image  string `json:"image"`
		Pushed string `json:"pushed,omitempty"`
	}

	if strings.TrimSpace(dockerfile) == "" {
		return BuildImageResult{}, errors.New("dockerfile_content is required")
	}
	body := buildImageRequest{DockerfileContent: dockerfile}
	if push != nil {
		if strings.TrimSpace(push.Registry) == "" {
			return BuildImageResult{}, errors.New("push.registry is required when push is set")
		}
		if push.Username == "" || push.Password == "" {
			return BuildImageResult{}, errors.New("push.username and push.password are required when push is set")
		}
		body.Push = &buildImagePushBody{
			Registry: push.Registry,
			Tag:      push.Tag,
			Server:   push.Server,
			Username: push.Username,
			Password: push.Password,
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return BuildImageResult{}, err
	}

	path := c.versioned("/images/build")

	response, err := c.doWithRetry(ctx, retryIdempotent, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		c.addAuth(request)
		return request, nil
	})
	if err != nil {
		return BuildImageResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, response.Body)
		return BuildImageResult{}, fmt.Errorf(
			"this daemon does not support Image builds (POST %s is not registered) — pass a string image reference (e.g. \"ubuntu:22.04\") instead, or upgrade the daemon",
			path,
		)
	}
	if response.StatusCode >= 400 {
		return BuildImageResult{}, decodeError(response)
	}

	var payload buildImageResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return BuildImageResult{}, err
	}
	return BuildImageResult{Image: payload.Image, Pushed: payload.Pushed}, nil
}

func (c *Client) List(ctx context.Context, tags map[string]string) ([]*Sandbox, error) {
	return c.ListWithOptions(ctx, tags, false)
}

const maxClusterListPages = 100000

// ListWithOptions lists sandboxes; includeEnv appends ?include_env=true.
// In cluster mode the daemon pages via X-Cluster-List-Next-Page-Token; this
// drains pages until the next token is empty. maxClusterListPages is a safety
// cap (enough for 100k sandboxes at page size 1, or far more at default 100).
// Partial coverage or an unready placement view is returned as an error rather
// than a silent incomplete list.
func (c *Client) ListWithOptions(ctx context.Context, tags map[string]string, includeEnv bool) ([]*Sandbox, error) {
	return c.ListWithQuery(ctx, ListQuery{Tags: tags, IncludeEnv: includeEnv})
}

// ListWithQuery is ListWithOptions with every list filter.
func (c *Client) ListWithQuery(ctx context.Context, q ListQuery) ([]*Sandbox, error) {
	var items []*Sandbox
	pageToken := ""
	for page := 0; page < maxClusterListPages; page++ {
		response, next, err := c.ListPageWithQuery(ctx, q, pageToken)
		if err != nil {
			return nil, err
		}
		items = append(items, response...)
		pageToken = next
		if pageToken == "" {
			return items, nil
		}
	}
	return nil, errors.New("incomplete cluster list: exceeded max pages")
}

// ListPageWithOptions fetches exactly one cluster list page. The returned
// token is opaque and empty on the final page. This is the bounded-memory path
// for fleet inventory callers; partial/unready coverage is always an error.
func (c *Client) ListPageWithOptions(ctx context.Context, tags map[string]string, includeEnv bool, pageToken string) ([]*Sandbox, string, error) {
	return c.ListPageWithQuery(ctx, ListQuery{Tags: tags, IncludeEnv: includeEnv}, pageToken)
}

// ListQuery is the full set of GET /sandboxes filters.
type ListQuery struct {
	Tags       map[string]string
	IncludeEnv bool
	// Name filters to the caller's sandbox with this name (?name=). Servers
	// that predate name lookup ignore it; GetByName verifies the reply.
	Name string
	// Limit asks for at most this many rows per page (?limit=); 0 leaves the
	// server default. Single-node servers that predate single-node paging
	// return every row in one page, so callers that need a bound must also
	// cap the reply themselves.
	Limit int
}

// ListPageWithQuery is ListPageWithOptions with every list filter.
func (c *Client) ListPageWithQuery(ctx context.Context, q ListQuery, pageToken string) ([]*Sandbox, string, error) {
	basePath := c.versionPrefix + "/sandboxes" + buildSandboxQuery(q.Tags, q.IncludeEnv)
	basePath = appendQueryParam(basePath, "name", strings.TrimSpace(q.Name))
	if q.Limit > 0 {
		basePath = appendQueryParam(basePath, "limit", strconv.Itoa(q.Limit))
	}
	path := appendQueryParam(basePath, "page_token", pageToken)
	var response []models.Sandbox
	hdrs, err := c.doJSONHeaders(ctx, http.MethodGet, path, nil, &response, retryIdempotent)
	if err != nil {
		return nil, "", err
	}
	if hdrs.Get("X-Cluster-List-Partial") == "true" || hdrs.Get("X-Cluster-List-Placement-Ready") == "false" {
		return nil, "", errors.New("incomplete cluster list")
	}
	items := make([]*Sandbox, 0, len(response))
	for _, item := range response {
		items = append(items, c.wrap(item))
	}
	return items, strings.TrimSpace(hdrs.Get("X-Cluster-List-Next-Page-Token")), nil
}

func appendQueryParam(path, key, value string) string {
	if strings.TrimSpace(value) == "" {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

func buildSandboxQuery(tags map[string]string, includeEnv bool) string {
	values := make(url.Values)
	for k, v := range tags {
		values.Set("tag."+k, v)
	}
	if includeEnv {
		values.Set("include_env", "true")
	}
	if len(values) == 0 {
		return ""
	}
	return "?" + values.Encode()
}

// GetByName returns the caller's sandbox called name with one request, or an
// error matching ErrNotFound. Names are unique per owner. The reply is only
// trusted when it holds at most one sandbox carrying the requested name: a
// server that predates ?name= ignores the filter and returns an ordinary list
// page, and acting on its first row would target the wrong sandbox. That case
// returns an error matching ErrNameLookupUnsupported.
func (c *Client) GetByName(ctx context.Context, name string, includeEnv bool) (*Sandbox, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("sandbox name is required")
	}
	items, _, err := c.ListPageWithQuery(ctx, ListQuery{Name: name, IncludeEnv: includeEnv}, "")
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("sandbox %q: %w", name, ErrNotFound)
	}
	if len(items) > 1 || items[0].Name != name {
		return nil, fmt.Errorf("%s does not support sandbox name lookup; use the sandbox ID or upgrade the server: %w", c.baseURL, ErrNameLookupUnsupported)
	}
	return items[0], nil
}

func (c *Client) Get(ctx context.Context, id string) (*Sandbox, error) {
	return c.GetWithOptions(ctx, id, false)
}

// GetWithOptions fetches a sandbox; includeEnv appends ?include_env=true.
func (c *Client) GetWithOptions(ctx context.Context, id string, includeEnv bool) (*Sandbox, error) {
	var response models.Sandbox
	path := c.versionPrefix + "/sandboxes/" + id + buildSandboxQuery(nil, includeEnv)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Start(ctx context.Context, id string) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/start", nil, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Stop(ctx context.Context, id string) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/stop", nil, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

// CreateSnapshot saves a sandbox's files as a snapshot. allowPause nil
// leaves the server's default (pause a running sandbox briefly).
func (c *Client) CreateSnapshot(ctx context.Context, id, name string, allowPause *bool) (SandboxSnapshot, error) {
	var response models.SandboxSnapshot
	err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/snapshot",
		models.CreateSandboxSnapshotRequest{Name: name, AllowPause: allowPause}, &response)
	return response, err
}

// RegisterSnapshotOptions is the wire shape for Client.RegisterSnapshot.
// Exactly one of Image (a pre-built registry reference) or DockerfileContent
// (build inputs the daemon compiles via Image-builder) must be set.
type RegisterSnapshotOptions struct {
	Name              string
	Image             string
	DockerfileContent string
	ContextHashes     []string
	Entrypoint        []string
	RegionID          string
	CPU               float64
	GPU               float64
	MemoryMB          int
	DiskGB            int
}

// RegisterSnapshot persists a named snapshot pointing at either a caller-
// supplied image reference or a Dockerfile the daemon will build. Mirrors
// POST /v1/snapshots; returns the stored row so callers can read back the
// resolved image (which differs from the request when DockerfileContent is
// set — the daemon returns the content-addressed build tag).
func (c *Client) RegisterSnapshot(ctx context.Context, opts RegisterSnapshotOptions) (SandboxSnapshot, error) {
	type registerSnapshotRequest struct {
		Name              string   `json:"name"`
		Image             string   `json:"image,omitempty"`
		DockerfileContent string   `json:"dockerfile_content,omitempty"`
		ContextHashes     []string `json:"context_hashes,omitempty"`
		Entrypoint        []string `json:"entrypoint,omitempty"`
		RegionID          string   `json:"region_id,omitempty"`
		CPU               float64  `json:"cpu,omitempty"`
		GPU               float64  `json:"gpu,omitempty"`
		MemoryMB          int      `json:"memory_mb,omitempty"`
		DiskGB            int      `json:"disk_gb,omitempty"`
	}

	if strings.TrimSpace(opts.Name) == "" {
		return SandboxSnapshot{}, errors.New("name is required")
	}
	image := strings.TrimSpace(opts.Image)
	dockerfile := strings.TrimSpace(opts.DockerfileContent)
	switch {
	case image == "" && dockerfile == "":
		return SandboxSnapshot{}, errors.New("image or dockerfile_content is required")
	case image != "" && dockerfile != "":
		return SandboxSnapshot{}, errors.New("image and dockerfile_content are mutually exclusive")
	}

	body := registerSnapshotRequest{
		Name:              opts.Name,
		Image:             image,
		DockerfileContent: dockerfile,
		ContextHashes:     opts.ContextHashes,
		Entrypoint:        opts.Entrypoint,
		RegionID:          strings.TrimSpace(opts.RegionID),
		CPU:               opts.CPU,
		GPU:               opts.GPU,
		MemoryMB:          opts.MemoryMB,
		DiskGB:            opts.DiskGB,
	}
	var response models.SandboxSnapshot
	err := c.doJSON(ctx, http.MethodPost, c.versioned("/snapshots"), body, &response)
	return response, err
}

func (c *Client) Destroy(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, c.versionPrefix+"/sandboxes/"+id, nil, nil)
}

// CreateTemplate registers a Firecracker rootfs template. Returns a 202-shape
// row with status="pending"; callers poll GetTemplate until the row reaches
// "ready" (fast-boot available) or "ready_no_snapshot" (cold boot only).
// Idempotent when opts.ID is supplied — a duplicate ID is rejected with 409
// so retried CI steps don't register two rows for the same logical template.
func (c *Client) CreateTemplate(ctx context.Context, opts models.CreateTemplateRequest) (models.Template, error) {
	if strings.TrimSpace(opts.Image) == "" {
		return models.Template{}, errors.New("image is required")
	}
	var response models.Template
	err := c.doJSON(ctx, http.MethodPost, c.versioned("/templates"), opts, &response)
	return response, err
}

func (c *Client) ListTemplates(ctx context.Context) ([]models.Template, error) {
	var response []models.Template
	if err := c.doJSON(ctx, http.MethodGet, c.versioned("/templates"), nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) GetTemplate(ctx context.Context, id string) (models.Template, error) {
	var response models.Template
	err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/templates/"+id, nil, &response)
	return response, err
}

func (c *Client) DeleteTemplate(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, c.versionPrefix+"/templates/"+id, nil, nil)
}

// CreateWasmModule resolves module_ref on this host and upserts the catalogue.
// Returns a ready row on success. Idempotent when opts.ID is supplied and
// matches the same module_ref.
func (c *Client) CreateWasmModule(ctx context.Context, opts models.CreateWasmModuleRequest) (models.WasmModule, error) {
	if strings.TrimSpace(opts.ModuleRef) == "" {
		return models.WasmModule{}, errors.New("module_ref is required")
	}
	var response models.WasmModule
	err := c.doJSON(ctx, http.MethodPost, c.versioned("/wasm-modules"), opts, &response)
	return response, err
}

func (c *Client) ListWasmModules(ctx context.Context) ([]models.WasmModule, error) {
	var response []models.WasmModule
	if err := c.doJSON(ctx, http.MethodGet, c.versioned("/wasm-modules"), nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) GetWasmModule(ctx context.Context, id string) (models.WasmModule, error) {
	var response models.WasmModule
	err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/wasm-modules/"+id, nil, &response)
	return response, err
}

func (c *Client) DeleteWasmModule(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, c.versionPrefix+"/wasm-modules/"+id, nil, nil)
}

// PushWasmModule uploads a compiled core-wasip1 module to the registry under
// the caller's own credentials and returns the oci:// ref to use as ModuleRef
// on a later create. The daemon validates and forwards the bytes; it never
// stores them.
func (c *Client) PushWasmModule(ctx context.Context, opts models.PushWasmModuleOptions) (models.PushWasmModuleResponse, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return models.PushWasmModuleResponse{}, errors.New("name is required")
	}
	if strings.TrimSpace(opts.RegistryToken) == "" {
		return models.PushWasmModuleResponse{}, errors.New("registry token is required")
	}
	query := url.Values{"name": {opts.Name}}
	if strings.TrimSpace(opts.Tag) != "" {
		query.Set("tag", opts.Tag)
	}
	path := c.baseURL + c.versioned("/wasm-modules/push") + "?" + query.Encode()
	response, err := c.doWithRetry(ctx, retryIdempotent, func() (*http.Request, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(opts.Module))
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Registry-Token", opts.RegistryToken)
		if strings.TrimSpace(opts.RegistryUsername) != "" {
			req.Header.Set("X-Registry-Username", opts.RegistryUsername)
		}
		c.addAuth(req)
		return req, nil
	})
	if err != nil {
		return models.PushWasmModuleResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return models.PushWasmModuleResponse{}, decodeError(response)
	}
	var out models.PushWasmModuleResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return models.PushWasmModuleResponse{}, err
	}
	return out, nil
}

// RebuildTemplate kicks an operator-triggered snapshot rebuild. Idempotent
// under concurrent retry — the daemon's CAS collapses N parallel calls for
// the same ready template into one rebuild kick. Returns the row in its
// post-transition state (typically "unhealthy"); poll GetTemplate to observe
// the transition back to "ready".
//
// Returns an HTTP error (status 412) when the template is in a state where
// rebuild is unsafe (build in flight) or unsupported (ready_no_snapshot,
// failed — those need delete+recreate today).
func (c *Client) RebuildTemplate(ctx context.Context, id string) (models.Template, error) {
	var response models.Template
	err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/templates/"+id+"/rebuild", nil, &response)
	return response, err
}

func (c *Client) Reconcile(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/admin/reconcile", nil, nil)
}

func (c *Client) Resize(ctx context.Context, id string, opts ResizeOptions) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/resize", opts, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

// UpdateLifecycle replaces the per-sandbox lifecycle timers. Send all four
// fields; setting a field to zero clears that timer. The server validates,
// rejecting durations beyond the configured maximum and inconsistent
// stop/destroy pairs.
func (c *Client) UpdateLifecycle(ctx context.Context, id string, lifecycle models.Lifecycle) (*Sandbox, error) {
	var response models.Sandbox
	body := models.UpdateLifecycleRequest{Lifecycle: lifecycle}
	if err := c.doJSON(ctx, http.MethodPut, c.versionPrefix+"/sandboxes/"+id+"/lifecycle", body, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Mounts(ctx context.Context, id string) ([]models.MountSpecRedacted, error) {
	var response struct {
		Mounts []models.MountSpecRedacted `json:"mounts"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id+"/mounts", nil, &response); err != nil {
		return nil, err
	}
	return response.Mounts, nil
}

// CloneGeneration is the toolbox clone-generation marker (wire shape).
type CloneGeneration struct {
	Generation string `json:"generation"`
	ResumedAt  int64  `json:"resumed_at"`
}

func (c *Client) CloneGeneration(ctx context.Context, id string) (CloneGeneration, error) {
	var response CloneGeneration
	err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id+"/toolbox/clone-generation", nil, &response)
	return response, err
}

func (c *Client) GetNetworkUsage(ctx context.Context, id string) (models.NetworkUsage, error) {
	var response models.NetworkUsage
	if err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id+"/network/usage", nil, &response); err != nil {
		return models.NetworkUsage{}, err
	}
	return response, nil
}

// CheckNetworkPolicy evaluates a policy against a destination without a
// sandbox.
func (c *Client) CheckNetworkPolicy(ctx context.Context, request models.NetworkPolicyCheckRequest) (models.NetworkPolicyCheckResponse, error) {
	var response models.NetworkPolicyCheckResponse
	err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/network/policy/check", request, &response)
	return response, err
}

// SetNetworkPolicy replaces a sandbox's egress policy and returns the
// effective one.
func (c *Client) SetNetworkPolicy(ctx context.Context, id string, request models.NetworkPolicyRequest) (models.NetworkPolicy, error) {
	var response models.NetworkPolicy
	err := c.doJSON(ctx, http.MethodPut, c.versionPrefix+"/sandboxes/"+id+"/network/policy", request, &response)
	return response, err
}

// GetNetworkLearned reads a sandbox's learn-mode recording.
func (c *Client) GetNetworkLearned(ctx context.Context, id string) (models.NetworkLearned, error) {
	var response models.NetworkLearned
	err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id+"/network/learned", nil, &response)
	return response, err
}

func (c *Client) egressProfilePath(name string) string {
	return c.versionPrefix + "/egress-profiles/" + url.PathEscape(name)
}

// PutEgressProfile creates or replaces a named egress profile.
func (c *Client) PutEgressProfile(ctx context.Context, name string, request models.EgressProfileRequest) (models.EgressProfile, error) {
	var response models.EgressProfile
	err := c.doJSON(ctx, http.MethodPut, c.egressProfilePath(name), request, &response)
	return response, err
}

// GetEgressProfile reads one named egress profile.
func (c *Client) GetEgressProfile(ctx context.Context, name string) (models.EgressProfile, error) {
	var response models.EgressProfile
	err := c.doJSON(ctx, http.MethodGet, c.egressProfilePath(name), nil, &response)
	return response, err
}

// ListEgressProfiles reads one page of named egress profiles.
func (c *Client) ListEgressProfiles(ctx context.Context, opts sdktypes.ListEgressProfilesOptions) (models.EgressProfileList, error) {
	values := make(url.Values)
	if opts.Cursor != "" {
		values.Set("cursor", opts.Cursor)
	}
	if opts.Limit > 0 {
		values.Set("limit", strconv.Itoa(opts.Limit))
	}
	path := c.versionPrefix + "/egress-profiles"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	var response models.EgressProfileList
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return models.EgressProfileList{}, err
	}
	if response.Profiles == nil {
		response.Profiles = []models.EgressProfile{}
	}
	return response, nil
}

// DeleteEgressProfile removes a named egress profile.
func (c *Client) DeleteEgressProfile(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodDelete, c.egressProfilePath(name), nil, nil)
}

func (c *Client) teamQuotaPath(team string) string {
	return c.versionPrefix + "/teams/" + url.PathEscape(team) + "/quota"
}

// PutTeamQuota sets a team's quota (admin only). Idempotent: the same
// limits twice change nothing, so it retries like a read.
func (c *Client) PutTeamQuota(ctx context.Context, team string, request models.TeamQuotaRequest) (models.TeamQuota, error) {
	var response models.TeamQuota
	err := c.doJSON(ctx, http.MethodPut, c.teamQuotaPath(team), request, &response)
	return response, err
}

// GetTeamQuota reads a team's quota and what the team holds now.
func (c *Client) GetTeamQuota(ctx context.Context, team string) (models.TeamQuota, error) {
	var response models.TeamQuota
	err := c.doJSON(ctx, http.MethodGet, c.teamQuotaPath(team), nil, &response)
	return response, err
}

// DeleteTeamQuota removes a team's quota; one already gone is a success.
func (c *Client) DeleteTeamQuota(ctx context.Context, team string) error {
	return c.doJSON(ctx, http.MethodDelete, c.teamQuotaPath(team), nil, nil)
}

func (c *Client) snapshotPath(name string) string {
	return c.versionPrefix + "/snapshots/" + url.PathEscape(name)
}

// GetSnapshot reads one named snapshot's metadata.
func (c *Client) GetSnapshot(ctx context.Context, name string) (SandboxSnapshot, error) {
	var response models.SandboxSnapshot
	err := c.doJSON(ctx, http.MethodGet, c.snapshotPath(name), nil, &response)
	return response, err
}

// ListSnapshots reads one page of named snapshots. Limit and StartingAfter
// map to the `limit` and `starting_after` query params; the wire `has_more`
// flag is surfaced on SnapshotList.HasMore.
func (c *Client) ListSnapshots(ctx context.Context, opts sdktypes.ListSnapshotsOptions) (sdktypes.SnapshotList, error) {
	values := make(url.Values)
	if opts.Limit > 0 {
		values.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.StartingAfter != "" {
		values.Set("starting_after", opts.StartingAfter)
	}
	path := c.versioned("/snapshots")
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	var response sdktypes.SnapshotList
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return sdktypes.SnapshotList{}, err
	}
	if response.Snapshots == nil {
		response.Snapshots = []sdktypes.SandboxSnapshot{}
	}
	return response, nil
}

// DeleteSnapshot removes a named snapshot.
func (c *Client) DeleteSnapshot(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodDelete, c.snapshotPath(name), nil, nil)
}

// GetAudit reads one page of a sandbox's audit log.
func (c *Client) GetAudit(ctx context.Context, id string, opts sdktypes.AuditOptions) (sdktypes.AuditPage, error) {
	values := make(url.Values)
	if opts.Kind != "" {
		values.Set("kind", opts.Kind)
	}
	if opts.Limit > 0 {
		values.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Cursor != "" {
		values.Set("cursor", opts.Cursor)
	}
	if opts.IncarnationID != "" {
		values.Set("incarnation_id", opts.IncarnationID)
	}
	if opts.Caller != "" {
		values.Set("caller", opts.Caller)
	}
	path := c.versionPrefix + "/sandboxes/" + id + "/audit"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	var page sdktypes.AuditPage
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &page); err != nil {
		return sdktypes.AuditPage{}, err
	}
	if page.Events == nil {
		page.Events = []sdktypes.AuditEvent{}
	}
	return page, nil
}

func (c *Client) SetNetworkLimits(ctx context.Context, id string, request models.UpdateNetworkLimitsRequest) (models.NetworkUsage, error) {
	var response models.NetworkUsage
	if err := c.doJSON(ctx, http.MethodPatch, c.versionPrefix+"/sandboxes/"+id+"/network/limits", request, &response); err != nil {
		return models.NetworkUsage{}, err
	}
	return response, nil
}

// Exec runs a command in the sandbox and waits for it to finish. Unlike the
// other endpoints, exec is not safe to re-send: the toolbox runs the command
// once per request it receives, and a timeout or dropped connection after the
// request was written cannot tell whether it already ran. So it is retried
// only when the connection never opened or the server refused it with 429 or
// 503; any other failure is returned to the caller.
//
// MaxStdoutBytes, MaxStderrBytes and Argv are checked against the sandbox's
// agent first: an agent older than them would ignore the caps and return all
// output, or refuse argv with a confusing "command is required", so the call
// fails with *UnsupportedFeatureError instead.
func (c *Client) Exec(ctx context.Context, id string, request ExecRequest) (ExecResult, error) {
	var response ExecResult
	var features []string
	if request.MaxStdoutBytes != 0 || request.MaxStderrBytes != 0 {
		features = append(features, "exec.max_output_bytes")
	}
	if len(request.Argv) > 0 {
		features = append(features, "exec.argv")
	}
	if err := c.RequireToolboxFeatures(ctx, id, features...); err != nil {
		return response, err
	}
	_, err := c.doJSONHeaders(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/toolbox/process/execute", request, &response, retryUnsentOnly)
	return response, err
}

// UploadFile uploads data to targetPath with no write options.
func (c *Client) UploadFile(ctx context.Context, id, targetPath string, data []byte) error {
	return c.UploadFileWithOptions(ctx, id, targetPath, data, sdktypes.UploadFileOptions{})
}

// UploadFileStream uploads r to targetPath with no write options; see
// UploadFileStreamWithOptions.
func (c *Client) UploadFileStream(ctx context.Context, id, targetPath string, r io.Reader) error {
	return c.UploadFileStreamWithOptions(ctx, id, targetPath, r, sdktypes.UploadFileOptions{})
}

// DownloadFileStream opens targetPath for reading without buffering it. The
// caller reads the returned body and must Close it; closing early (after the
// first window of a large file, say) ends the transfer. The request retries
// like any other GET until the response headers arrive.
func (c *Client) DownloadFileStream(ctx context.Context, id, targetPath string) (io.ReadCloser, error) {
	return c.DownloadFileStreamWithOptions(ctx, id, targetPath, sdktypes.DownloadFileOptions{})
}

// DownloadFile reads the whole of targetPath. It retries like any safe call.
func (c *Client) DownloadFile(ctx context.Context, id, targetPath string) ([]byte, error) {
	return c.DownloadFileWithOptions(ctx, id, targetPath, sdktypes.DownloadFileOptions{})
}

// ExposePort publishes a sandbox container port. Pass an empty protocol to
// fall back to the default HTTP routing; pass "tcp" or "tls" to opt into the
// caddy-l4 surfaces. Host and HostPort on the returned ExposeResult are
// populated only on the "tcp" path. The first exposure makes a private
// sandbox public (AllowPublicTraffic omitted or false at create alike).
func (c *Client) ExposePort(ctx context.Context, id string, port int, protocol string) (ExposeResult, error) {
	return c.ExposePortWithVisibility(ctx, id, port, protocol, "")
}

// ExposePortWithVisibility is ExposePort with a visibility: "token" makes the
// URL need a sandbox token for this port, "public" opens it. Empty sends
// none, so a new port is public and an exposed port keeps its gate (a plain
// retry never opens a token port).
func (c *Client) ExposePortWithVisibility(ctx context.Context, id string, port int, protocol, visibility string) (ExposeResult, error) {
	var body any
	fields := map[string]string{}
	if protocol != "" && protocol != "http" {
		fields["protocol"] = protocol
	}
	if visibility != "" {
		fields["visibility"] = visibility
	}
	if len(fields) > 0 {
		body = fields
	}
	var response ExposeResult
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf(c.versionPrefix+"/sandboxes/%s/ports/%d", id, port), body, &response)
	return response, err
}

func (c *Client) UnexposePort(ctx context.Context, id string, port int) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf(c.versionPrefix+"/sandboxes/%s/ports/%d", id, port), nil, nil)
}

// CreateSandboxToken issues a signed token scoped to one sandbox (POST
// /v1/sandboxes/{id}/tokens). Not idempotent by nature: every call makes a
// new token and the server stores none. It uses the normal retry tier: a
// retry after a lost answer makes a second token nobody holds, which simply
// expires.
func (c *Client) CreateSandboxToken(ctx context.Context, id string, req models.CreateSandboxTokenRequest) (models.SandboxToken, error) {
	var out models.SandboxToken
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf(c.versionPrefix+"/sandboxes/%s/tokens", id), req, &out)
	return out, err
}

// RevokeSandboxTokens makes every token issued for one sandbox so far stop
// working (POST /v1/sandboxes/{id}/tokens/revoke). A token issued after it
// works. Safe to retry: a repeated call refuses the same tokens again (plus
// any issued in between), so it uses the normal retry tier.
func (c *Client) RevokeSandboxTokens(ctx context.Context, id string) (models.RevokeSandboxTokensResponse, error) {
	var out models.RevokeSandboxTokensResponse
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf(c.versionPrefix+"/sandboxes/%s/tokens/revoke", id), nil, &out)
	return out, err
}

// customDomainsEnvelope mirrors the {"custom_domains":[...]} shape used by
// both the add and list responses, so a single decoder handles both routes.
type customDomainsEnvelope struct {
	CustomDomains []models.CustomDomain `json:"custom_domains"`
}

// AddCustomDomain attaches an operator-provided public hostname to a sandbox.
// targetPort is the in-container TCP port traffic for the hostname should
// dial; pass 0 to route to the toolbox agent (the pre-target-port default,
// preserving existing behavior). The port is set once at attach time —
// changing it requires detach + re-add. Returns the full per-hostname row
// list so callers don't need a follow-up GET to read the canonical hostname
// or initial status. The server normalizes hostname; passing it verbatim is
// correct.
func (c *Client) AddCustomDomain(ctx context.Context, id, hostname string, targetPort int) ([]models.CustomDomain, error) {
	body := models.AddCustomDomainRequest{Hostname: hostname, TargetPort: targetPort}
	var response customDomainsEnvelope
	if err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/custom-domains", body, &response); err != nil {
		return nil, err
	}
	return response.CustomDomains, nil
}

// RemoveCustomDomain detaches a hostname. The hostname is URL-encoded so dots
// and other DNS-legal characters survive the path round-trip; the server
// re-normalizes (lowercase, trim trailing dot) before comparing.
func (c *Client) RemoveCustomDomain(ctx context.Context, id, hostname string) error {
	return c.doJSON(ctx, http.MethodDelete, c.versionPrefix+"/sandboxes/"+id+"/custom-domains/"+url.PathEscape(hostname), nil, nil)
}

// ListCustomDomains returns the per-hostname rows attached to a sandbox. Same
// envelope shape as AddCustomDomain so one decoder serves both routes.
func (c *Client) ListCustomDomains(ctx context.Context, id string) ([]models.CustomDomain, error) {
	var response customDomainsEnvelope
	if err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id+"/custom-domains", nil, &response); err != nil {
		return nil, err
	}
	return response.CustomDomains, nil
}

// DNSTarget returns the cluster-published ingress target — the hostname or
// IP set custom-domain DNS records should point at. The shape is stable
// across deployments; callers branch on Source ("hostname" / "ips" / "mixed"
// / "unknown") rather than guessing from which fields are populated.
func (c *Client) DNSTarget(ctx context.Context) (models.IngressTarget, error) {
	var response models.IngressTarget
	err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/ingress/dns", nil, &response)
	return response, err
}

// CustomDomainDNS returns the ready-to-paste DNS records (one row per custom
// domain × per ingress address) for a sandbox plus the underlying ingress
// target the records were composed from. Lets callers render a DNS-setup UI
// without having to combine ListCustomDomains and DNSTarget themselves.
func (c *Client) CustomDomainDNS(ctx context.Context, id string) (models.CustomDomainDNSRecords, error) {
	var response models.CustomDomainDNSRecords
	err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id+"/custom-domains/dns", nil, &response)
	return response, err
}

func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	var response HealthStatus
	err := c.doJSON(ctx, http.MethodGet, "/health", nil, &response)
	return response, err
}

func (s *Sandbox) Refresh(ctx context.Context) error {
	updated, err := s.client.Get(ctx, s.ID)
	if err != nil {
		return err
	}
	s.Sandbox = updated.Sandbox
	return nil
}

func (s *Sandbox) Exec(ctx context.Context, command string) (ExecResult, error) {
	return s.client.Exec(ctx, s.ID, ExecRequest{Command: command})
}

func (s *Sandbox) UploadFile(ctx context.Context, targetPath string, data []byte) error {
	return s.client.UploadFile(ctx, s.ID, targetPath, data)
}

// UploadFileStream uploads r to targetPath without buffering it.
func (s *Sandbox) UploadFileStream(ctx context.Context, targetPath string, r io.Reader) error {
	return s.client.UploadFileStream(ctx, s.ID, targetPath, r)
}

// DownloadFileStream opens targetPath for reading; the caller must Close it.
func (s *Sandbox) DownloadFileStream(ctx context.Context, targetPath string) (io.ReadCloser, error) {
	return s.client.DownloadFileStream(ctx, s.ID, targetPath)
}

func (s *Sandbox) DownloadFile(ctx context.Context, targetPath string) ([]byte, error) {
	return s.client.DownloadFile(ctx, s.ID, targetPath)
}

func (s *Sandbox) ExposePort(ctx context.Context, port int, protocol string) (ExposeResult, error) {
	return s.client.ExposePort(ctx, s.ID, port, protocol)
}

func (s *Sandbox) CreateToken(ctx context.Context, req models.CreateSandboxTokenRequest) (models.SandboxToken, error) {
	return s.client.CreateSandboxToken(ctx, s.ID, req)
}

func (s *Sandbox) RevokeTokens(ctx context.Context) (models.RevokeSandboxTokensResponse, error) {
	return s.client.RevokeSandboxTokens(ctx, s.ID)
}

func (s *Sandbox) AddCustomDomain(ctx context.Context, hostname string, targetPort int) ([]models.CustomDomain, error) {
	return s.client.AddCustomDomain(ctx, s.ID, hostname, targetPort)
}

func (s *Sandbox) RemoveCustomDomain(ctx context.Context, hostname string) error {
	return s.client.RemoveCustomDomain(ctx, s.ID, hostname)
}

func (s *Sandbox) ListCustomDomains(ctx context.Context) ([]models.CustomDomain, error) {
	return s.client.ListCustomDomains(ctx, s.ID)
}

func (s *Sandbox) Start(ctx context.Context) error {
	updated, err := s.client.Start(ctx, s.ID)
	if err != nil {
		return err
	}
	s.Sandbox = updated.Sandbox
	return nil
}

func (s *Sandbox) Stop(ctx context.Context) error {
	updated, err := s.client.Stop(ctx, s.ID)
	if err != nil {
		return err
	}
	s.Sandbox = updated.Sandbox
	return nil
}

func (s *Sandbox) Destroy(ctx context.Context) error {
	return s.client.Destroy(ctx, s.ID)
}

func (s *Sandbox) Resize(ctx context.Context, opts ResizeOptions) error {
	updated, err := s.client.Resize(ctx, s.ID, opts)
	if err != nil {
		return err
	}
	s.Sandbox = updated.Sandbox
	return nil
}

func (s *Sandbox) UpdateLifecycle(ctx context.Context, lifecycle models.Lifecycle) error {
	updated, err := s.client.UpdateLifecycle(ctx, s.ID, lifecycle)
	if err != nil {
		return err
	}
	s.Sandbox = updated.Sandbox
	return nil
}

// RequireToolboxFeatures fails closed unless the sandbox's agent lists every
// feature on /version. toolboxd ignores request options it does not know, so
// sending a newer option to an older agent would silently skip it (an
// overwrite guard, an output cap). The error is an *UnsupportedFeatureError.
func (c *Client) RequireToolboxFeatures(ctx context.Context, id string, features ...string) error {
	if len(features) == 0 {
		return nil
	}
	if c.hasToolboxFeatures(id, features) {
		return nil
	}
	var info struct {
		Version  string   `json:"version"`
		Features []string `json:"features"`
		Runtime  string   `json:"runtime"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+url.PathEscape(id)+"/toolbox/version", nil, &info); err != nil {
		return err
	}
	have := make(map[string]struct{}, len(info.Features))
	for _, f := range info.Features {
		have[f] = struct{}{}
	}
	c.featuresMu.Lock()
	if c.toolboxFeatures == nil {
		c.toolboxFeatures = map[string]map[string]struct{}{}
	}
	c.toolboxFeatures[id] = have
	c.featuresMu.Unlock()
	var missing []string
	for _, f := range features {
		if _, ok := have[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return &UnsupportedFeatureError{SandboxID: id, Features: missing, AgentVersion: info.Version, Runtime: info.Runtime}
	}
	return nil
}

func (c *Client) hasToolboxFeatures(id string, features []string) bool {
	c.featuresMu.Lock()
	defer c.featuresMu.Unlock()
	have, ok := c.toolboxFeatures[id]
	if !ok {
		return false
	}
	for _, f := range features {
		if _, ok := have[f]; !ok {
			return false
		}
	}
	return true
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	_, err := c.doJSONHeaders(ctx, method, path, requestBody, responseBody, retryIdempotent)
	return err
}

func (c *Client) doJSONHeaders(ctx context.Context, method, path string, requestBody any, responseBody any, policy retryPolicy) (http.Header, error) {
	return c.doJSONRequest(ctx, method, path, requestBody, responseBody, policy, nil)
}

// doJSONRequest is doJSONHeaders with extra request headers, set on every
// attempt so a retry carries them unchanged.
func (c *Client) doJSONRequest(ctx context.Context, method, path string, requestBody any, responseBody any, policy retryPolicy, extra http.Header) (http.Header, error) {
	var encoded []byte
	var err error
	if requestBody != nil {
		encoded, err = json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
	}

	response, err := c.doWithRetry(ctx, policy, func() (*http.Request, error) {
		var body io.Reader
		if encoded != nil {
			body = bytes.NewReader(encoded)
		}
		request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
		if err != nil {
			return nil, err
		}
		if encoded != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		for name, values := range extra {
			request.Header[name] = values
		}
		c.addAuth(request)
		return request, nil
	})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		return response.Header, decodeError(response)
	}
	if responseBody == nil || response.StatusCode == http.StatusNoContent {
		return response.Header.Clone(), nil
	}
	if err := json.NewDecoder(response.Body).Decode(responseBody); err != nil {
		return response.Header, err
	}
	return response.Header.Clone(), nil
}

// retryPolicy is the per-request choice of which failures doWithRetry may
// re-send after. The daemon designs most endpoints for idempotent retry, so a
// duplicate is harmless there; exec is the exception, because the toolbox runs
// the command once per request it receives.
type retryPolicy int

const (
	// retryIdempotent re-sends after any transient transport error or
	// retryable status. A timeout, reset or EOF can arrive after the server
	// received the request and acted on it, so this is only for endpoints that
	// tolerate a duplicate.
	retryIdempotent retryPolicy = iota
	// retryUnsentOnly re-sends only when the request provably never reached
	// the server (the connection never opened) or the server answered 429 or
	// 503, which it sends to refuse a request before doing any work. Every
	// other status, 421/502/504 included, is surfaced: the SDK cannot tell
	// which hop produced it, and a 502 or 504 can follow a command that
	// already started.
	retryUnsentOnly
)

func (p retryPolicy) retriesStatus(code int) bool {
	if p == retryUnsentOnly {
		return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
	}
	return isRetryableStatusCode(code)
}

func (p retryPolicy) retriesError(err error) bool {
	if p == retryUnsentOnly {
		return isUnsentTransportError(err)
	}
	return isTransientTransportError(err)
}

// isTransientTransportError reports whether err is a transport failure worth
// re-sending an idempotent request after. It is deliberately broad: a timeout,
// reset or EOF says the exchange failed, not that the request never reached
// the server, so it is only safe where a duplicate is harmless. Requests that
// must not be duplicated use isUnsentTransportError instead.
func isTransientTransportError(err error) bool {
	if err == nil {
		return false
	}
	// context errors are only retryable if it's DeadlineExceeded. Canceled
	// means the caller aborted, so we shouldn't retry.
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Typical Go network errors:
	msg := err.Error()
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "timeout") {
		return true
	}
	return false
}

// isUnsentTransportError reports whether err proves the request never left
// the client: the host name did not resolve, or the TCP connection was never
// opened (refused, or the connect itself timed out). It inspects typed errors
// rather than messages, because a "timeout" or "EOF" in a message cannot say
// whether the request was written first.
func isUnsentTransportError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// Through an HTTP proxy the dial failure is wrapped in a "proxyconnect"
	// OpError, and errors.As stops at the first OpError, so walk each one.
	for err != nil {
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			return false
		}
		if opErr.Op == "dial" {
			return true
		}
		err = opErr.Err
	}
	return false
}

// isRetryableStatusCode returns true for HTTP 421, 429 and 502/503/504. 421
// Misdirected Request means an owner answered for a sandbox it doesn't hold
// (connection coalescing or a stale route after failover). The server closes
// the connection, so the retry reconnects and the ingress re-routes it.
func isRetryableStatusCode(code int) bool {
	switch code {
	case http.StatusMisdirectedRequest, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// doWithRetry sends the request makeReq builds, re-sending it with jittered
// exponential backoff when policy allows the failure. A 429 or 503 waits as
// long as its Retry-After asks instead (see retryWait), and ctx ends any wait.
func (c *Client) doWithRetry(ctx context.Context, policy retryPolicy, makeReq func() (*http.Request, error)) (*http.Response, error) {
	return c.doWithRetryDone(ctx, policy, "", makeReq)
}

// doWithRetryDone is doWithRetry for a call whose retry can find its own
// work already done: a delete whose reply was lost finds the path gone, a
// mkdir finds its folder made. When a re-sent attempt gets an error reply
// carrying the toolbox error code doneCode, the call succeeds with an empty
// 204 (plan section 10, "Retries"), but only if an earlier attempt may have
// done the work: its reply was lost (a dropped connection, 502 or 504). A
// 421, 429 or 503 says the server did nothing, so a delete of a path that
// was never there still reports it after one, as the first attempt does.
func (c *Client) doWithRetryDone(ctx context.Context, policy retryPolicy, doneCode string, makeReq func() (*http.Request, error)) (*http.Response, error) {
	maxRetries := *c.retryConfig.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	var lastErr error
	mayHaveRun := false
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := makeReq()
		if err != nil {
			return nil, err // Can't even build the request, don't retry.
		}

		response, err := c.httpClient.Do(req)
		if err == nil && mayHaveRun && doneCode != "" && response.StatusCode >= 400 && replyHasCode(response, doneCode) {
			response.Body.Close()
			return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
		}
		// A connect-phase failure sent nothing (isUnsentTransportError), so,
		// as in the other SDKs, it says nothing about the work.
		if (err != nil && !isUnsentTransportError(err)) || (err == nil && replyMayBeLost(response.StatusCode)) {
			mayHaveRun = true
		}

		var retryAfter string
		if err == nil {
			// A response: re-send only a transient status with budget left.
			if !policy.retriesStatus(response.StatusCode) || attempt >= maxRetries {
				return response, nil
			}
			retryAfter = retryAfterHint(response)
			response.Body.Close()
		} else {
			// An error: re-send only if the policy allows it.
			lastErr = err
			if !policy.retriesError(err) || attempt >= maxRetries {
				break
			}
		}

		if err := sleepCtx(ctx, c.retryWait(attempt, retryAfter, time.Now(), rand.Float64())); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

// replyMayBeLost reports a status after which the server may still have
// done the work: a gateway gave up waiting for it (502, 504). 421, 429 and
// 503 are answered before any work.
func replyMayBeLost(code int) bool {
	return code == http.StatusBadGateway || code == http.StatusGatewayTimeout
}

// replyHasCode reports whether an error reply's JSON carries code. The body
// stays readable for decodeError.
func replyHasCode(response *http.Response, code string) bool {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	var reply models.ErrorResponse
	return json.Unmarshal(body, &reply) == nil && reply.Code == code
}

func (c *Client) addAuth(request *http.Request) {
	c.setAuthHeaders(request.Header)
}

// setAuthHeaders writes the credential and the team selection. Every HTTP
// request and WebSocket handshake goes through it, so a client built with a
// team never sends a request that acts for another one.
func (c *Client) setAuthHeaders(header http.Header) {
	if c.patToken != "" {
		header.Set("Authorization", "Bearer "+c.patToken)
	}
	if c.team != "" {
		header.Set(HeaderTeam, c.team)
	}
}

func (c *Client) wrap(sandbox models.Sandbox) *Sandbox {
	return &Sandbox{Sandbox: sandbox, client: c}
}
