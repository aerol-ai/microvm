package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	apiv1 "github.com/aerol-ai/microvm/sdk/go/internal/apiclient/v1"
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

type Client struct {
	baseURL       string
	patToken      string
	httpClient    *http.Client
	apiVersion    APIVersion
	versionPrefix string
	retryConfig   RetryConfig
}

type ClientOptions struct {
	PATToken   string
	HTTPClient *http.Client
	// APIVersion pins the wire version this client speaks. Empty defaults to
	// the SDK's pinned default (v1 today). Pass APIVersionV1 explicitly to
	// guarantee stability across SDK upgrades.
	APIVersion APIVersion
	// Retry configures the policy for transient transport errors and retryable
	// HTTP status codes (429, 502, 503, 504).
	Retry *RetryConfig
}

// RetryConfig specifies how the SDK should retry transient errors.
type RetryConfig struct {
	MaxRetries  *int
	BaseDelayMs *int
	MaxDelayMs  *int
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

func (c *Client) Create(ctx context.Context, opts CreateOptions) (*Sandbox, string, error) {
	var response models.CreateSandboxResponse
	if err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes", opts, &response); err != nil {
		return nil, "", err
	}
	return c.wrap(response.Sandbox), response.SSHPrivateKey, nil
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

	response, err := c.doWithRetry(ctx, func() (*http.Request, error) {
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

// ListWithOptions lists sandboxes; includeEnv appends ?include_env=true.
func (c *Client) ListWithOptions(ctx context.Context, tags map[string]string, includeEnv bool) ([]*Sandbox, error) {
	var response []models.Sandbox
	path := c.versionPrefix + "/sandboxes" + buildSandboxQuery(tags, includeEnv)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	items := make([]*Sandbox, 0, len(response))
	for _, item := range response {
		items = append(items, c.wrap(item))
	}
	return items, nil
}

// buildTagQuery renders the tag filter as the server's `?tag.<key>=<value>`
// wire format. The `tag.` prefix is literal — parseTagFilter on the server
// inspects the *decoded* query key — so only the user-supplied key and value
// get percent-encoded. An empty or nil map returns "" so the URL is identical
// to the pre-filter call (no stray trailing "?").
func buildTagQuery(tags map[string]string) string {
	return buildSandboxQuery(tags, false)
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

func (c *Client) CreateSnapshot(ctx context.Context, id, name string) (SandboxSnapshot, error) {
	var response models.SandboxSnapshot
	err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/snapshot", models.CreateSandboxSnapshotRequest{Name: name}, &response)
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
	response, err := c.doWithRetry(ctx, func() (*http.Request, error) {
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

func (c *Client) SetNetworkLimits(ctx context.Context, id string, request models.UpdateNetworkLimitsRequest) (models.NetworkUsage, error) {
	var response models.NetworkUsage
	if err := c.doJSON(ctx, http.MethodPatch, c.versionPrefix+"/sandboxes/"+id+"/network/limits", request, &response); err != nil {
		return models.NetworkUsage{}, err
	}
	return response, nil
}

func (c *Client) Exec(ctx context.Context, id string, request ExecRequest) (ExecResult, error) {
	var response ExecResult
	err := c.doJSON(ctx, http.MethodPost, c.versionPrefix+"/sandboxes/"+id+"/toolbox/process/execute", request, &response)
	return response, err
}

func (c *Client) UploadFile(ctx context.Context, id, targetPath string, data []byte) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("path", targetPath)
	part, err := writer.CreateFormFile("file", filepath.Base(targetPath))
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.versionPrefix+"/sandboxes/"+id+"/toolbox/files/upload", &body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return decodeError(response)
	}
	return nil
}

func (c *Client) DownloadFile(ctx context.Context, id, targetPath string) ([]byte, error) {
	encodedPath := url.QueryEscape(targetPath)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+c.versionPrefix+"/sandboxes/"+id+"/toolbox/files/download?path="+encodedPath, nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return nil, decodeError(response)
	}
	return io.ReadAll(response.Body)
}

// ExposePort publishes a sandbox container port. Pass an empty protocol to
// fall back to the default HTTP routing; pass "tcp" or "tls" to opt into the
// caddy-l4 surfaces. Host and HostPort on the returned ExposeResult are
// populated only on the "tcp" path.
func (c *Client) ExposePort(ctx context.Context, id string, port int, protocol string) (ExposeResult, error) {
	var body any
	if protocol != "" && protocol != "http" {
		body = map[string]string{"protocol": protocol}
	}
	var response ExposeResult
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf(c.versionPrefix+"/sandboxes/%s/ports/%d", id, port), body, &response)
	return response, err
}

func (c *Client) UnexposePort(ctx context.Context, id string, port int) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf(c.versionPrefix+"/sandboxes/%s/ports/%d", id, port), nil, nil)
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

func (s *Sandbox) DownloadFile(ctx context.Context, targetPath string) ([]byte, error) {
	return s.client.DownloadFile(ctx, s.ID, targetPath)
}

func (s *Sandbox) ExposePort(ctx context.Context, port int, protocol string) (ExposeResult, error) {
	return s.client.ExposePort(ctx, s.ID, port, protocol)
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

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	var encoded []byte
	var err error
	if requestBody != nil {
		encoded, err = json.Marshal(requestBody)
		if err != nil {
			return err
		}
	}

	response, err := c.doWithRetry(ctx, func() (*http.Request, error) {
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
		c.addAuth(request)
		return request, nil
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		return decodeError(response)
	}
	if responseBody == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(responseBody)
}

// isTransientTransportError loosely matches the Node.js SDK logic by checking
// if the error indicates a socket/connection failure before the server processed
// the request.
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

// isRetryableStatusCode returns true for HTTP 429 and 502/503/504.
func isRetryableStatusCode(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func (c *Client) doWithRetry(ctx context.Context, makeReq func() (*http.Request, error)) (*http.Response, error) {
	maxRetries := *c.retryConfig.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	baseDelayMs := *c.retryConfig.BaseDelayMs
	maxDelayMs := *c.retryConfig.MaxDelayMs

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := makeReq()
		if err != nil {
			return nil, err // Can't even build the request, don't retry.
		}

		response, err := c.httpClient.Do(req)

		// If we got a response, check if the status code is transient.
		if err == nil {
			if isRetryableStatusCode(response.StatusCode) && attempt < maxRetries {
				response.Body.Close()
				goto retry
			}
			return response, nil
		}

		// We got an error. Check if it's a transport error.
		lastErr = err
		if !isTransientTransportError(err) || attempt >= maxRetries {
			break
		}

	retry:
		delayMs := baseDelayMs * (1 << attempt)
		if delayMs > maxDelayMs {
			delayMs = maxDelayMs
		}
		// Jitter ±25%
		jitter := 1.0 + (rand.Float64()-0.5)*0.5
		sleepDuration := time.Duration(float64(delayMs)*jitter) * time.Millisecond

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleepDuration):
		}
	}
	return nil, lastErr
}

func (c *Client) addAuth(request *http.Request) {
	if c.patToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.patToken)
	}
}

func (c *Client) wrap(sandbox models.Sandbox) *Sandbox {
	return &Sandbox{Sandbox: sandbox, client: c}
}

func decodeError(response *http.Response) error {
	var payload models.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err == nil && payload.Error != "" {
		return errors.New(payload.Error)
	}
	return fmt.Errorf("request failed with status %d", response.StatusCode)
}
