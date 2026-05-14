package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

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
}

type ClientOptions struct {
	PATToken   string
	HTTPClient *http.Client
	// APIVersion pins the wire version this client speaks. Empty defaults to
	// the SDK's pinned default (v1 today). Pass APIVersionV1 explicitly to
	// guarantee stability across SDK upgrades.
	APIVersion APIVersion
}

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
	return &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		patToken:      config.PATToken,
		httpClient:    httpClient,
		apiVersion:    version,
		versionPrefix: prefix,
	}
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

func (c *Client) BuildImage(ctx context.Context, dockerfile string) (string, error) {
	type buildImageRequest struct {
		DockerfileContent string `json:"dockerfile_content"`
	}
	type buildImageResponse struct {
		Image string `json:"image"`
	}

	if strings.TrimSpace(dockerfile) == "" {
		return "", errors.New("dockerfile_content is required")
	}

	encoded, err := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	if err != nil {
		return "", err
	}

	path := c.versioned("/images/build")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, response.Body)
		return "", fmt.Errorf(
			"this daemon does not support Image builds (POST %s is not registered) — pass a string image reference (e.g. \"ubuntu:22.04\") instead, or upgrade the daemon",
			path,
		)
	}
	if response.StatusCode >= 400 {
		return "", decodeError(response)
	}

	var payload buildImageResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Image, nil
}

func (c *Client) List(ctx context.Context) ([]*Sandbox, error) {
	var response []models.Sandbox
	if err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes", nil, &response); err != nil {
		return nil, err
	}
	items := make([]*Sandbox, 0, len(response))
	for _, item := range response {
		items = append(items, c.wrap(item))
	}
	return items, nil
}

func (c *Client) Get(ctx context.Context, id string) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodGet, c.versionPrefix+"/sandboxes/"+id, nil, &response); err != nil {
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

func (c *Client) Destroy(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, c.versionPrefix+"/sandboxes/"+id, nil, nil)
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
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
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
