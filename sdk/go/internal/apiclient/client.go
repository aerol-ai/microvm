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
)

type CreateOptions = models.CreateSandboxRequest
type ResizeOptions = models.ResizeSandboxRequest
type ExecRequest = models.ExecRequest
type ExecResult = models.ExecResult
type ExposedPort = models.ExposedPort
type HealthStatus = models.HealthStatus

type Client struct {
	baseURL    string
	patToken   string
	httpClient *http.Client
}

type ClientOptions struct {
	PATToken   string
	HTTPClient *http.Client
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
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		patToken:   config.PATToken,
		httpClient: httpClient,
	}
}

func (c *Client) Create(ctx context.Context, opts CreateOptions) (*Sandbox, string, error) {
	var response models.CreateSandboxResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sandboxes", opts, &response); err != nil {
		return nil, "", err
	}
	return c.wrap(response.Sandbox), response.SSHPrivateKey, nil
}

func (c *Client) List(ctx context.Context) ([]*Sandbox, error) {
	var response []models.Sandbox
	if err := c.doJSON(ctx, http.MethodGet, "/v1/sandboxes", nil, &response); err != nil {
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
	if err := c.doJSON(ctx, http.MethodGet, "/v1/sandboxes/"+id, nil, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Start(ctx context.Context, id string) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+id+"/start", nil, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Stop(ctx context.Context, id string) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+id+"/stop", nil, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Destroy(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/sandboxes/"+id, nil, nil)
}

func (c *Client) Reconcile(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/admin/reconcile", nil, nil)
}

func (c *Client) Resize(ctx context.Context, id string, opts ResizeOptions) (*Sandbox, error) {
	var response models.Sandbox
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+id+"/resize", opts, &response); err != nil {
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
	if err := c.doJSON(ctx, http.MethodPut, "/v1/sandboxes/"+id+"/lifecycle", body, &response); err != nil {
		return nil, err
	}
	return c.wrap(response), nil
}

func (c *Client) Mounts(ctx context.Context, id string) ([]models.MountSpecRedacted, error) {
	var response struct {
		Mounts []models.MountSpecRedacted `json:"mounts"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/sandboxes/"+id+"/mounts", nil, &response); err != nil {
		return nil, err
	}
	return response.Mounts, nil
}

func (c *Client) Exec(ctx context.Context, id string, request ExecRequest) (ExecResult, error) {
	var response ExecResult
	err := c.doJSON(ctx, http.MethodPost, "/v1/sandboxes/"+id+"/toolbox/process/execute", request, &response)
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

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/sandboxes/"+id+"/toolbox/files/upload", &body)
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/sandboxes/"+id+"/toolbox/files/download?path="+encodedPath, nil)
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

func (c *Client) ExposePort(ctx context.Context, id string, port int) (string, error) {
	var response struct {
		PublicURL string `json:"public_url"`
	}
	err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/v1/sandboxes/%s/ports/%d", id, port), nil, &response)
	return response.PublicURL, err
}

func (c *Client) UnexposePort(ctx context.Context, id string, port int) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/v1/sandboxes/%s/ports/%d", id, port), nil, nil)
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

func (s *Sandbox) ExposePort(ctx context.Context, port int) (string, error) {
	return s.client.ExposePort(ctx, s.ID, port)
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
