package microvm

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	basesdk "github.com/aerol-ai/microvm/sdk/go"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const defaultAPIURL = "http://127.0.0.1:8080"
const authRequiredErrorMessage = "PAT token is required. Set PATToken or SB_PAT_TOKEN/SB_API_TOKEN."

type Client struct {
	apiURL   string
	patToken string
	inner    *basesdk.Client
}

type Sandbox struct {
	sdktypes.Sandbox
	client *Client
}

func NewClient() (*Client, error) {
	return NewClientWithConfig(nil)
}

func NewClientWithConfig(config *sdktypes.MicroVMConfig) (*Client, error) {
	apiURL := ""
	patToken := ""
	var httpClient *http.Client

	if config != nil {
		apiURL = strings.TrimSpace(config.APIUrl)
		patToken = strings.TrimSpace(config.PATToken)
		httpClient = config.HTTPClient
	}

	if patToken == "" {
		patToken = firstNonEmptyEnv("SB_PAT_TOKEN", "SB_API_TOKEN")
	}
	if apiURL == "" {
		apiURL = firstNonEmptyEnv("SB_API_URL", "SB_SERVER_URL")
		if apiURL == "" {
			apiURL = defaultAPIURL
		}
	}
	if patToken == "" {
		return nil, errors.New(authRequiredErrorMessage)
	}

	inner := basesdk.NewClientWithOptions(apiURL, basesdk.ClientOptions{
		PATToken:   patToken,
		HTTPClient: httpClient,
	})

	return &Client{
		apiURL:   strings.TrimRight(apiURL, "/"),
		patToken: patToken,
		inner:    inner,
	}, nil
}

func (c *Client) Create(ctx context.Context, opts sdktypes.CreateSandboxOptions) (*Sandbox, error) {
	item, err := c.inner.Create(ctx, opts)
	if err != nil {
		return nil, err
	}
	return wrapSandbox(c, item), nil
}

func (c *Client) List(ctx context.Context) ([]*Sandbox, error) {
	items, err := c.inner.List(ctx)
	if err != nil {
		return nil, err
	}
	wrapped := make([]*Sandbox, 0, len(items))
	for _, item := range items {
		wrapped = append(wrapped, wrapSandbox(c, item))
	}
	return wrapped, nil
}

func (c *Client) Get(ctx context.Context, id string) (*Sandbox, error) {
	item, err := c.inner.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return wrapSandbox(c, item), nil
}

func (c *Client) Start(ctx context.Context, id string) (*Sandbox, error) {
	item, err := c.inner.Start(ctx, id)
	if err != nil {
		return nil, err
	}
	return wrapSandbox(c, item), nil
}

func (c *Client) Stop(ctx context.Context, id string) (*Sandbox, error) {
	item, err := c.inner.Stop(ctx, id)
	if err != nil {
		return nil, err
	}
	return wrapSandbox(c, item), nil
}

func (c *Client) Destroy(ctx context.Context, id string) error {
	return c.inner.Destroy(ctx, id)
}

func (c *Client) Resize(ctx context.Context, id string, opts sdktypes.ResizeSandboxOptions) (*Sandbox, error) {
	item, err := c.inner.Resize(ctx, id, opts)
	if err != nil {
		return nil, err
	}
	return wrapSandbox(c, item), nil
}

func (c *Client) Health(ctx context.Context) (sdktypes.HealthStatus, error) {
	return c.inner.Health(ctx)
}

func (s *Sandbox) Refresh(ctx context.Context) error {
	item, err := s.client.Get(ctx, s.ID)
	if err != nil {
		return err
	}
	s.Sandbox = item.Sandbox
	return nil
}

func (s *Sandbox) Exec(ctx context.Context, request sdktypes.ExecRequest) (sdktypes.ExecResult, error) {
	return s.client.inner.Exec(ctx, s.ID, request)
}

func (s *Sandbox) ExecCommand(ctx context.Context, command string) (sdktypes.ExecResult, error) {
	return s.client.inner.Exec(ctx, s.ID, sdktypes.ExecRequest{Command: command})
}

func (s *Sandbox) UploadFile(ctx context.Context, targetPath string, data []byte) error {
	return s.client.inner.UploadFile(ctx, s.ID, targetPath, data)
}

func (s *Sandbox) DownloadFile(ctx context.Context, targetPath string) ([]byte, error) {
	return s.client.inner.DownloadFile(ctx, s.ID, targetPath)
}

func (s *Sandbox) ExposePort(ctx context.Context, port int) (string, error) {
	return s.client.inner.ExposePort(ctx, s.ID, port)
}

func (s *Sandbox) UnexposePort(ctx context.Context, port int) error {
	return s.client.inner.UnexposePort(ctx, s.ID, port)
}

func (s *Sandbox) Start(ctx context.Context) error {
	item, err := s.client.Start(ctx, s.ID)
	if err != nil {
		return err
	}
	s.Sandbox = item.Sandbox
	return nil
}

func (s *Sandbox) Stop(ctx context.Context) error {
	item, err := s.client.Stop(ctx, s.ID)
	if err != nil {
		return err
	}
	s.Sandbox = item.Sandbox
	return nil
}

func (s *Sandbox) Destroy(ctx context.Context) error {
	return s.client.Destroy(ctx, s.ID)
}

func (s *Sandbox) Resize(ctx context.Context, opts sdktypes.ResizeSandboxOptions) error {
	item, err := s.client.Resize(ctx, s.ID, opts)
	if err != nil {
		return err
	}
	s.Sandbox = item.Sandbox
	return nil
}

func wrapSandbox(client *Client, item *basesdk.Sandbox) *Sandbox {
	if item == nil {
		return nil
	}
	return &Sandbox{
		Sandbox: item.Sandbox,
		client:  client,
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
