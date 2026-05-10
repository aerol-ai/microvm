package microvm

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	apiclient "github.com/aerol-ai/microvm/sdk/go/internal/apiclient"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const defaultAPIURL = "http://127.0.0.1:21212"
const authRequiredErrorMessage = "PAT token is required. Set PATToken or SB_PAT_TOKEN."

type Client struct {
	apiURL   string
	patToken string
	inner    *apiclient.Client
}

type Sandbox struct {
	sdktypes.Sandbox
	// SSHPrivateKey is populated only on the response from Client.Create. It
	// is the per-sandbox ed25519 private key the gateway authorizes; persist
	// it locally before discarding the create response, the server cannot
	// regenerate it.
	SSHPrivateKey string
	client        *Client
}

type ExecStreamHandle struct {
	inner *apiclient.ExecStreamHandle
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
		patToken = strings.TrimSpace(os.Getenv("SB_PAT_TOKEN"))
	}
	if apiURL == "" {
		apiURL = strings.TrimSpace(os.Getenv("SB_API_URL"))
		if apiURL == "" {
			apiURL = defaultAPIURL
		}
	}
	if patToken == "" {
		return nil, errors.New(authRequiredErrorMessage)
	}

	inner := apiclient.NewClient(apiURL, apiclient.ClientOptions{
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
	item, sshPrivateKey, err := c.inner.Create(ctx, opts)
	if err != nil {
		return nil, err
	}
	wrapped := wrapSandbox(c, item)
	wrapped.SSHPrivateKey = sshPrivateKey
	return wrapped, nil
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

// Mounts returns the redacted mount config for a sandbox. Credentials are
// never included; this endpoint is for showing the user what their sandbox
// has configured, not for retrieving secrets.
func (c *Client) Mounts(ctx context.Context, id string) ([]sdktypes.MountSpecRedacted, error) {
	return c.inner.Mounts(ctx, id)
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

// UpdateLifecycle replaces the per-sandbox lifecycle timers. Pass zero in
// any field to clear that timer; pass non-zero to set or extend it. The
// server validates and rejects negative durations, durations over the
// configured cap, or stop/destroy pairs where destroy fires before stop.
func (c *Client) UpdateLifecycle(ctx context.Context, id string, lifecycle sdktypes.Lifecycle) (*Sandbox, error) {
	item, err := c.inner.UpdateLifecycle(ctx, id, lifecycle)
	if err != nil {
		return nil, err
	}
	return wrapSandbox(c, item), nil
}

func (c *Client) Reconcile(ctx context.Context) error {
	return c.inner.Reconcile(ctx)
}

func (c *Client) Health(ctx context.Context) (sdktypes.HealthStatus, error) {
	return c.inner.Health(ctx)
}

func (c *Client) ExecStream(ctx context.Context, id string, options sdktypes.ExecStreamOptions) (*ExecStreamHandle, error) {
	handle, err := c.inner.ExecStream(ctx, id, options)
	if err != nil {
		return nil, err
	}
	return &ExecStreamHandle{inner: handle}, nil
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

func (s *Sandbox) ExecStream(ctx context.Context, options sdktypes.ExecStreamOptions) (*ExecStreamHandle, error) {
	return s.client.ExecStream(ctx, s.ID, options)
}

func (s *Sandbox) UploadFile(ctx context.Context, targetPath string, data []byte) error {
	return s.client.inner.UploadFile(ctx, s.ID, targetPath, data)
}

func (s *Sandbox) DownloadFile(ctx context.Context, targetPath string) ([]byte, error) {
	return s.client.inner.DownloadFile(ctx, s.ID, targetPath)
}

// ExposeOption customizes an ExposePort call. Build values with WithProtocol;
// the variadic shape leaves room for future expansion (e.g. tags, idle TTL)
// without breaking call sites.
type ExposeOption func(*exposeOptions)

type exposeOptions struct {
	protocol sdktypes.ExposeProtocol
}

// WithProtocol selects the wire surface the exposure publishes through.
// Defaults to ExposeProtocolHTTP when omitted.
func WithProtocol(p sdktypes.ExposeProtocol) ExposeOption {
	return func(o *exposeOptions) { o.protocol = p }
}

// ExposePort publishes a sandbox container port. Use WithProtocol to choose a
// non-HTTP surface:
//
//   - WithProtocol(ExposeProtocolTCP): raw caddy-l4 listener on a parent-host
//     port. Pair with native protocol clients (psql, redis-cli, mysql,
//     mongosh). Result.Host and Result.HostPort are populated on this path.
//   - WithProtocol(ExposeProtocolTLS): caddy-l4 TLS-SNI route on the shared
//     listener. Requires --domain and SB_L4_TLS_LISTEN.
//
// With no option (or WithProtocol(ExposeProtocolHTTP)) the result is the
// default Caddy HTTP reverse-proxy URL.
func (s *Sandbox) ExposePort(ctx context.Context, port int, opts ...ExposeOption) (sdktypes.ExposeResult, error) {
	cfg := exposeOptions{protocol: sdktypes.ExposeProtocolHTTP}
	for _, opt := range opts {
		opt(&cfg)
	}
	return s.client.inner.ExposePort(ctx, s.ID, port, string(cfg.protocol))
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

func (s *Sandbox) UpdateLifecycle(ctx context.Context, lifecycle sdktypes.Lifecycle) error {
	item, err := s.client.UpdateLifecycle(ctx, s.ID, lifecycle)
	if err != nil {
		return err
	}
	s.Sandbox = item.Sandbox
	return nil
}

func (h *ExecStreamHandle) Write(data []byte) error {
	return h.inner.Write(data)
}

func (h *ExecStreamHandle) WriteString(data string) error {
	return h.inner.WriteString(data)
}

func (h *ExecStreamHandle) Resize(cols, rows int) error {
	return h.inner.Resize(cols, rows)
}

func (h *ExecStreamHandle) Signal(name string) error {
	return h.inner.Signal(name)
}

func (h *ExecStreamHandle) Close() error {
	return h.inner.Close()
}

func (h *ExecStreamHandle) Wait() (sdktypes.ExecExitInfo, error) {
	return h.inner.Wait()
}

func wrapSandbox(client *Client, item *apiclient.Sandbox) *Sandbox {
	if item == nil {
		return nil
	}
	return &Sandbox{
		Sandbox: item.Sandbox,
		client:  client,
	}
}
