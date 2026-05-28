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
	apiVersion := ""
	var httpClient *http.Client

	if config != nil {
		apiURL = strings.TrimSpace(config.APIUrl)
		patToken = strings.TrimSpace(config.PATToken)
		httpClient = config.HTTPClient
		apiVersion = strings.TrimSpace(config.APIVersion)
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

	opts := apiclient.ClientOptions{
		PATToken:   patToken,
		HTTPClient: httpClient,
		APIVersion: apiclient.APIVersion(apiVersion),
	}
	if config != nil && config.Retry != nil {
		opts.Retry = &apiclient.RetryConfig{}
		if config.Retry.MaxRetries != nil {
			opts.Retry.MaxRetries = config.Retry.MaxRetries
		}
		if config.Retry.BaseDelayMs != nil {
			opts.Retry.BaseDelayMs = config.Retry.BaseDelayMs
		}
		if config.Retry.MaxDelayMs != nil {
			opts.Retry.MaxDelayMs = config.Retry.MaxDelayMs
		}
	}

	inner := apiclient.NewClient(apiURL, opts)

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

// BuildImage compiles an Image builder into a content-addressed image tag via
// POST /v1/images/build. Older daemons that do not register the route return a
// tailored error telling the caller to fall back to a plain string image.
func (c *Client) BuildImage(ctx context.Context, image *Image) (string, error) {
	if image == nil {
		return "", errors.New("image is nil")
	}
	if err := image.Err(); err != nil {
		return "", err
	}
	return c.inner.BuildImage(ctx, image.Dockerfile())
}

// BuildImageWithOptions builds an Image and optionally pushes the result to a
// remote registry. Push credentials are forwarded to the daemon as a one-shot
// X-Registry-Auth header and never persisted server-side. Returns the local
// content-addressed tag and (when push was requested) the pushed reference.
func (c *Client) BuildImageWithOptions(ctx context.Context, image *Image, opts sdktypes.BuildImageOptions) (sdktypes.BuildImageResult, error) {
	if image == nil {
		return sdktypes.BuildImageResult{}, errors.New("image is nil")
	}
	if err := image.Err(); err != nil {
		return sdktypes.BuildImageResult{}, err
	}
	var push *apiclient.BuildImagePushSpec
	if opts.Push != nil {
		push = &apiclient.BuildImagePushSpec{
			Registry: opts.Push.Registry,
			Tag:      opts.Push.Tag,
			Server:   opts.Push.Server,
			Username: opts.Push.Username,
			Password: opts.Push.Password,
		}
	}
	res, err := c.inner.BuildImageWithPush(ctx, image.Dockerfile(), push)
	if err != nil {
		return sdktypes.BuildImageResult{}, err
	}
	return sdktypes.BuildImageResult{Image: res.Image, Pushed: res.Pushed}, nil
}

// CreateWithImage builds an Image to a content-addressed tag, then creates the
// sandbox using the resolved string image. This keeps CreateSandboxOptions
// source-compatible with the server's request model.
func (c *Client) CreateWithImage(ctx context.Context, image *Image, opts sdktypes.CreateSandboxOptions) (*Sandbox, error) {
	tag, err := c.BuildImage(ctx, image)
	if err != nil {
		return nil, err
	}
	opts.Image = tag
	return c.Create(ctx, opts)
}

// ListOption customizes a List call. Build values with WithTags; the variadic
// shape leaves room for future filters (e.g. status, lifecycle) without
// breaking call sites.
type ListOption func(*listOptions)

type listOptions struct {
	tags map[string]string
}

// WithTags filters the result to sandboxes whose Tags map contains every
// supplied key/value pair (AND semantics on the server). Wire format is
// `?tag.<key>=<value>`; the SDK percent-encodes keys and values for you. An
// empty or nil map is a no-op — the call is identical to List(ctx).
func WithTags(tags map[string]string) ListOption {
	return func(o *listOptions) { o.tags = tags }
}

func (c *Client) List(ctx context.Context, opts ...ListOption) ([]*Sandbox, error) {
	var cfg listOptions
	for _, opt := range opts {
		opt(&cfg)
	}
	items, err := c.inner.List(ctx, cfg.tags)
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

// GetNetworkUsage returns current cumulative ingress/egress byte counters and
// the configured per-direction caps for a sandbox. A `*Limit` of zero means
// unlimited.
func (c *Client) GetNetworkUsage(ctx context.Context, id string) (sdktypes.NetworkUsage, error) {
	return c.inner.GetNetworkUsage(ctx, id)
}

// SetNetworkLimits raises or lifts the per-direction byte caps. Leave a field
// nil to keep the current value; pass a pointer to zero to set "unlimited".
// Raising a cap above current usage clears the per-IP iptables block on the
// next reconcile pass (or immediately if it's already over the new cap).
func (c *Client) SetNetworkLimits(ctx context.Context, id string, opts sdktypes.SetNetworkLimitsOptions) (sdktypes.NetworkUsage, error) {
	return c.inner.SetNetworkLimits(ctx, id, opts)
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

func (c *Client) CreateSnapshot(ctx context.Context, id, name string) (sdktypes.SandboxSnapshot, error) {
	return c.inner.CreateSnapshot(ctx, id, name)
}

// RegisterSnapshot persists a named snapshot pointing at either a pre-built
// image (opts.Image) or a Dockerfile the daemon will build (opts.Dockerfile
// — typically obtained from Image.Dockerfile()). The returned snapshot's
// Image field reflects the resolved registry reference (for the build path
// this is the daemon's content-addressed tag).
//
// Once registered, callers can reference the snapshot by name in
// CreateSandboxOptions.Snapshot — the server resolves it to the image at
// create time.
func (c *Client) RegisterSnapshot(ctx context.Context, opts sdktypes.RegisterSnapshotOptions) (sdktypes.SandboxSnapshot, error) {
	return c.inner.RegisterSnapshot(ctx, apiclient.RegisterSnapshotOptions{
		Name:              opts.Name,
		Image:             opts.Image,
		DockerfileContent: opts.DockerfileContent,
		ContextHashes:     opts.ContextHashes,
		Entrypoint:        opts.Entrypoint,
		RegionID:          opts.RegionID,
		CPU:               opts.CPU,
		GPU:               opts.GPU,
		MemoryMB:          opts.MemoryMB,
		DiskGB:            opts.DiskGB,
	})
}

// RegisterSnapshotFromImage compiles an Image-builder graph and registers
// the resulting Dockerfile as a named snapshot. Convenience wrapper around
// RegisterSnapshot that mirrors CreateWithImage's ergonomics — pass an
// *Image instead of remembering to call Image.Dockerfile() yourself.
func (c *Client) RegisterSnapshotFromImage(ctx context.Context, name string, image *Image, opts sdktypes.RegisterSnapshotOptions) (sdktypes.SandboxSnapshot, error) {
	if image == nil {
		return sdktypes.SandboxSnapshot{}, errors.New("image is nil")
	}
	if err := image.Err(); err != nil {
		return sdktypes.SandboxSnapshot{}, err
	}
	opts.Name = name
	opts.Image = ""
	opts.DockerfileContent = image.Dockerfile()
	return c.RegisterSnapshot(ctx, opts)
}

func (c *Client) Destroy(ctx context.Context, id string) error {
	return c.inner.Destroy(ctx, id)
}

// CreateTemplate registers a Firecracker rootfs template. Returns immediately
// with a status="pending" row; poll Client.GetTemplate until the row reaches
// "ready" (fast-boot available) or "ready_no_snapshot" (cold boot only).
//
// Idempotent when opts.ID is set: a duplicate ID returns 409 so a retried
// CI step does not register two rows for the same logical template.
func (c *Client) CreateTemplate(ctx context.Context, opts sdktypes.CreateTemplateOptions) (sdktypes.Template, error) {
	return c.inner.CreateTemplate(ctx, opts)
}

func (c *Client) ListTemplates(ctx context.Context) ([]sdktypes.Template, error) {
	return c.inner.ListTemplates(ctx)
}

func (c *Client) GetTemplate(ctx context.Context, id string) (sdktypes.Template, error) {
	return c.inner.GetTemplate(ctx, id)
}

func (c *Client) DeleteTemplate(ctx context.Context, id string) error {
	return c.inner.DeleteTemplate(ctx, id)
}

// RebuildTemplate re-runs the snapshot phase against an existing template.
// Idempotent under concurrent retry: the daemon's CAS collapses N parallel
// calls for the same ready template into one rebuild kick. Returns the row
// in its post-transition state (typically "unhealthy"); poll GetTemplate
// to observe the transition back to "ready".
//
// Returns an HTTP error (status 412) when the template is in a state where
// rebuild is not safe (build in flight) or not supported (ready_no_snapshot,
// failed — those need delete+recreate today).
func (c *Client) RebuildTemplate(ctx context.Context, id string) (sdktypes.Template, error) {
	return c.inner.RebuildTemplate(ctx, id)
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

// DNSTarget returns the cluster-published ingress target — the hostname
// and/or IP set that custom-domain DNS records must point at. Source
// disambiguates the shape ("hostname" / "ips" / "mixed" / "unknown"), so
// callers don't have to inspect which fields are populated to know whether
// to render a CNAME or A/AAAA setup hint.
func (c *Client) DNSTarget(ctx context.Context) (sdktypes.IngressTarget, error) {
	return c.inner.DNSTarget(ctx)
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

// CustomDomainOption customizes an AddCustomDomain call. Build values with
// WithTargetPort; the variadic shape leaves room for future expansion.
type CustomDomainOption func(*customDomainOptions)

type customDomainOptions struct {
	targetPort int
}

// WithTargetPort routes the custom hostname to the given in-container TCP
// port instead of the default toolbox agent. Set once at attach time;
// changing the port for an already-attached hostname requires
// RemoveCustomDomain + AddCustomDomain so in-flight traffic can't silently
// redirect. Re-adding the same hostname with a different port returns 409.
func WithTargetPort(port int) CustomDomainOption {
	return func(o *customDomainOptions) { o.targetPort = port }
}

// AddCustomDomain attaches a public hostname (e.g. "api.acme.com") to this
// sandbox. The server lowercases / trims and validates the hostname; the
// returned slice is the full per-hostname row list, so callers can read the
// canonical form and initial status without a follow-up GET.
//
// 412 Precondition Failed surfaces when the deployment is in IP mode or the
// custom-domain feature is disabled. 409 Conflict surfaces when the hostname
// is already attached to a different sandbox, the sandbox has any
// tcp/tls-protocol exposed port (the IRON RULE: SNI cannot route per host on
// a shared L4 listener), or the re-add target_port differs from the stored
// value. 400 Bad Request surfaces when target_port is outside [0, 65535].
func (s *Sandbox) AddCustomDomain(ctx context.Context, hostname string, opts ...CustomDomainOption) ([]sdktypes.CustomDomain, error) {
	cfg := customDomainOptions{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return s.client.inner.AddCustomDomain(ctx, s.ID, hostname, cfg.targetPort)
}

// RemoveCustomDomain detaches a hostname previously attached via
// AddCustomDomain or CreateSandboxOptions.CustomDomains. Case-insensitive;
// the server normalizes before comparing.
func (s *Sandbox) RemoveCustomDomain(ctx context.Context, hostname string) error {
	return s.client.inner.RemoveCustomDomain(ctx, s.ID, hostname)
}

// ListCustomDomains returns the per-hostname rows currently attached to the
// sandbox. Use this to poll Status (pending_dns → issuing → ready/failed)
// after AddCustomDomain.
func (s *Sandbox) ListCustomDomains(ctx context.Context) ([]sdktypes.CustomDomain, error) {
	return s.client.inner.ListCustomDomains(ctx, s.ID)
}

// CustomDomainDNS returns the ready-to-paste DNS records the user must add at
// their provider for every custom domain on this sandbox to reach the
// cluster, plus the raw ingress target the records were derived from. One
// row per (hostname × ingress address); branch on Target.Source to render a
// "CNAME vs A/AAAA" hint.
func (s *Sandbox) CustomDomainDNS(ctx context.Context) (sdktypes.CustomDomainDNSRecords, error) {
	return s.client.inner.CustomDomainDNS(ctx, s.ID)
}

func (s *Sandbox) CreateSnapshot(ctx context.Context, name string) (sdktypes.SandboxSnapshot, error) {
	return s.client.CreateSnapshot(ctx, s.ID, name)
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

func (s *Sandbox) GetNetworkUsage(ctx context.Context) (sdktypes.NetworkUsage, error) {
	return s.client.GetNetworkUsage(ctx, s.ID)
}

func (s *Sandbox) SetNetworkLimits(ctx context.Context, opts sdktypes.SetNetworkLimitsOptions) (sdktypes.NetworkUsage, error) {
	return s.client.SetNetworkLimits(ctx, s.ID, opts)
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
