package containerd

import (
	"context"
	"fmt"
	"strings"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	managedLabelKey   = "aerolvm.managed"
	sandboxIDLabelKey = "aerolvm.sandbox_id"
)

// Client wraps a namespaced containerd connection.
type Client struct {
	namespace string
	tr        clientTransport
	raw       *cntr.Client // set only for live clients; Raw() uses this
}

// connectDialFn dials containerd; tests inject a stub rawAPI to avoid a live socket.
var connectDialFn = func(socket, namespace string) (rawAPI, error) {
	raw, err := cntr.New(socket, cntr.WithDefaultNamespace(namespace))
	if err != nil {
		return nil, err
	}
	return cntrClientRaw{raw}, nil
}

// Connect dials the system containerd socket and scopes to namespace.
func Connect(socket, namespace string) (*Client, error) {
	socket = strings.TrimSpace(socket)
	if socket == "" {
		return nil, fmt.Errorf("containerd socket path is required")
	}
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		return nil, fmt.Errorf("containerd namespace is required")
	}
	raw, err := connectDialFn(socket, ns)
	if err != nil {
		return nil, fmt.Errorf("dial containerd: %w", err)
	}
	ver, verr := raw.Version(context.Background())
	if verr != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("containerd version: %w", verr)
	}
	if err := assertSupportedContainerdVersion(ver.Version); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if cc, ok := raw.(cntrClientRaw); ok && cc.Client != nil {
		return &Client{raw: cc.Client, namespace: ns, tr: &liveTransport{raw: raw, ns: ns}}, nil
	}
	return &Client{namespace: ns, tr: &liveTransport{raw: raw, ns: ns}}, nil
}

func (c *Client) Close() error {
	if c == nil || c.tr == nil {
		return nil
	}
	return c.tr.close()
}

func (c *Client) withNS(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, c.namespace)
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.tr == nil {
		return fmt.Errorf("containerd client is nil")
	}
	_, err := c.tr.isServing(ctx)
	return err
}

func (c *Client) Raw() *cntr.Client {
	if c == nil {
		return nil
	}
	return c.raw
}

func (c *Client) Namespace() string {
	if c == nil {
		return ""
	}
	return c.namespace
}

func (c *Client) LoadContainer(ctx context.Context, id string) (cntr.Container, error) {
	return c.tr.loadContainer(c.withNS(ctx), id)
}

func (c *Client) NewContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	return c.tr.newContainer(c.withNS(ctx), id, opts...)
}

func (c *Client) GetImage(ctx context.Context, ref string) (cntr.Image, error) {
	return c.tr.getImage(c.withNS(ctx), ref)
}

func (c *Client) PullImage(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
	return c.tr.pullImage(c.withNS(ctx), ref, opts...)
}

func (c *Client) ListContainers(ctx context.Context, filters ...string) ([]cntr.Container, error) {
	return c.tr.listContainers(c.withNS(ctx), filters...)
}

func (c *Client) SubscribeEvents(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error) {
	return c.tr.subscribe(c.withNS(ctx), filters...)
}

// ContentStore exposes the backing content store for image config reads.
func (c *Client) ContentStore() content.Store {
	if c == nil || c.tr == nil {
		return nil
	}
	return c.tr.contentStore()
}

func (c *Client) contentProvider() content.Provider {
	if c == nil || c.tr == nil {
		return nil
	}
	return c.tr.contentProvider()
}
