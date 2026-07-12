package containerd

import (
	"context"
	"fmt"
	"strings"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/namespaces"
)

const managedLabelKey = "aerolvm.managed"

// Client wraps a namespaced containerd connection.
type Client struct {
	raw       *cntr.Client
	namespace string
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
	// Set the default namespace on the raw client too: methods on the returned
	// cntr.Container/cntr.Task objects (NewTask, task.Start, task.Pids, Delete)
	// do not flow through Client.withNS, so without a default they run with no
	// namespace and fail with "namespace is required".
	raw, err := cntr.New(socket, cntr.WithDefaultNamespace(ns))
	if err != nil {
		return nil, fmt.Errorf("dial containerd: %w", err)
	}
	return &Client{raw: raw, namespace: ns}, nil
}

func (c *Client) Close() error {
	if c == nil || c.raw == nil {
		return nil
	}
	return c.raw.Close()
}

func (c *Client) withNS(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, c.namespace)
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.raw == nil {
		return fmt.Errorf("containerd client is nil")
	}
	_, err := c.raw.IsServing(ctx)
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
	return c.raw.LoadContainer(c.withNS(ctx), id)
}

func (c *Client) NewContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	return c.raw.NewContainer(c.withNS(ctx), id, opts...)
}

func (c *Client) GetImage(ctx context.Context, ref string) (cntr.Image, error) {
	return c.raw.GetImage(c.withNS(ctx), ref)
}

func (c *Client) PullImage(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
	return c.raw.Pull(c.withNS(ctx), ref, opts...)
}

func (c *Client) ListContainers(ctx context.Context, filters ...string) ([]cntr.Container, error) {
	return c.raw.Containers(c.withNS(ctx), filters...)
}

func (c *Client) SubscribeEvents(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error) {
	return c.raw.EventService().Subscribe(c.withNS(ctx), filters...)
}
