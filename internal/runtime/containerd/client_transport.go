package containerd

import (
	"context"
	"errors"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/events"
)

// clientTransport is the containerd API subset the driver exercises. Production
// uses liveTransport; tests inject fakeTransport (poolFakeDaemon analogue).
type clientTransport interface {
	close() error
	isServing(ctx context.Context) (bool, error)
	loadContainer(ctx context.Context, id string) (cntr.Container, error)
	newContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error)
	getImage(ctx context.Context, ref string) (cntr.Image, error)
	pullImage(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error)
	listContainers(ctx context.Context, filters ...string) ([]cntr.Container, error)
	subscribe(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error)
	contentStore() content.Store
	contentProvider() content.Provider
}

// rawAPI is the containerd client surface liveTransport delegates to. Exposed
// as an interface so unit tests can exercise liveTransport without a socket.
type rawAPI interface {
	Close() error
	IsServing(ctx context.Context) (bool, error)
	LoadContainer(ctx context.Context, id string) (cntr.Container, error)
	NewContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error)
	GetImage(ctx context.Context, ref string) (cntr.Image, error)
	Pull(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error)
	Containers(ctx context.Context, filters ...string) ([]cntr.Container, error)
	Subscribe(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error)
	ContentStore() content.Store
	ContentProvider() content.Provider
	Version(ctx context.Context) (cntr.Version, error)
}

// cntrClientRaw adapts *cntr.Client to rawAPI (flattening EventService.Subscribe).
type cntrClientRaw struct{ *cntr.Client }

func (c cntrClientRaw) Subscribe(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error) {
	if c.Client == nil {
		ch := make(chan *events.Envelope)
		errCh := make(chan error, 1)
		close(ch)
		errCh <- errors.New("containerd client is nil")
		return ch, errCh
	}
	return c.Client.EventService().Subscribe(ctx, filters...)
}

func (c cntrClientRaw) ContentProvider() content.Provider {
	if c.Client == nil {
		return nil
	}
	return c.ContentStore()
}

func (c cntrClientRaw) Version(ctx context.Context) (cntr.Version, error) {
	if c.Client == nil {
		return cntr.Version{}, errors.New("containerd client is nil")
	}
	return c.Client.Version(ctx)
}

type liveTransport struct {
	raw rawAPI
	ns  string
}

func (t *liveTransport) close() error {
	if t == nil || t.raw == nil {
		return nil
	}
	return t.raw.Close()
}

func (t *liveTransport) isServing(ctx context.Context) (bool, error) {
	return t.raw.IsServing(namespaced(ctx, t.ns))
}

func (t *liveTransport) loadContainer(ctx context.Context, id string) (cntr.Container, error) {
	return t.raw.LoadContainer(namespaced(ctx, t.ns), id)
}

func (t *liveTransport) newContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	return t.raw.NewContainer(namespaced(ctx, t.ns), id, opts...)
}

func (t *liveTransport) getImage(ctx context.Context, ref string) (cntr.Image, error) {
	return t.raw.GetImage(namespaced(ctx, t.ns), ref)
}

func (t *liveTransport) pullImage(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
	return t.raw.Pull(namespaced(ctx, t.ns), ref, opts...)
}

func (t *liveTransport) listContainers(ctx context.Context, filters ...string) ([]cntr.Container, error) {
	return t.raw.Containers(namespaced(ctx, t.ns), filters...)
}

func (t *liveTransport) subscribe(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error) {
	return t.raw.Subscribe(namespaced(ctx, t.ns), filters...)
}

func (t *liveTransport) contentStore() content.Store {
	return t.raw.ContentStore()
}

func (t *liveTransport) contentProvider() content.Provider {
	return t.raw.ContentProvider()
}
