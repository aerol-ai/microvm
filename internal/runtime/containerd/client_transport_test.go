package containerd

import (
	"context"
	"testing"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/events"
)

func TestLiveTransportCloseNilSafe(t *testing.T) {
	var tr *liveTransport
	if err := tr.close(); err != nil {
		t.Fatal(err)
	}
	if err := (&liveTransport{ns: "aerolvm"}).close(); err != nil {
		t.Fatal(err)
	}
}

// stubRawAPI routes liveTransport calls to fakeTransport for offline coverage.
type stubRawAPI struct{ ft *fakeTransport }

func (s stubRawAPI) Close() error { return s.ft.close() }

func (s stubRawAPI) IsServing(ctx context.Context) (bool, error) { return s.ft.isServing(ctx) }

func (s stubRawAPI) LoadContainer(ctx context.Context, id string) (cntr.Container, error) {
	return s.ft.loadContainer(ctx, id)
}

func (s stubRawAPI) NewContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	return s.ft.newContainer(ctx, id, opts...)
}

func (s stubRawAPI) GetImage(ctx context.Context, ref string) (cntr.Image, error) {
	return s.ft.getImage(ctx, ref)
}

func (s stubRawAPI) Pull(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
	return s.ft.pullImage(ctx, ref, opts...)
}

func (s stubRawAPI) Containers(ctx context.Context, filters ...string) ([]cntr.Container, error) {
	return s.ft.listContainers(ctx, filters...)
}

func (s stubRawAPI) Subscribe(ctx context.Context, filters ...string) (<-chan *events.Envelope, <-chan error) {
	return s.ft.subscribe(ctx, filters...)
}

func (s stubRawAPI) ContentStore() content.Store { return s.ft.contentStore() }

func (s stubRawAPI) ContentProvider() content.Provider { return s.ft.contentProvider() }

func TestLiveTransportDelegatesToStub(t *testing.T) {
	ft := newFakeTransport()
	ft.emitEvents = true
	tr := &liveTransport{raw: stubRawAPI{ft: ft}, ns: "aerolvm"}
	ctx := context.Background()

	if err := tr.close(); err != nil {
		t.Fatal(err)
	}
	if serving, err := tr.isServing(ctx); err != nil || !serving {
		t.Fatalf("serving=%v err=%v", serving, err)
	}
	if _, err := tr.newContainer(ctx, "sb-live"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.loadContainer(ctx, "sb-live"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.getImage(ctx, "alpine:3.20"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.pullImage(ctx, "alpine:3.20"); err != nil {
		t.Fatal(err)
	}
	list, err := tr.listContainers(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%d err=%v", len(list), err)
	}
	ch, errCh := tr.subscribe(ctx)
	if ch == nil || errCh == nil {
		t.Fatal("subscribe channels nil")
	}
	if tr.contentStore() != nil {
		t.Fatal("fake content store should be nil")
	}
	if tr.contentProvider() != nil {
		t.Fatal("fake content provider should be nil without provider")
	}
	provider, _ := newTestImageProvider(t)
	ft.provider = provider
	tr2 := &liveTransport{raw: stubRawAPI{ft: ft}, ns: "aerolvm"}
	if tr2.contentProvider() == nil {
		t.Fatal("expected content provider")
	}

	// Wire through Client so Ping exercises liveTransport.isServing.
	c := &Client{namespace: "aerolvm", tr: tr}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}
