package containerd

import (
	"context"

	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func namespaced(ctx context.Context, ns string) context.Context {
	return namespaces.WithNamespace(ctx, ns)
}

// NewTestClient wires a fake or stub transport for unit tests.
func NewTestClient(namespace string, tr clientTransport) *Client {
	return &Client{namespace: namespace, tr: tr}
}
