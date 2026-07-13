package containerd

import (
	"context"
	"encoding/json"
	"fmt"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func imageDefaultCommand(ctx context.Context, client *Client, image cntr.Image) ([]string, error) {
	if client == nil || client.contentProvider() == nil {
		return nil, fmt.Errorf("content store unavailable")
	}
	return imageConfigCommand(ctx, client.contentProvider(), image)
}

func imageConfigCommand(ctx context.Context, provider content.Provider, image cntr.Image) ([]string, error) {
	desc, err := image.Config(ctx)
	if err != nil {
		return nil, err
	}
	cfgDesc, err := images.Config(ctx, provider, desc, nil)
	if err != nil {
		return nil, err
	}
	ra, err := provider.ReaderAt(ctx, cfgDesc)
	if err != nil {
		return nil, err
	}
	defer ra.Close()
	var cfg ocispec.Image
	if err := json.NewDecoder(content.NewReader(ra)).Decode(&cfg); err != nil {
		return nil, err
	}
	return append(append([]string{}, cfg.Config.Entrypoint...), cfg.Config.Cmd...), nil
}
