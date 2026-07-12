package containerd

import (
	"context"
	"encoding/json"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func imageDefaultCommand(ctx context.Context, client *Client, image cntr.Image) ([]string, error) {
	provider := client.Raw().ContentStore()
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
