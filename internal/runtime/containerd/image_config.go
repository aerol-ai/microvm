package containerd

import (
	"context"
	"encoding/json"
	"fmt"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func imageDefaultCommand(ctx context.Context, client *Client, image cntr.Image) ([]string, error) {
	if client == nil || client.contentProvider() == nil {
		return nil, fmt.Errorf("content store unavailable")
	}
	return imageConfigCommand(ctx, client.contentProvider(), image)
}

func imageConfigCommand(ctx context.Context, provider content.Provider, image cntr.Image) ([]string, error) {
	cfg, err := readImageConfig(ctx, provider, image)
	if err != nil {
		return nil, err
	}
	return append(append([]string{}, cfg.Config.Entrypoint...), cfg.Config.Cmd...), nil
}

// imageUser is the image's USER, the user oci.WithImageConfig runs the
// container as: the create policy's require_non_root rule reads it.
func imageUser(ctx context.Context, client *Client, image cntr.Image) (string, error) {
	if client == nil || client.contentProvider() == nil {
		return "", fmt.Errorf("content store unavailable")
	}
	cfg, err := readImageConfig(ctx, client.contentProvider(), image)
	if err != nil {
		return "", err
	}
	return cfg.Config.User, nil
}

func readImageConfig(ctx context.Context, provider content.Provider, image cntr.Image) (ocispec.Image, error) {
	// Image.Config returns the config descriptor directly — containerd already
	// resolves index→manifest→config for the client platform. Read it straight
	// from the content store. Do NOT feed it back through images.Config, which
	// expects a manifest/index and fails with "unexpected media type
	// application/vnd.oci.image.config.v1+json" on the config descriptor.
	var cfg ocispec.Image
	cfgDesc, err := image.Config(ctx)
	if err != nil {
		return cfg, err
	}
	ra, err := provider.ReaderAt(ctx, cfgDesc)
	if err != nil {
		return cfg, err
	}
	defer ra.Close()
	if err := json.NewDecoder(content.NewReader(ra)).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
