package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const defaultAOCRRegistryHost = "aocr.aerol.ai"

// ImageDistributionProvider is the control-plane contract for image
// availability. Providers may verify digests or talk to an external registry
// cache, but the core daemon only needs the resulting placement metadata.
type ImageDistributionProvider interface {
	ClassifyImage(ctx context.Context, image string) (models.ImageDistributionMetadata, error)
}

type defaultImageDistributionProvider struct {
	aocrHost string
}

func newDefaultImageDistributionProvider(aocrHost string) ImageDistributionProvider {
	aocrHost = strings.ToLower(strings.TrimSpace(aocrHost))
	if aocrHost == "" {
		aocrHost = defaultAOCRRegistryHost
	}
	return defaultImageDistributionProvider{aocrHost: aocrHost}
}

func (p defaultImageDistributionProvider) ClassifyImage(_ context.Context, image string) (models.ImageDistributionMetadata, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return models.ImageDistributionMetadata{}, nil
	}
	if docker.IsLocalOnlyImageRef(image) {
		return models.ImageDistributionMetadata{
			Mode: models.ImageDistributionLocalOnly,
		}, nil
	}
	if host := imageRegistryHost(image); host != "" && host == p.aocrHost {
		return models.ImageDistributionMetadata{
			Mode:        models.ImageDistributionAOCR,
			RegistryRef: image,
		}, nil
	}
	return models.ImageDistributionMetadata{
		Mode:        models.ImageDistributionExternalRegistry,
		RegistryRef: image,
	}, nil
}

// NormalizeCreateImageDistribution resolves snapshot aliases and fills the
// create request's image-distribution metadata before placement decisions are
// made. The method is intentionally side-effect free: it does not pull, push,
// or verify image contents.
func (s *Service) NormalizeCreateImageDistribution(ctx context.Context, req *models.CreateSandboxRequest) error {
	if req == nil {
		return nil
	}
	req.Image = strings.TrimSpace(req.Image)

	if s != nil && s.store != nil && req.Image != "" {
		if snapshot, err := s.store.GetSnapshot(ctx, req.Image); err == nil && snapshot != nil {
			if image := strings.TrimSpace(snapshot.Image); image != "" {
				req.Image = image
			}
			if req.ImageDistribution().IsZero() {
				req.ApplyImageDistribution(snapshot.ImageDistribution())
			}
		}
	}

	meta := req.ImageDistribution()
	if meta.IsZero() {
		classified, err := s.imageDistributionProvider().ClassifyImage(ctx, req.Image)
		if err != nil {
			return err
		}
		meta = classified
	}
	normalized, err := normalizeImageDistributionMetadata(req.Image, meta)
	if err != nil {
		return err
	}
	req.ApplyImageDistribution(normalized)
	return nil
}

func (s *Service) normalizeSnapshotImageDistribution(ctx context.Context, snapshot *models.SandboxSnapshot, forceLocal bool) error {
	if snapshot == nil {
		return nil
	}
	snapshot.Image = strings.TrimSpace(snapshot.Image)
	meta := snapshot.ImageDistribution()
	if forceLocal {
		meta.Mode = models.ImageDistributionLocalOnly
		meta.RegistryRef = ""
	}
	if meta.IsZero() {
		classified, err := s.imageDistributionProvider().ClassifyImage(ctx, snapshot.Image)
		if err != nil {
			return err
		}
		meta = classified
	}
	normalized, err := normalizeImageDistributionMetadata(snapshot.Image, meta)
	if err != nil {
		return err
	}
	snapshot.ApplyImageDistribution(normalized)
	return nil
}

func (s *Service) imageDistributionProvider() ImageDistributionProvider {
	if s != nil && s.images != nil {
		return s.images
	}
	return newDefaultImageDistributionProvider("")
}

func normalizeImageDistributionMetadata(image string, meta models.ImageDistributionMetadata) (models.ImageDistributionMetadata, error) {
	mode, err := models.NormalizeImageDistributionMode(meta.Mode)
	if err != nil {
		return models.ImageDistributionMetadata{}, err
	}
	meta.Mode = mode
	meta.Digest = strings.TrimSpace(meta.Digest)
	meta.RegistryRef = strings.TrimSpace(meta.RegistryRef)
	if meta.Mode == "" && strings.TrimSpace(image) != "" {
		meta.Mode = models.ImageDistributionExternalRegistry
	}
	if (meta.Mode == models.ImageDistributionExternalRegistry || meta.Mode == models.ImageDistributionAOCR) && meta.RegistryRef == "" {
		meta.RegistryRef = strings.TrimSpace(image)
	}
	return meta, nil
}

func ImageRequiresLocalPlacement(req models.CreateSandboxRequest) bool {
	return req.ImageDistributionMode == models.ImageDistributionLocalOnly || docker.IsLocalOnlyImageRef(req.Image)
}

func imageRegistryHost(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	if _, after, ok := strings.Cut(image, "://"); ok {
		image = after
	}
	first, _, ok := strings.Cut(image, "/")
	if !ok {
		return ""
	}
	first = strings.ToLower(strings.TrimSpace(first))
	if first == "localhost" || strings.Contains(first, ".") || strings.Contains(first, ":") {
		return first
	}
	return ""
}
