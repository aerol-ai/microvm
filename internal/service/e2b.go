package service

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) UpsertE2BSandboxMetadata(ctx context.Context, meta models.E2BSandboxMetadata) error {
	return s.store.UpsertE2BSandboxMetadata(ctx, meta)
}

func (s *Service) GetE2BSandboxMetadata(ctx context.Context, sandboxID string) (*models.E2BSandboxMetadata, error) {
	return s.store.GetE2BSandboxMetadata(ctx, sandboxID)
}

func (s *Service) ListE2BSandboxMetadata(ctx context.Context) (map[string]models.E2BSandboxMetadata, error) {
	return s.store.ListE2BSandboxMetadata(ctx)
}

func (s *Service) UpsertE2BSnapshot(ctx context.Context, meta models.E2BSnapshotMetadata) error {
	return s.store.UpsertE2BSnapshot(ctx, meta)
}

func (s *Service) GetE2BSnapshot(ctx context.Context, snapshotID string) (*models.E2BSnapshotMetadata, error) {
	return s.store.GetE2BSnapshot(ctx, snapshotID)
}

func (s *Service) ListE2BSnapshots(ctx context.Context) (map[string]models.E2BSnapshotMetadata, error) {
	return s.store.ListE2BSnapshots(ctx)
}

func (s *Service) DeleteE2BSnapshot(ctx context.Context, snapshotID string) error {
	return s.store.DeleteE2BSnapshot(ctx, snapshotID)
}
