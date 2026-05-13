package service

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) UpsertDaytonaMetadata(ctx context.Context, meta models.DaytonaSandboxMetadata) error {
	return s.store.UpsertDaytonaMetadata(ctx, meta)
}

func (s *Service) GetDaytonaMetadata(ctx context.Context, sandboxID string) (*models.DaytonaSandboxMetadata, error) {
	return s.store.GetDaytonaMetadata(ctx, sandboxID)
}

func (s *Service) ListDaytonaMetadata(ctx context.Context) (map[string]models.DaytonaSandboxMetadata, error) {
	return s.store.ListDaytonaMetadata(ctx)
}

func (s *Service) ResolveDaytonaSandboxID(ctx context.Context, name string) (string, error) {
	return s.store.ResolveDaytonaSandboxID(ctx, name)
}
