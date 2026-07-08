package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (s *Service) releaseAdoptedParkReservation(state *models.SandboxRuntimeState) {
	if s == nil || state == nil || state.AdoptedParkID == "" {
		return
	}
	capacity.ReleaseParkReservation(s.admitter, state.AdoptedParkID)
}

func (s *Service) returnExistingSandboxResponse(ctx context.Context, sandboxID string) (*models.CreateSandboxResponse, bool) {
	existing, err := s.store.Get(ctx, sandboxID)
	if err != nil || existing == nil {
		return nil, false
	}
	return &models.CreateSandboxResponse{Sandbox: *existing}, true
}

func (s *Service) handleDuplicateCreateAfterRuntime(ctx context.Context, sandboxID string, err error) (*models.CreateSandboxResponse, error) {
	if errors.Is(err, docker.ErrSandboxContainerExists) {
		if resp, ok := s.returnExistingSandboxResponse(ctx, sandboxID); ok {
			return resp, nil
		}
		return nil, models.ErrSandboxExists
	}
	return nil, err
}

func (s *Service) handleDuplicateStoreCreate(ctx context.Context, sandboxID string, err error) (*models.CreateSandboxResponse, error) {
	if errors.Is(err, models.ErrSandboxExists) {
		if resp, ok := s.returnExistingSandboxResponse(ctx, sandboxID); ok {
			return resp, nil
		}
		return nil, models.ErrSandboxExists
	}
	return nil, err
}
