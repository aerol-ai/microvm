package service

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestIdempotencyStateDefaultWave23(t *testing.T) {
	if got := idempotencyState(&models.IdempotentRequestRecord{State: "weird"}); got == "" {
		t.Fatal("expected non-empty")
	}
}
