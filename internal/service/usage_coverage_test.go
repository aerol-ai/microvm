package service

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestUsageAppendReservedNilWave23(t *testing.T) {
	now := time.Now().UTC()
	_ = appendReservedSamples(nil, nil, now, now.Add(time.Second))
	sb := &models.Sandbox{ID: "x", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 256, DiskGB: 1, OwnerRef: "o", CreatedAt: now}
	_ = appendReservedSamples(nil, sb, now, now.Add(time.Second))
}
