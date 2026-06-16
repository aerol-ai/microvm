package service

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// UC-78 (offline): foreign-arch AOCR snapshot refs are rejected at resume time.
func TestUC78_ForeignArchSnapshotRefRejected(t *testing.T) {
	host := hostSnapshotArch()
	foreign := snapshotArchAMD64
	if host == snapshotArchAMD64 {
		foreign = snapshotArchARM64
	}
	foreignRef := "aocr.test/cluster/cluster-42/snapshots/snap:latest--arch-" + foreign

	svc := &Service{
		images: newDefaultImageDistributionProvider("aocr.test"),
	}

	req := &models.CreateSandboxRequest{Image: foreignRef}
	req.ApplyImageDistribution(models.ImageDistributionMetadata{
		Mode:        models.ImageDistributionAOCR,
		RegistryRef: foreignRef,
	})
	err := svc.NormalizeCreateImageDistribution(context.Background(), req)
	if err == nil {
		t.Fatal("expected foreign-arch snapshot ref to be rejected")
	}
	if !strings.Contains(err.Error(), "does not match host architecture") {
		t.Fatalf("error = %v, want arch mismatch", err)
	}
}

func TestUC78_UntaggedAMD64RefStillResolvesOnAMD64Host(t *testing.T) {
	if hostSnapshotArch() != snapshotArchAMD64 {
		t.Skip("amd64 back-compat applies on amd64 hosts only")
	}
	legacyRef := "aocr.test/cluster/cluster-42/snapshots/snap:latest"
	if err := ValidateSnapshotRefArch(legacyRef, snapshotArchAMD64); err != nil {
		t.Fatalf("legacy untagged ref should resolve on amd64: %v", err)
	}
}

func TestUC78_ForeignArchTemplateRefRejectedOnPull(t *testing.T) {
	host := hostSnapshotArch()
	foreign := snapshotArchAMD64
	if host == snapshotArchAMD64 {
		foreign = snapshotArchARM64
	}
	foreignRef := "aocr.test/cluster/cluster-42/templates/tpl-1:latest--arch-" + foreign

	svc := &Service{
		templateArtifactPuller: &TemplateArtifactPuller{templatesDir: t.TempDir()},
	}
	err := svc.EnsureTemplateLocal(context.Background(), &models.Template{
		ID:          "tpl-1",
		RegistryRef: foreignRef,
	})
	if err == nil {
		t.Fatal("expected foreign-arch template ref to be rejected")
	}
	if !strings.Contains(err.Error(), "does not match host architecture") {
		t.Fatalf("error = %v, want arch mismatch", err)
	}
}
