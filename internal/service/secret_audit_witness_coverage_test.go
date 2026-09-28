package service

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestSecretAuditWitnessAndTipPaths(t *testing.T) {
	if (*Service)(nil).secretAuditWitnessPath() != "" || (*Service)(nil).secretAuditWitnessTipPath() != "" {
		t.Fatal("nil service leaked audit paths")
	}
	if (&Service{}).secretAuditWitnessPath() != "" || (&Service{}).secretAuditWitnessTipPath() != "" {
		t.Fatal("fileless service leaked audit paths")
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if svc.secretAuditWitnessPath() == "" || svc.secretAuditWitnessTipPath() == "" {
		t.Fatal("initialized sink must expose witness/tip sidecar paths")
	}
	if !strings.HasSuffix(svc.secretAuditWitnessPath(), secretAuditWitnessReceiptFile) {
		t.Fatalf("witness path = %q", svc.secretAuditWitnessPath())
	}
	if !strings.HasSuffix(svc.secretAuditWitnessTipPath(), secretAuditWitnessTipFile) {
		t.Fatalf("tip path = %q", svc.secretAuditWitnessTipPath())
	}
}
