package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestEnsureToolboxBinaryErrors(t *testing.T) {
	d := New(Config{}, nil, nil)
	if err := d.ensureToolboxBinary(); err == nil || !strings.Contains(err.Error(), "SB_TOOLBOX_BINARY_PATH") {
		t.Fatalf("err=%v", err)
	}
	d.cfg.ToolboxBinaryPath = filepath.Join(t.TempDir(), "missing")
	if err := d.ensureToolboxBinary(); err == nil || !strings.Contains(err.Error(), "toolbox binary") {
		t.Fatalf("err=%v", err)
	}
}

func TestTaskLogPathEmptyDir(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.taskLogPath("sb"); err == nil {
		t.Fatal("want log dir error")
	}
}

func TestSetupReadySocketOK(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDir(t)
	env := []string{"A=1"}
	var mounts []specs.Mount
	rl, err := d.setupReadySocket(&env, &mounts, "sb1", "tok")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rl.Close() })
	if len(env) < 2 {
		t.Fatalf("env=%v", env)
	}
	if len(mounts) != 1 {
		t.Fatalf("mounts=%v", mounts)
	}
}

func TestSetupReadySocketBadDir(t *testing.T) {
	d := newTestDriver(t)
	// ReadyDir points at a file so EnsureReadyDir/mkdir fails.
	bad := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.cfg.ReadyDir = bad
	env := []string{}
	var mounts []specs.Mount
	if _, err := d.setupReadySocket(&env, &mounts, "sb1", "tok"); err == nil {
		t.Fatal("want ready dir error")
	}
}

func TestPinImageLeaseAddResourceFails(t *testing.T) {
	lm := &fakeLeaseManager{addErr: errors.New("add failed")}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	d := newTestDriver(t)
	img := &fakeImage{
		name:   "alpine:3.20",
		target: ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("f", 64))},
	}
	_, err := d.pinImageLease(context.Background(), d.client, img)
	if err == nil || !strings.Contains(err.Error(), "pin image lease") {
		t.Fatalf("err=%v", err)
	}
	if len(lm.deleted) != 1 {
		t.Fatalf("lease should roll back: %v", lm.deleted)
	}
}

func TestApplyAdoptNetworkPolicyEgressFail(t *testing.T) {
	be := &netrulesFailInsertBackend{}
	d := New(Config{}, netrules.NewWithBackend(be), nil)
	err := d.applyAdoptNetworkPolicy("10.88.0.9", models.CreateSandboxRequest{
		NetworkAllowOut: []string{"1.2.3.0/24"},
	})
	if err == nil {
		t.Fatal("want egress policy error")
	}
}

type netrulesFailInsertBackend struct{ netrulesMemBackend }

func (m *netrulesFailInsertBackend) Insert(string, string, int, ...string) error {
	return errors.New("insert failed")
}
