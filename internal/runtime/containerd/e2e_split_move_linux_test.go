//go:build linux

package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootclient"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// helperNetns is the netns pool's build and teardown as one helper call
// each, for a live run with no store.
type helperNetns struct{ c *rootclient.Client }

func (h helperNetns) Provision(ctx context.Context, id string) (string, string, error) {
	return h.c.RealizeNetns(ctx, id)
}
func (h helperNetns) Release(ctx context.Context, id string) error {
	return h.c.RemoveNetns(ctx, id, "")
}
func (helperNetns) ReassignOwner(context.Context, string, string) error { return nil }

// toolboxExec runs command in the sandbox at ip through its toolbox.
func toolboxExec(ctx context.Context, ip, token, command string) (string, error) {
	body, _ := json.Marshal(map[string]any{"command": command, "timeout_seconds": 30})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s:2280/process/execute", ip), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("status %d: %w", resp.StatusCode, err)
	}
	if out.ExitCode != 0 {
		return "", fmt.Errorf("exit %d: %s", out.ExitCode, out.Stderr)
	}
	return strings.TrimSpace(out.Stdout), nil
}

// TestE2ESplitGvisorMove (M1 PR 13) moves a running gVisor sandbox with its
// memory through a live root helper, as sandboxd with no rights does in
// privilege mode split: a real containerd behind the helper's gate, real
// runsc, the agent's real client (AEROL_E2E_HELPER_SOCKET and
// AEROL_E2E_GVISOR_MOVE=1; the box runs it as the agent's uid). The
// sandbox writes a file in its own memory-backed root; the move's stop has
// the helper checkpoint it; the export and the import pass the bundle
// through the helper; the source goes; the restore's create brings it
// back, and the file is still there.
func TestE2ESplitGvisorMove(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" || os.Getenv("AEROL_E2E_GVISOR_MOVE") == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_GVISOR_MOVE")
	}
	client := rootclient.New(rootclient.Config{Socket: sock, HelperUID: 0})
	t.Cleanup(func() { _ = client.Close() })
	cfg := Config{
		Namespace: "aerolvm", ToolboxBinaryPath: os.Getenv("AEROL_E2E_TOOLBOX"), ToolboxMountPath: "/.aerol/toolboxd", ToolboxPort: 2280,
		WaitTimeout: 2 * time.Minute, ToolboxWaitTimeout: 2 * time.Minute, ReadyEnabled: true, ReadyDir: "/run/sandboxd/docker/ready",
		ReadinessPollInit: 50 * time.Millisecond, ReadinessPollMax: 500 * time.Millisecond, HTTPClientTimeout: 10 * time.Second,
		LogDir: "/var/lib/sandboxd/containerd/logs", RunDir: "/var/lib/sandboxd/containerd", NativeNetnsPool: true,
		DefaultRuntime: models.RuntimeGvisor, PidsLimit: 4096, PullMaxConcurrent: 2,
	}
	d := New(cfg, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	d.SetRootHelper(client)
	d.SetMoveHelper(client)
	d.SetNetnsHandoff(helperNetns{client})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	const id, token = "sb-e2e-move", "e2e-move-token-0123456789abcdef"
	req := models.CreateSandboxRequest{Image: "docker.io/library/alpine:3.20", Runtime: models.RuntimeGvisor, ContainerCommand: []string{"sleep", "inf"},
		CPU: 1, MemoryMB: 512}
	_ = d.Destroy(ctx, &models.Sandbox{ID: id, Runtime: models.RuntimeGvisor})

	start := time.Now()
	state, err := d.Create(ctx, req, id, token, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("created %s at %s in %v", id, state.ContainerIP, time.Since(start).Round(time.Millisecond))
	mark := fmt.Sprintf("moved-%d", time.Now().UnixNano())
	if out, err := toolboxExec(ctx, state.ContainerIP, token, "echo "+mark+" > /tmp/state && cat /tmp/state"); err != nil || out != mark {
		t.Fatalf("write the state: %q %v", out, err)
	}

	start = time.Now()
	if err := d.Stop(sbruntime.WithCheckpoint(ctx), id); err != nil {
		t.Fatalf("checkpoint stop: %v", err)
	}
	t.Logf("checkpointed through the helper in %v", time.Since(start).Round(time.Millisecond))
	var bundle bytes.Buffer
	if err := d.ExportSandboxSnapshot(ctx, id, &bundle); err != nil {
		t.Fatalf("export: %v", err)
	}
	t.Logf("exported a bundle of %d bytes", bundle.Len())
	if err := d.Destroy(ctx, &models.Sandbox{ID: id, Runtime: models.RuntimeGvisor, ContainerID: id, ContainerIP: state.ContainerIP}); err != nil {
		t.Fatalf("destroy the source: %v", err)
	}
	if err := d.ImportSandboxSnapshot(ctx, id, bytes.NewReader(bundle.Bytes())); err != nil {
		t.Fatalf("import: %v", err)
	}
	if path, err := client.StagedMove(ctx, id); err != nil || path == "" {
		t.Fatalf("staged: %q %v", path, err)
	}

	start = time.Now()
	restored, err := d.Create(sbruntime.WithRestore(ctx), req, id, token, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	t.Logf("restored at %s in %v", restored.ContainerIP, time.Since(start).Round(time.Millisecond))
	out, err := toolboxExec(ctx, restored.ContainerIP, token, "cat /tmp/state")
	if err != nil || out != mark {
		t.Fatalf("after the move the state is %q (%v), want %q", out, err, mark)
	}
	if path, err := client.StagedMove(ctx, id); err != nil || path != "" {
		t.Fatalf("the used checkpoint stayed: %q %v", path, err)
	}
	t.Logf("the state survived the move: %s", out)
	if err := d.Destroy(ctx, &models.Sandbox{ID: id, Runtime: models.RuntimeGvisor, ContainerID: id, ContainerIP: restored.ContainerIP}); err != nil {
		t.Fatalf("destroy: %v", err)
	}
}
