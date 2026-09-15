package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/observability"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"go.opentelemetry.io/otel/attribute"
)

// WasmMigrateRequest is the operator body for POST /v1/cluster/wasm-migrate.
type WasmMigrateRequest struct {
	SandboxID    string `json:"sandbox_id"`
	TargetNodeID string `json:"target_node_id"`
}

// WasmMigrateResponse summarizes a completed cross-node handoff.
type WasmMigrateResponse struct {
	SandboxID       string `json:"sandbox_id"`
	SourceNodeID    string `json:"source_node_id"`
	TargetNodeID    string `json:"target_node_id"`
	CloneGeneration string `json:"clone_generation"`
	CheckpointPath  string `json:"checkpoint_path"`
}

// MigrateWasmSandbox packages a boundary checkpoint for handoff to a sibling node.
func (s *Service) MigrateWasmSandbox(ctx context.Context, sandboxID, destDir string) (string, string, error) {
	if s.wasm == nil {
		return "", "", fmt.Errorf("wasm runtime not configured")
	}
	host, ok := s.wasm.(wasmruntime.MigrationHost)
	if !ok {
		return "", "", fmt.Errorf("wasm runtime does not implement migration")
	}
	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return "", "", err
	}
	if !s.isWasmSandbox(sandbox) {
		return "", "", fmt.Errorf("sandbox %s is not wasm runtime", sandboxID)
	}
	return host.MigrateSandbox(ctx, sandbox, destDir)
}

// ExportWasmMigration streams a §4.8.1 mem.snap tarball for sandboxID.
func (s *Service) ExportWasmMigration(ctx context.Context, sandboxID string, w io.Writer) (cloneGen string, err error) {
	ctx, span := observability.StartSpan(ctx, "wasm.migrate.export",
		attribute.String("sandbox.id", sandboxID),
	)
	defer func() { observability.EndSpan(span, err) }()

	if s.wasm == nil || !s.cfg.EnableWasm {
		return "", fmt.Errorf("wasm runtime not configured")
	}
	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return "", err
	}
	if !s.isWasmSandbox(sandbox) {
		return "", fmt.Errorf("sandbox %s is not wasm runtime", sandboxID)
	}
	tmpDir, err := os.MkdirTemp("", "wasm-migrate-export-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	memSnapDir, cloneGen, err := s.MigrateWasmSandbox(ctx, sandboxID, tmpDir)
	if err != nil {
		return "", err
	}
	if err := writeWasmCheckpointTar(w, memSnapDir); err != nil {
		return "", err
	}
	return cloneGen, nil
}

// ImportWasmMigration accepts a streamed mem.snap tarball on the receiving node,
// promotes the sandbox row to passivated, and reassigns cluster ownership to self.
func (s *Service) ImportWasmMigration(ctx context.Context, sandboxID, expectedCloneGen string, r io.Reader) (err error) {
	ctx, span := observability.StartSpan(ctx, "wasm.migrate.import",
		attribute.String("sandbox.id", sandboxID),
	)
	defer func() { observability.EndSpan(span, err) }()

	if !s.cfg.EnableWasm {
		return fmt.Errorf("wasm runtime disabled")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return fmt.Errorf("sandbox id required")
	}
	checkpointPath := wasmCheckpointDir(s.cfg.WasmModulesDir, sandboxID)
	if err := extractWasmCheckpointTar(r, checkpointPath); err != nil {
		return err
	}
	snap, err := wasmengine.ReadSnapshotDir(checkpointPath, wasmengine.EngineNameWazero())
	if err != nil {
		return err
	}
	cloneGen := strings.TrimSpace(snap.Config.CloneGeneration)
	if expectedCloneGen != "" && cloneGen != "" && cloneGen != expectedCloneGen {
		return fmt.Errorf("clone generation mismatch: %w", models.ErrSnapshotFenced)
	}
	if err := s.ensureWasmSandboxRowForImport(ctx, sandboxID, snap, checkpointPath, cloneGen); err != nil {
		return err
	}
	if c := s.Cluster(); c != nil {
		target := cluster.PlacementTarget{
			NodeID: c.SelfNodeID(),
			APIURL: c.SelfAPIURL(),
			IsSelf: true,
		}
		if err := c.ReassignPlacement(ctx, sandboxID, target); err != nil {
			return fmt.Errorf("reassign placement: %w", err)
		}
	}
	return nil
}

func (s *Service) ensureWasmSandboxRowForImport(ctx context.Context, sandboxID string, snap wasmengine.SnapshotRestoreInput, checkpointPath, cloneGen string) error {
	existing, err := s.store.Get(ctx, sandboxID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if existing != nil {
		if err := s.store.CompareCloneGeneration(ctx, sandboxID, cloneGen); err != nil {
			return err
		}
		return s.store.UpdateWasmCheckpoint(ctx, sandboxID, string(models.SandboxStatusPassivated), checkpointPath, cloneGen, "")
	}
	spec := s.clusterSpecForImport(sandboxID, snap)
	now := time.Now().UTC()
	row := &models.Sandbox{
		ID:                 sandboxID,
		Runtime:            models.RuntimeWasm,
		Durability:         snap.Config.Durability,
		ModuleRef:          spec.ModuleRef,
		Image:              spec.Image,
		ModuleDigest:       snap.Config.BaseModule.Digest,
		Status:             models.SandboxStatusPassivated,
		CheckpointPath:     checkpointPath,
		CloneGeneration:    cloneGen,
		CPU:                spec.CPU,
		MemoryMB:           spec.MemoryMB,
		DiskGB:             spec.DiskGB,
		Env:                spec.Env,
		NetworkBlockAll:    spec.NetworkBlockAll,
		NetworkAllowOut:    spec.NetworkAllowOut,
		NetworkDenyOut:     spec.NetworkDenyOut,
		AllowPublicTraffic: spec.AllowPublicTraffic,
		ContainerCommand:   spec.ContainerCommand,
		CreatedAt:          now,
		UpdatedAt:          now,
		OwnerRef:           ownerRefForCreate(ctx),
	}
	if row.Durability == "" {
		row.Durability = models.DurabilityPassivatable
	}
	if row.ModuleRef == "" {
		return fmt.Errorf("import %s: module_ref required (missing cluster spec)", sandboxID)
	}
	if row.Image == "" {
		row.Image = row.ModuleRef
	}
	return s.persistSandboxCreate(ctx, row)
}

func (s *Service) clusterSpecForImport(sandboxID string, snap wasmengine.SnapshotRestoreInput) models.CreateSandboxRequest {
	if c := s.Cluster(); c != nil {
		if spec := c.SpecOf(sandboxID); spec != nil {
			return *spec
		}
	}
	return models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: snap.Config.Durability,
	}
}

// MigrateWasmSandboxToNode orchestrates export on the current owner and import
// on targetNodeID (plans/wasm-runtime.md §4.4).
func (s *Service) MigrateWasmSandboxToNode(ctx context.Context, sandboxID, targetNodeID string) (resp *WasmMigrateResponse, err error) {
	ctx, span := observability.StartSpan(ctx, "wasm.migrate",
		attribute.String("sandbox.id", sandboxID),
		attribute.String("target.node_id", targetNodeID),
	)
	defer func() { observability.EndSpan(span, err) }()

	c := s.Cluster()
	if c == nil {
		return nil, fmt.Errorf("cluster not enabled")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	targetNodeID = strings.TrimSpace(targetNodeID)
	if sandboxID == "" || targetNodeID == "" {
		return nil, fmt.Errorf("sandbox_id and target_node_id required")
	}
	owner, err := c.OwnerOf(sandboxID)
	if err != nil {
		return nil, err
	}
	if owner.NodeID == targetNodeID {
		return nil, fmt.Errorf("target node already owns sandbox %s", sandboxID)
	}
	targetMember, ok := memberByID(c.Members(), targetNodeID)
	if !ok || !targetMember.Alive {
		return nil, fmt.Errorf("target node %q not found or not alive", targetNodeID)
	}
	if c.IsNodeDrained(targetNodeID) {
		return nil, fmt.Errorf("target node %q is drained", targetNodeID)
	}

	var buf bytes.Buffer
	var cloneGen string
	if owner.IsSelf {
		cloneGen, err = s.ExportWasmMigration(ctx, sandboxID, &buf)
	} else {
		cloneGen, err = cluster.StreamWasmMigrateExport(ctx, c, owner, sandboxID, &buf)
	}
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}

	if targetMember.NodeID == c.SelfNodeID() {
		err = s.ImportWasmMigration(ctx, sandboxID, cloneGen, bytes.NewReader(buf.Bytes()))
	} else {
		err = cluster.PostWasmMigrateImport(ctx, c, targetMember, sandboxID, cloneGen, bytes.NewReader(buf.Bytes()))
	}
	if err != nil {
		return nil, fmt.Errorf("import: %w", err)
	}

	return &WasmMigrateResponse{
		SandboxID:       sandboxID,
		SourceNodeID:    owner.NodeID,
		TargetNodeID:    targetNodeID,
		CloneGeneration: cloneGen,
		CheckpointPath:  wasmCheckpointDir(s.cfg.WasmModulesDir, sandboxID),
	}, nil
}

// EvacuateLocalWasmSandboxesForDrain checkpoints and migrates passivatable/durable
// WASM sandboxes off this node during cluster drain (§4.4).
func (s *Service) EvacuateLocalWasmSandboxesForDrain(ctx context.Context) error {
	if s.wasm == nil || !s.cfg.EnableWasm {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	if err := s.DrainWasmSandboxes(ctx); err != nil {
		s.logger.Warn("wasm drain checkpoint before evacuate failed", "error", err)
	}
	known, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	selfID := c.SelfNodeID()
	var firstErr error
	for _, sb := range known {
		if sb == nil || !s.isWasmSandbox(sb) {
			continue
		}
		if !wasmShouldCheckpoint(sb.Durability) {
			continue
		}
		owner, err := c.OwnerOf(sb.ID)
		if err != nil || !owner.IsSelf {
			continue
		}
		target, ok := selectWasmEvacuationTarget(c, selfID)
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("no evacuation target for sandbox %s", sb.ID)
			}
			s.logger.Warn("wasm evacuate: no target", "sandbox_id", sb.ID)
			continue
		}
		if _, err := s.MigrateWasmSandboxToNode(ctx, sb.ID, target.NodeID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.logger.Warn("wasm evacuate migrate failed",
				"sandbox_id", sb.ID,
				"target", target.NodeID,
				"error", err,
			)
		} else {
			s.logger.Info("wasm sandbox evacuated on drain",
				"sandbox_id", sb.ID,
				"target", target.NodeID,
			)
		}
	}
	return firstErr
}

func selectWasmEvacuationTarget(c cluster.Client, excludeNodeID string) (cluster.PlacementTarget, bool) {
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == excludeNodeID || c.IsNodeDrained(m.NodeID) {
			continue
		}
		if m.APIURL == "" && m.NodeID != c.SelfNodeID() {
			continue
		}
		if !cluster.CanOwnSandboxRole(m.Role) {
			continue
		}
		return cluster.PlacementTarget{
			NodeID:        m.NodeID,
			APIURL:        m.APIURL,
			DataPlaneHost: m.DataPlaneHost,
			IsSelf:        m.NodeID == c.SelfNodeID(),
		}, true
	}
	return cluster.PlacementTarget{}, false
}

func memberByID(members []cluster.Member, nodeID string) (cluster.Member, bool) {
	for _, m := range members {
		if m.NodeID == nodeID {
			return m, true
		}
	}
	return cluster.Member{}, false
}
