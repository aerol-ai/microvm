package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// SnapshotPushConfig wires the optional background AOCR push to a specific
// registry endpoint. A zero value disables push; the snapshot path runs
// exactly as before. main() validates that PATPath, ClusterID, and Host
// are non-empty when Enabled=true.
//
// Auth reuses the auto-import cluster PAT (same secret, same rotation
// surface). The PAT file is re-read on every call so an operator can
// rotate it without restarting sandboxd — there's no in-memory cache.
type SnapshotPushConfig struct {
	// Enabled gates the whole feature. When false the snapshot-create
	// path stays byte-identical to today (no push, no state transitions).
	Enabled bool
	// Host is the AOCR registry vhost the daemon pushes to
	// (e.g. `aocr.aerol.ai`). Falls back to ImageDistributionAOCRHost
	// at the wiring layer when MirrorPushHost is unset.
	Host string
	// ClusterID is the AOCR-scoped tenant the snapshot ends up under.
	// Used both as the registry-auth username (by convention; AOCR
	// validates the PAT, not the username) and as the path namespace
	// `cluster/<id>/snapshots/<name>`.
	ClusterID string
	// PATPath is the file path to the bearer token presented as the
	// Docker registry password. File-sourced so rotation is just a
	// file write; never logged.
	PATPath string
	// TagSuffix is an optional AOCR retention suffix appended to the
	// pushed tag (`latest<suffix>`), e.g. "--ttl-1h" or "--idle-30d".
	// AOCR's reaper parses `--(ttl|idle)-<dur>` off the END of the tag, so
	// `latest--ttl-1h` expires 1h after push. Empty (the default and prod
	// behavior) pushes a plain `latest` tag, which the reaper keeps
	// latest-only forever. Because "suffixes are real tags" in AOCR, the
	// pull side (DestRefFor) must use the same suffix — both go through
	// snapshotAOCRRef, so they stay consistent. Used by ephemeral clusters
	// (e.g. integration tests) that want their snapshots auto-reaped.
	TagSuffix string
}

// retentionSuffixPattern matches the AOCR retention tag suffix
// (`--ttl-<dur>` / `--idle-<dur>`), mirroring the registry's reaper regex
// `^(.*)--(ttl|idle)-([a-z0-9]+)$`. Validation here is intentionally lax on
// the duration token — AOCR is the authority on which durations exist; we only
// guarantee the suffix is well-formed so a typo fails at boot, not at push.
var retentionSuffixPattern = regexp.MustCompile(`^--(ttl|idle)-[a-z0-9]+$`)

// Validate enforces the consistency rules the snapshot pusher relies on.
// Returns nil for a disabled config so callers can validate unconditionally.
func (c SnapshotPushConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("SnapshotPushConfig: Host required when Enabled")
	}
	if strings.TrimSpace(c.ClusterID) == "" {
		return errors.New("SnapshotPushConfig: ClusterID required when Enabled")
	}
	if strings.TrimSpace(c.PATPath) == "" {
		return errors.New("SnapshotPushConfig: PATPath required when Enabled")
	}
	if s := strings.TrimSpace(c.TagSuffix); s != "" && !retentionSuffixPattern.MatchString(s) {
		return fmt.Errorf("SnapshotPushConfig: TagSuffix %q must be a retention suffix like --ttl-1h or --idle-30d", s)
	}
	return nil
}

// SnapshotPushDocker is the narrow Docker surface the pusher needs.
// Pulled out so tests can inject a fake without instantiating a real
// Docker client, and so the dependency surface of the pusher stays
// readable at a glance.
type SnapshotPushDocker interface {
	PushImage(ctx context.Context, req docker.PushImageRequest) (string, error)
}

// SnapshotPushResult is what PushOnce returns on success. The destination
// ref is what the reconciler writes onto the snapshot row's
// ImageRegistryRef field — and what cluster placement on other nodes
// will see when they decide where to start a sandbox from this snapshot.
type SnapshotPushResult struct {
	RegistryRef string
	// Digest is the manifest digest (`sha256:...`) the registry assigned
	// to the pushed tag, as reported by Docker's push stream `aux`
	// payload. Empty when the daemon did not surface one — older daemons
	// or registries that don't return a manifest digest will leave this
	// blank and the reconciler stores "" rather than fabricating a value.
	Digest string
}

// SnapshotPusher pushes a locally-committed snapshot image to AOCR. It
// holds no per-snapshot state; instantiate once at boot and reuse.
// Safe for concurrent use.
type SnapshotPusher struct {
	cfg    SnapshotPushConfig
	docker SnapshotPushDocker
	logger *slog.Logger
}

// NewSnapshotPusher builds a pusher. Returns nil if cfg.Enabled is false
// so callers can do `if pusher == nil { return }` on the snapshot-create
// path without an extra config check.
func NewSnapshotPusher(cfg SnapshotPushConfig, docker SnapshotPushDocker, logger *slog.Logger) (*SnapshotPusher, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if docker == nil {
		return nil, errors.New("SnapshotPusher: docker is required when SnapshotPushConfig.Enabled=true")
	}
	return &SnapshotPusher{
		cfg:    cfg,
		docker: docker,
		logger: logger,
	}, nil
}

// PushOnce tags the snapshot's local image as the AOCR destination ref
// and pushes via the Docker daemon. Returns the destination ref on
// success — used by the reconciler to fill ImageRegistryRef and flip
// ImageDistributionMode to "aocr".
//
// Idempotent: re-pushing the same `cluster/<id>/snapshots/<name>:latest`
// tag is safe; the registry treats the layer set as already-present and
// the daemon's push completes without error.
//
// The PAT is read fresh from disk on every call so an operator can
// rotate it without restarting sandboxd. The PAT never appears in the
// returned error message — only the registry's response body does.
func (p *SnapshotPusher) PushOnce(ctx context.Context, snapshot *models.SandboxSnapshot) (SnapshotPushResult, error) {
	if p == nil {
		return SnapshotPushResult{}, errors.New("snapshot push disabled (pusher is nil)")
	}
	if snapshot == nil {
		return SnapshotPushResult{}, errors.New("snapshot push: snapshot is required")
	}
	source := strings.TrimSpace(snapshot.Image)
	if source == "" {
		return SnapshotPushResult{}, errors.New("snapshot push: snapshot has no image to push")
	}
	name := strings.TrimSpace(snapshot.Name)
	if name == "" {
		return SnapshotPushResult{}, errors.New("snapshot push: snapshot has no name")
	}

	pat, err := readPATFile(p.cfg.PATPath)
	if err != nil {
		return SnapshotPushResult{}, fmt.Errorf("snapshot push: read PAT: %w", err)
	}

	dest := snapshotAOCRRef(p.cfg.Host, p.cfg.ClusterID, name, p.cfg.TagSuffix)

	var digest string
	pushed, err := p.docker.PushImage(ctx, docker.PushImageRequest{
		SourceTag: source,
		DestRef:   dest,
		Auth: models.RegistryAuth{
			Server:   p.cfg.Host,
			Username: p.cfg.ClusterID,
			Password: pat,
		},
		OnLog: func(line string) {
			if p.logger != nil {
				p.logger.Debug("snapshot push", "snapshot", name, "dest", dest, "line", line)
			}
		},
		OnDigest: func(d string) {
			digest = d
		},
	})
	if err != nil {
		return SnapshotPushResult{}, fmt.Errorf("snapshot push %s -> %s: %w", source, dest, err)
	}
	if strings.TrimSpace(pushed) == "" {
		// Defensive: PushImage promises the canonical repo:tag on success.
		// If it ever returns empty, fall back to the planned dest so the
		// snapshot row still gets a usable ref.
		pushed = dest
	}
	return SnapshotPushResult{RegistryRef: pushed, Digest: digest}, nil
}

// DestRefFor returns the AOCR destination ref this pusher would write
// for the given snapshot name. Used by callers that need the canonical
// ref without actually pushing — e.g. cross-node snapshot lookup, where
// a peer node took the snapshot and we want to pull from AOCR without
// asking the FSM whether the snapshot exists. Returns "" when the
// pusher is nil so callers can no-op cleanly when push is disabled.
func (p *SnapshotPusher) DestRefFor(snapshotName string) string {
	if p == nil {
		return ""
	}
	name := strings.TrimSpace(snapshotName)
	if name == "" {
		return ""
	}
	return snapshotAOCRRef(p.cfg.Host, p.cfg.ClusterID, name, p.cfg.TagSuffix)
}

// snapshotAOCRRef is the AOCR destination convention for cluster-local
// snapshots: `<host>/cluster/<id>/snapshots/<name>:latest<suffix>`. Mirrors the
// auto-import path's `cluster/<id>/_imported/...` namespace pattern. The base
// tag is "latest" — snapshot names are themselves unique (the store enforces a
// PRIMARY KEY on `name`). An optional retention suffix (`--ttl-*` / `--idle-*`)
// is appended so the registry reaper can age the tag out; empty means a plain
// `latest` tag that is kept indefinitely. Push and pull must agree on the tag,
// so every caller routes through here.
func snapshotAOCRRef(host, clusterID, snapshotName, tagSuffix string) string {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	clusterID = strings.TrimSpace(clusterID)
	snapshotName = strings.ToLower(strings.TrimSpace(snapshotName))
	tagSuffix = strings.ToLower(strings.TrimSpace(tagSuffix))
	archSfx := archTagSuffix(hostSnapshotArch())
	return fmt.Sprintf("%s/cluster/%s/snapshots/%s:latest%s%s", host, clusterID, snapshotName, tagSuffix, archSfx)
}

// readPATFile reads the bearer token from disk. Trailing whitespace
// (including newlines from `echo "..." > /tmp/pat`) is trimmed so an
// operator using a text editor doesn't end up with a token the registry
// rejects.
func readPATFile(path string) (string, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("PAT file %s is empty", path)
	}
	return token, nil
}

// SnapshotNeedsPush reports whether a snapshot row is a candidate for
// background push. Only local_only snapshots benefit — anything already
// in a remote registry is already distributable, and pushing it would
// just double-store the image.
func SnapshotNeedsPush(snapshot *models.SandboxSnapshot) bool {
	if snapshot == nil {
		return false
	}
	return snapshot.ImageDistributionMode == models.ImageDistributionLocalOnly
}
