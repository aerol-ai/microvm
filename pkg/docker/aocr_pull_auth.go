package docker

import (
	"os"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// aocrClusterPullAuth is the node-local credential the daemon presents when
// pulling cluster-owned artifacts (snapshots + Firecracker templates) from
// AOCR. It mirrors the producer-side SnapshotPushConfig: the same cluster PAT
// authorizes both push (snapshot_push.go / template_push.go) and pull, scoped
// to the `cluster/<id>/*` namespace by AOCR's auth/src/clusterPat.ts.
//
// Why this lives on the Client rather than being threaded through every
// caller: the two consumer paths that need it — the create-path pull of an
// AOCR-distributed snapshot (client.go Create → pullImageDedup) and the
// Firecracker template puller (export.go PullImage → pullImageDedup) — both
// funnel through pullImageDedup with a nil RegistryAuth. Back-filling there in
// one place keeps the credential out of the per-sandbox sealed-registry path
// (it is node config, not user data, so it is never sealed or forwarded
// cross-node) and reads the PAT fresh on every pull so rotation is a file
// write — the exact contract the pushers already follow.
type aocrClusterPullAuth struct {
	// hosts are the registry vhosts whose `cluster/...` repos this credential
	// applies to (typically the AOCR push host). Lowercased, trailing slash
	// stripped. A ref whose host is not in this set is left untouched so the
	// cluster PAT never leaks to an unrelated registry.
	hosts []string
	// clusterID is presented as the registry username. AOCR validates the PAT
	// (the password), not the username, but the convention keeps logs and the
	// `cluster/<id>/` path segment aligned.
	clusterID string
	// patPath is the file holding the bearer token presented as the registry
	// password. Re-read on every resolve so rotation needs no restart; never
	// logged.
	patPath string
}

// ConfigureAOCRPullAuth installs the cluster-PAT pull credential onto an
// existing Client. A no-op (leaves the feature off, pulls stay anonymous) when
// clusterID or patPath is empty, or when no non-empty host is supplied —
// matching the "consume-only node without AOCR creds" case where a public
// registry needs no auth. Called once from main() after config load, alongside
// ConfigureMirror.
func (c *Client) ConfigureAOCRPullAuth(hosts []string, clusterID, patPath string) {
	clusterID = strings.TrimSpace(clusterID)
	patPath = strings.TrimSpace(patPath)
	if clusterID == "" || patPath == "" {
		return
	}
	normalized := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimRight(strings.TrimSpace(h), "/"))
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		normalized = append(normalized, h)
	}
	if len(normalized) == 0 {
		return
	}
	c.aocrPullAuth = &aocrClusterPullAuth{
		hosts:     normalized,
		clusterID: clusterID,
		patPath:   patPath,
	}
}

// resolveAOCRPullAuth returns the cluster-PAT credential for imageRef when the
// ref targets a configured AOCR host under the `cluster/` namespace, and nil
// otherwise. Returning nil leaves the pull anonymous — correct for public
// images and for nodes that never configured AOCR pull auth.
//
// The PAT is read fresh from disk on each call; a read failure resolves to nil
// (and a warning) rather than blocking the pull — an anonymous attempt that
// 401s surfaces a clearer registry error than a half-applied credential.
func (c *Client) resolveAOCRPullAuth(imageRef string) *models.RegistryAuth {
	if c.aocrPullAuth == nil {
		return nil
	}
	ref := strings.TrimSpace(imageRef)
	if ref == "" {
		return nil
	}
	// Strip any transport prefix (docker://, oci:, etc.) before splitting host.
	if _, after, ok := strings.Cut(ref, "://"); ok {
		ref = after
	}
	host, rest := splitHostRepo(ref)
	if host == "" {
		return nil
	}
	if !slices.Contains(c.aocrPullAuth.hosts, strings.ToLower(host)) {
		return nil
	}
	// Only the cluster-owned namespace is in scope for this credential; a
	// non-cluster repo on the same host (e.g. a user push) must not silently
	// borrow the cluster PAT.
	if rest != "cluster" && !strings.HasPrefix(rest, "cluster/") {
		return nil
	}

	pat, err := readAOCRPATFile(c.aocrPullAuth.patPath)
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("aocr pull auth: read PAT failed; pulling anonymously",
				"path", c.aocrPullAuth.patPath, "error", err)
		}
		return nil
	}
	return &models.RegistryAuth{
		Server:   host,
		Username: c.aocrPullAuth.clusterID,
		Password: pat,
	}
}

// readAOCRPATFile reads the bearer token from disk, trimming trailing
// whitespace (newlines from `echo "..." > pat`) so an editor-written token is
// not rejected by the registry. Mirrors service.readPATFile; duplicated here
// to keep pkg/docker free of an internal/service import.
func readAOCRPATFile(path string) (string, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", os.ErrInvalid
	}
	return token, nil
}
