package docker

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// AOCRPullAuth is the node-local credential the daemon presents when pulling
// cluster-owned artifacts (snapshots + Firecracker templates) from AOCR. It
// mirrors the producer-side SnapshotPushConfig: the same cluster PAT authorizes
// both push (snapshot_push.go / template_push.go) and pull, scoped to the
// `cluster/<id>/*` namespace by AOCR's auth/src/clusterPat.ts.
//
// Why it is exported rather than private to the Client: both container engines
// pull AOCR-distributed snapshots on the create path with no caller credential
// — dockerd through this package (Create / PullImage → pullImageDedup) and
// native containerd through internal/runtime/containerd's ensureImage. One
// shared resolver keeps the scoping rules (configured host + `cluster/` repo
// only) identical across engines, so flipping a node from docker to containerd
// can neither widen nor lose what the cluster PAT is presented for.
//
// The credential is node config, not user data: it is never sealed, stored on
// a sandbox row, or forwarded cross-node. Immutable after construction, so
// concurrent Resolve calls need no lock.
type AOCRPullAuth struct {
	// hosts are the registry vhosts whose `cluster/...` repos this credential
	// applies to (typically the AOCR push host). Normalized by
	// normalizeAOCRHost. A ref whose host is not in this set is left untouched
	// so the cluster PAT never leaks to an unrelated registry.
	hosts []string
	// clusterID is presented as the registry username. AOCR validates the PAT
	// (the password), not the username, but the convention keeps logs and the
	// `cluster/<id>/` path segment aligned.
	clusterID string
	// patPath is the file holding the bearer token presented as the registry
	// password. Re-read on every resolve so rotation is a file write and needs
	// no restart; never logged.
	patPath string
}

// NewAOCRPullAuth builds the cluster-PAT pull credential, or returns nil (the
// feature stays off, pulls stay anonymous) when clusterID or patPath is empty
// or no non-empty host is supplied — the "consume-only node without AOCR
// creds" case where a public registry needs no auth. A nil *AOCRPullAuth is a
// valid Resolve receiver, so callers may store the result unconditionally.
func NewAOCRPullAuth(hosts []string, clusterID, patPath string) *AOCRPullAuth {
	clusterID = strings.TrimSpace(clusterID)
	patPath = strings.TrimSpace(patPath)
	if clusterID == "" || patPath == "" {
		return nil
	}
	normalized := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = normalizeAOCRHost(h)
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
		return nil
	}
	return &AOCRPullAuth{
		hosts:     normalized,
		clusterID: clusterID,
		patPath:   patPath,
	}
}

// Resolve returns the cluster-PAT credential for imageRef when the ref targets
// a configured AOCR host under the `cluster/` namespace.
//
//   - (nil, nil): out of scope (other host, non-cluster repo, bare Docker Hub
//     ref) or a nil receiver. The pull stays anonymous, which is correct for
//     public images. The PAT file is not read, so an unrelated pull pays no
//     file I/O.
//   - (auth, nil): in scope. Server is the ref's host as written, Username the
//     cluster ID, Password the PAT read fresh from disk.
//   - (nil, err): in scope, but the PAT file is missing, unreadable, or blank.
//     err names the file path, never its contents; the caller owns the policy
//     (both engines warn and fall back to an anonymous attempt).
func (a *AOCRPullAuth) Resolve(imageRef string) (*models.RegistryAuth, error) {
	if a == nil {
		return nil, nil
	}
	ref := strings.TrimSpace(imageRef)
	if ref == "" {
		return nil, nil
	}
	// Strip any transport prefix (docker://, oci:, etc.) before splitting host.
	if _, after, ok := strings.Cut(ref, "://"); ok {
		ref = after
	}
	host, rest := splitHostRepo(ref)
	if host == "" {
		return nil, nil
	}
	if !slices.Contains(a.hosts, normalizeAOCRHost(host)) {
		return nil, nil
	}
	// Only the cluster-owned namespace is in scope for this credential; a
	// non-cluster repo on the same host (e.g. a user push) must not silently
	// borrow the cluster PAT.
	if rest != "cluster" && !strings.HasPrefix(rest, "cluster/") {
		return nil, nil
	}

	pat, err := readAOCRPATFile(a.patPath)
	if err != nil {
		return nil, fmt.Errorf("read AOCR cluster PAT file %s: %w", a.patPath, err)
	}
	return &models.RegistryAuth{
		Server:   host,
		Username: a.clusterID,
		Password: pat,
	}, nil
}

// ConfigureAOCRPullAuth installs the cluster-PAT pull credential onto an
// existing Client. A no-op (any prior setting is kept; by default pulls stay
// anonymous) when NewAOCRPullAuth reports the config incomplete. Called once
// from the daemon after config load, alongside ConfigureMirror.
func (c *Client) ConfigureAOCRPullAuth(hosts []string, clusterID, patPath string) {
	if a := NewAOCRPullAuth(hosts, clusterID, patPath); a != nil {
		c.aocrPullAuth = a
	}
}

// resolveAOCRPullAuth returns the cluster-PAT credential for imageRef when the
// ref targets a configured AOCR host under the `cluster/` namespace, and nil
// otherwise. Returning nil leaves the pull anonymous — correct for public
// images and for nodes that never configured AOCR pull auth.
//
// A PAT read failure resolves to nil (and a warning) rather than blocking the
// pull: the anonymous attempt then surfaces the registry's own 401, and the
// warning names the PAT path so the operator can tell why it was anonymous.
func (c *Client) resolveAOCRPullAuth(imageRef string) *models.RegistryAuth {
	auth, err := c.aocrPullAuth.Resolve(imageRef)
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("aocr pull auth: read PAT failed; pulling anonymously",
				"path", c.aocrPullAuth.patPath, "error", err)
		}
		return nil
	}
	return auth
}

// normalizeAOCRHost canonicalizes a registry host for comparison: trims space
// and trailing slashes, lowercases, and drops an explicit default registry port
// (`:443`/`:80`) so a configured `aocr.aerol.ai` still matches a ref written as
// `aocr.aerol.ai:443/cluster/...`. A non-default port (e.g. `:5000`) is
// significant and kept. IPv6 literals are bracketed (`[::1]:443`), so only the
// final `:port` is treated as a port — `strings.LastIndex` after the last `]`.
func normalizeAOCRHost(h string) string {
	h = strings.ToLower(strings.TrimRight(strings.TrimSpace(h), "/"))
	if h == "" {
		return ""
	}
	// Find a port colon that isn't part of an IPv6 literal.
	portColon := strings.LastIndexByte(h, ':')
	if portColon > strings.LastIndexByte(h, ']') {
		switch h[portColon+1:] {
		case "443", "80":
			h = h[:portColon]
		}
	}
	return h
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
