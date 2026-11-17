package volumes

import (
	"path"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A sandbox's replicated spec carries its platform volumes as plain mounts
// (the cluster create resolves them before it replicates the spec), so a
// node that rebuilds the sandbox from that spec sees a platform volume and
// an operator's raw mount the same way. Raw mounts need a host-capable
// caller, and a rebuild on another node has none, so the node takes a
// mount only when it is one of the sandbox's own platform volumes on this
// node's backend, and mounts it as this node builds it.

// TenantForOwnerRef is the tenant scope segment of a sandbox owned by
// ownerRef, as TenantScope gives it for a caller of that owner. An empty
// ownerRef (an operator's sandbox) has the operator scope, which depends on
// the node's configuration: it returns "".
func TenantForOwnerRef(ownerRef string) string {
	ref := strings.TrimSpace(ownerRef)
	if ref == "" {
		return ""
	}
	return "t-" + hashSegment(ref)
}

// PlatformMountShape reports whether m could be the mount of one of a
// tenant's platform volumes on some S3 or NFS backend, with no backend
// configuration to check against: an s3 or nfs mount whose source ends in
// <tenant>/<volume name>. tenant "" stands for an operator scope, any
// "op-" segment. It is a coarse filter for nodes without the volume
// configuration (the Raft leader deciding whether a sandbox may move);
// PlatformMountFor is the check a node mounts by.
func PlatformMountShape(m models.MountSpec, tenant string) bool {
	segs, ok := platformSourceSegments(m)
	// s3 needs the bucket before the scope; an nfs export may be "/".
	least := 2
	if m.Type == models.MountTypeS3 {
		least = 3
	}
	if !ok || len(segs) < least {
		return false
	}
	scope, name := segs[len(segs)-2], segs[len(segs)-1]
	if clean, err := SanitizeVolumeName(name); err != nil || clean != name {
		return false
	}
	if tenant == "" {
		return strings.HasPrefix(scope, operatorScopePrefix) && ValidateOperatorScope(scope) == nil
	}
	return scope == tenant
}

// PlatformMountFor reports whether m is the mount of one of tenant's
// platform volumes on backend b: its source is exactly b's coordinate for
// tenant and a volume name. It returns the mount as b builds it (b's
// options and credentials, m's target and read-only flag), so nothing but
// the target comes from m. A volume whose source predates a change to b's
// bucket, prefix or export is not one.
func PlatformMountFor(b Backend, tenant string, m models.MountSpec) (models.MountSpec, bool) {
	if strings.TrimSpace(tenant) == "" {
		return models.MountSpec{}, false
	}
	switch m.Type {
	case models.MountTypeS3:
		b.Kind = BackendS3
	case models.MountTypeNFS:
		b.Kind = BackendNFS
	default:
		return models.MountSpec{}, false
	}
	segs, ok := platformSourceSegments(m)
	if !ok || len(segs) == 0 {
		return models.MountSpec{}, false
	}
	name := segs[len(segs)-1]
	if clean, err := SanitizeVolumeName(name); err != nil || clean != name {
		return models.MountSpec{}, false
	}
	want, err := MountSource(b, tenant, name)
	if err != nil || want != m.Source {
		return models.MountSpec{}, false
	}
	out, err := BuildMountSpecForSource(b, want, m.Target, m.ReadOnly)
	if err != nil {
		return models.MountSpec{}, false
	}
	return out, true
}

// PlatformMountFromRecord reports whether m is the mount of platform volume
// vol, attached to the sandbox being rebuilt at att, for a sandbox whose
// tenant scope is tenant ("" for an operator's sandbox, which takes the
// volume's own operator scope). The source is the one the volume's record
// froze at creation (vol.Source), so a volume made before the operator
// changed the bucket, prefix or export keeps its location, as on delete and
// reclaim; a record from before that field has the location b builds for
// it. The source must end in the record's own tenant and name. It returns
// the mount as b builds it for that source (b's options and credentials,
// m's target and read-only flag).
func PlatformMountFromRecord(b Backend, tenant string, vol models.Volume, att models.VolumeAttachment, m models.MountSpec) (models.MountSpec, bool) {
	if att.VolumeID != vol.ID || att.Tenant != vol.Tenant || att.Source != m.Source || att.Target != m.Target {
		return models.MountSpec{}, false
	}
	if tenant != "" && vol.Tenant != tenant || tenant == "" && ValidateOperatorScope(vol.Tenant) != nil {
		return models.MountSpec{}, false
	}
	// The node mounts with its own backend, which must be the volume's.
	if vol.Backend != b.Kind || string(m.Type) != vol.Backend {
		return models.MountSpec{}, false
	}
	src := vol.Source
	if src == "" {
		var err error
		if src, err = MountSource(b, vol.Tenant, vol.Name); err != nil {
			return models.MountSpec{}, false
		}
	}
	if src != m.Source {
		return models.MountSpec{}, false
	}
	segs, ok := platformSourceSegments(m)
	if !ok || len(segs) < 2 || segs[len(segs)-2] != vol.Tenant || segs[len(segs)-1] != vol.Name {
		return models.MountSpec{}, false
	}
	// The record keeps a volume made before a prefix or export change, but
	// never another bucket or server: the node's own platform store only.
	// A volume made before the bucket or server itself changed falls back
	// to the configuration check, as one with no record does.
	if !onPlatformStore(b, m) {
		return models.MountSpec{}, false
	}
	out, err := BuildMountSpecForSource(b, src, m.Target, m.ReadOnly)
	if err != nil {
		return models.MountSpec{}, false
	}
	return out, true
}

// onPlatformStore reports whether m names this node's platform store: for
// s3 the configured bucket, for nfs the configured server.
func onPlatformStore(b Backend, m models.MountSpec) bool {
	switch m.Type {
	case models.MountTypeS3:
		bucket, _, _ := strings.Cut(m.Source, "/")
		return b.S3Bucket != "" && bucket == b.S3Bucket
	case models.MountTypeNFS:
		server, _, ok := strings.Cut(m.Source, ":/")
		return ok && b.NFSServer != "" && server == b.NFSServer
	}
	return false
}

// platformSourceSegments splits a platform mount's source into its path
// segments: "bucket/prefix/tenant/name" for s3, the path after
// "server:/" for nfs. ok is false for any other type or form, a scheme
// included, and for a path that is not already clean.
func platformSourceSegments(m models.MountSpec) ([]string, bool) {
	src := m.Source
	switch m.Type {
	case models.MountTypeS3:
		if strings.Contains(src, "://") {
			return nil, false
		}
	case models.MountTypeNFS:
		i := strings.Index(src, ":/")
		if i <= 0 {
			return nil, false
		}
		src = src[i+2:]
	default:
		return nil, false
	}
	if src == "" || strings.HasPrefix(src, "/") || path.Clean(src) != src {
		return nil, false
	}
	return strings.Split(src, "/"), true
}

// SourceUnderRoot reports whether source is a platform volume's coordinate
// on backend b: under b's bucket and prefix (s3) or server and export
// (nfs), followed by exactly a tenant or operator scope and a volume name.
// A node deletes a volume's bytes only for such a source (the reclaim
// sweep): a row's source is replicated, and a source anywhere else is not
// a volume this node's storage holds.
func SourceUnderRoot(b Backend, source string) bool {
	var root string
	switch b.Kind {
	case BackendS3:
		if strings.TrimSpace(b.S3Bucket) == "" {
			return false
		}
		root = path.Join(b.S3Bucket, strings.Trim(b.S3Prefix, "/")) + "/"
	case BackendNFS:
		if strings.TrimSpace(b.NFSServer) == "" {
			return false
		}
		root = b.NFSServer + ":/"
		if export := strings.Trim(b.NFSExport, "/"); export != "" {
			root += export + "/"
		}
	default:
		return false
	}
	rest, ok := strings.CutPrefix(source, root)
	if !ok || rest == "" || path.Clean(rest) != rest {
		return false
	}
	segs := strings.Split(rest, "/")
	if len(segs) != 2 {
		return false
	}
	scope, name := segs[0], segs[1]
	if clean, err := SanitizeVolumeName(name); err != nil || clean != name {
		return false
	}
	if strings.HasPrefix(scope, operatorScopePrefix) {
		return ValidateOperatorScope(scope) == nil
	}
	hex, ok := strings.CutPrefix(scope, "t-")
	if !ok || len(hex) != 16 {
		return false
	}
	for _, r := range hex {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
