package models

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// MountType identifies the storage backend the user wants mounted inside their
// container. The daemon runs the mount tool on the host (in a per-sandbox
// directory) and bind-mounts that directory into the container, so credentials
// never enter the container and the user's image needs no mount tooling.
type MountType string

const (
	MountTypeS3     MountType = "s3"
	MountTypeNFS    MountType = "nfs"
	MountTypeSSHFS  MountType = "sshfs"
	MountTypeRclone MountType = "rclone"
)

// MountSpec describes a single external-storage mount the user wants to be
// available inside their sandbox. Credentials are encrypted at rest in the
// daemon's database, materialized only on the host as the FUSE process needs
// them, and never returned by any read API.
type MountSpec struct {
	Type        MountType         `json:"type"`
	Target      string            `json:"target"`
	Source      string            `json:"source"`
	Options     map[string]string `json:"options,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
	ReadOnly    bool              `json:"read_only,omitempty"`
}

// MountSpecRedacted is the read-only view returned by the API. It mirrors
// MountSpec but strips credentials.
type MountSpecRedacted struct {
	Type           MountType         `json:"type"`
	Target         string            `json:"target"`
	Source         string            `json:"source"`
	Options        map[string]string `json:"options,omitempty"`
	ReadOnly       bool              `json:"read_only,omitempty"`
	HasCredentials bool              `json:"has_credentials"`
}

// MountSpecFile is the JSON envelope used to (de)serialize the encrypted
// blob of a sandbox's mount specs in the daemon's database. Kept as a struct
// rather than a bare slice so future fields (version, key id) can be added
// without a migration.
type MountSpecFile struct {
	Mounts []MountSpec `json:"mounts"`
}

// MaxMountsPerSandbox caps fan-out so a malicious request can't make sandboxd
// build an arbitrarily large container spec. Platform volumes count against the
// same cap as external mounts (a single shared budget).
const MaxMountsPerSandbox = 8

// PlatformVolumeMount is a request to attach a named, operator-backed
// persistent volume at Path inside the sandbox. Name is sanitized and scoped to
// the caller's tenant by the service; the user supplies nothing else (no
// bucket, no credentials). See plans/e2b-volume-mounts.md.
type PlatformVolumeMount struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// Volume is a first-class, operator-backed persistent volume object. E2B
// references volumes by name only (no object), but the Daytona facade exposes
// full CRUD, so a volume needs a durable row: a stable id, the owning tenant,
// the user-facing name, and which backend it lives on. The backing storage
// (S3 prefix / NFS dir) is derived deterministically from (tenant, name) — the
// row is metadata, not the data itself.
type Volume struct {
	ID      string `json:"id"`
	Tenant  string `json:"tenant"`
	Name    string `json:"name"`
	Backend string `json:"backend"`
	// Source is the backend coordinate (S3 bucket/prefix or NFS host:/path)
	// frozen at creation time. Delete and reconciliation read this stored value
	// rather than recomputing it from mutable operator config, so a volume keeps
	// mounting and reclaiming the exact location it was created against even if
	// the operator later changes the configured bucket/prefix/export. Empty for
	// rows created before this column existed; callers fall back to recompute.
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// VolumeAttachment is the indexed store-side reference from a sandbox to a
// platform volume. It deliberately duplicates the deterministic source so delete
// and reconciliation paths never need to decrypt sandbox_mounts or rebuild the
// source from mutable operator config just to answer "is this attached?".
type VolumeAttachment struct {
	Tenant        string    `json:"tenant"`
	VolumeID      string    `json:"volume_id"`
	SandboxID     string    `json:"sandbox_id"`
	IncarnationID string    `json:"incarnation_id"`
	Target        string    `json:"target"`
	Source        string    `json:"source"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedVolume bool      `json:"-"`
}

// PendingVolumeDeletion is a durable cleanup ledger row. Daytona delete removes
// the user-visible metadata row only after this record exists, so a backend
// cleanup failure never leaves remote data without coordinates to reconcile.
type PendingVolumeDeletion struct {
	VolumeID  string    `json:"volume_id"`
	Tenant    string    `json:"tenant"`
	Name      string    `json:"name"`
	Backend   string    `json:"backend"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	// ErrPlatformVolumesDisabled is returned when a request references platform
	// volumes but the operator has not enabled them. Facades map this to 412
	// Precondition Failed.
	ErrPlatformVolumesDisabled = errors.New("platform volumes are not enabled on this deployment")
	// ErrPlatformVolumesUnsupportedRuntime is returned when platform volumes are
	// requested on a runtime that cannot bind-mount host paths. Firecracker
	// (ext4 block-device rootfs) and wasm (host-mediated, no container FS) both
	// silently drop binds, so they are rejected up front.
	ErrPlatformVolumesUnsupportedRuntime = errors.New("platform volumes are not supported on the firecracker or wasm runtime")
	// ErrPlatformVolumeQuota is returned when a tenant would exceed its
	// configured volume-count cap.
	ErrPlatformVolumeQuota = errors.New("tenant platform-volume quota reached")

	// ErrPlatformVolumeInUse is returned when a delete is attempted while one or
	// more live sandboxes still have the volume attached. Facades map this to
	// 409 Conflict.
	ErrPlatformVolumeInUse = errors.New("volume is still attached to one or more sandboxes")
)

// MaxCredentialKeys / MaxCredentialBytes bound credential payload size so a
// malicious request can't blow up daemon memory.
const (
	MaxCredentialKeys  = 32
	MaxCredentialBytes = 4096
)

// sensitiveTargets are paths the daemon refuses to let users override with a
// mount. Mounting any of these would either break the toolbox / shell or
// allow shadowing system files.
var sensitiveTargets = map[string]struct{}{
	"/":        {},
	"/proc":    {},
	"/sys":     {},
	"/dev":     {},
	"/etc":     {},
	"/usr":     {},
	"/bin":     {},
	"/sbin":    {},
	"/lib":     {},
	"/lib32":   {},
	"/lib64":   {},
	"/boot":    {},
	"/var/run": {},
	"/run":     {},
}

// Validate checks the spec against the daemon's mount policy. toolboxMountPath
// is the path the toolbox binary is bind-mounted to inside the container; we
// refuse to let the user shadow it.
func (m *MountSpec) Validate(toolboxMountPath string) error {
	if m == nil {
		return errors.New("mount is nil")
	}
	switch m.Type {
	case MountTypeS3, MountTypeNFS, MountTypeSSHFS, MountTypeRclone:
	default:
		return fmt.Errorf("unsupported mount type %q", m.Type)
	}

	target := strings.TrimSpace(m.Target)
	if target == "" {
		return errors.New("target is required")
	}
	if !path.IsAbs(target) {
		return fmt.Errorf("target must be absolute: %q", target)
	}
	cleaned := path.Clean(target)
	if cleaned != target {
		return fmt.Errorf("target must be clean: %q (suggested: %q)", target, cleaned)
	}
	if strings.Contains(target, "..") {
		return fmt.Errorf("target must not contain ..: %q", target)
	}
	if _, blocked := sensitiveTargets[cleaned]; blocked {
		return fmt.Errorf("target %q is reserved", cleaned)
	}
	if toolboxMountPath != "" && cleaned == path.Clean(toolboxMountPath) {
		return fmt.Errorf("target %q collides with toolbox mount", cleaned)
	}

	if strings.TrimSpace(m.Source) == "" {
		return errors.New("source is required")
	}
	if err := validateSource(m.Type, m.Source); err != nil {
		return err
	}

	if len(m.Credentials) > MaxCredentialKeys {
		return fmt.Errorf("credentials: too many keys (max %d)", MaxCredentialKeys)
	}
	totalBytes := 0
	for k, v := range m.Credentials {
		if strings.ContainsAny(k, "\n\x00") || strings.ContainsAny(v, "\x00") {
			return errors.New("credentials must not contain null bytes or newlines in keys")
		}
		totalBytes += len(k) + len(v)
	}
	if totalBytes > MaxCredentialBytes {
		return fmt.Errorf("credentials: payload too large (max %d bytes)", MaxCredentialBytes)
	}

	return nil
}

func validateSource(t MountType, source string) error {
	source = strings.TrimSpace(source)
	switch t {
	case MountTypeS3:
		// Accept either a bare bucket name or s3://bucket[/prefix]. Reject
		// anything that smells like a host filesystem path.
		if strings.HasPrefix(source, "/") || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			return fmt.Errorf("s3 source must not be a filesystem path: %q", source)
		}
	case MountTypeNFS:
		// Format: host:/path
		if !strings.Contains(source, ":/") || strings.HasPrefix(source, "/") {
			return fmt.Errorf("nfs source must look like host:/path: %q", source)
		}
	case MountTypeSSHFS:
		// Format: user@host:/path
		if !strings.Contains(source, "@") || !strings.Contains(source, ":") {
			return fmt.Errorf("sshfs source must look like user@host:/path: %q", source)
		}
	case MountTypeRclone:
		// Format: remote:path (rclone's own syntax). Refuse a bare local path.
		if strings.HasPrefix(source, "/") || strings.HasPrefix(source, "./") {
			return fmt.Errorf("rclone source must be a configured remote, not a local path: %q", source)
		}
	}
	return nil
}

// Mount secrets belong in Credentials and nowhere else. Source and Options
// are not secrets by contract: the read API returns them, and in cluster mode
// they are replicated in the clear into the Raft placement spec and the
// recovery store so another node can re-run the mount (the service's
// RedactClusterSecrets keeps them and strips only Credentials). A credential
// smuggled into either — an rclone connection-string parameter in source, a
// mount-tool flag in options.extra_args, an NFS option, an invented options
// key — would therefore be replicated unsealed. mountCredentialNameMarkers
// are the substrings that mean "credential" in every tool this daemon drives
// (the AWS chain behind mount-s3, rclone backends, ssh); ValidateSecretsPlacement
// refuses such a name with a pointer to the right field. It is separate from
// Validate because it is an intake rule for new requests: a stored spec being
// replayed for a failover recreate is already replicated, and refusing it
// there would only lose the sandbox. This is hygiene at the edge, not the
// boundary: the boundary is that only Credentials is sealed.
var mountCredentialNameMarkers = []string{
	"secret", "password", "passwd", "token", "access_key", "private_key",
	"api_key", "customer_key", "client_secret", "sas_url",
}

// isMountCredentialName reports whether a flag, option, or parameter name
// names a credential. Leading dashes are dropped, case is ignored, and '-'
// and '_' are equivalent, so --s3-secret-access-key, secret_access_key and
// SECRET-ACCESS-KEY are one name. A bare "pass" (rclone's sftp/ftp/webdav
// parameter) and any name ending in _pass count too.
func isMountCredentialName(name string) bool {
	name = strings.ToLower(strings.TrimLeft(strings.TrimSpace(name), "-"))
	name = strings.ReplaceAll(name, "-", "_")
	if name == "" {
		return false
	}
	if name == "pass" || strings.HasSuffix(name, "_pass") {
		return true
	}
	for _, marker := range mountCredentialNameMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func mountCredentialInClearError(where, name string) error {
	return fmt.Errorf("%s %q names a credential: put it in credentials, which is sealed; source and options are stored and replicated in the clear", where, name)
}

// ValidateSecretsPlacement refuses credential-shaped names in the fields that
// are stored and replicated unsealed. See mountCredentialNameMarkers.
func (m *MountSpec) ValidateSecretsPlacement() error {
	if m == nil {
		return errors.New("mount is nil")
	}
	for k := range m.Options {
		if isMountCredentialName(k) {
			return mountCredentialInClearError("options key", k)
		}
	}
	// options.extra_args is whitespace-split into argv by the S3 adapter;
	// check every flag name, in both --flag=value and --flag value forms.
	for _, tok := range strings.Fields(m.Options["extra_args"]) {
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		name, _, _ := strings.Cut(tok, "=")
		if isMountCredentialName(name) {
			return mountCredentialInClearError("options.extra_args flag", name)
		}
	}
	// options.opts is the NFS -o list: name or name=value, comma-separated.
	if opts := strings.TrimSpace(m.Options["opts"]); opts != "" {
		for _, kv := range strings.Split(opts, ",") {
			name, _, _ := strings.Cut(kv, "=")
			if isMountCredentialName(name) {
				return mountCredentialInClearError("options.opts entry", name)
			}
		}
	}
	if m.Type == MountTypeRclone {
		if name, found := rcloneConnectionStringCredential(m.Source); found {
			return mountCredentialInClearError("rclone source parameter", name)
		}
	}
	return nil
}

// rcloneConnectionStringCredential scans rclone's remote,param=value:path and
// :backend,param=value:path connection-string syntax — which needs no
// rclone.conf and so can carry a whole credential in the source string — and
// returns the first parameter that names one. Best effort by design: a quoted
// value containing a colon ends the scan early and the parameters before it
// are still checked.
func rcloneConnectionStringCredential(source string) (string, bool) {
	source = strings.TrimPrefix(strings.TrimSpace(source), ":")
	remote, _, ok := strings.Cut(source, ":")
	if !ok {
		return "", false
	}
	params := strings.Split(remote, ",")
	for _, p := range params[1:] {
		name, _, _ := strings.Cut(p, "=")
		if isMountCredentialName(name) {
			return strings.TrimSpace(name), true
		}
	}
	return "", false
}

// Redact strips credentials, returning the user-safe view.
func (m *MountSpec) Redact() MountSpecRedacted {
	return MountSpecRedacted{
		Type:           m.Type,
		Target:         m.Target,
		Source:         m.Source,
		Options:        copyStringMap(m.Options),
		ReadOnly:       m.ReadOnly,
		HasCredentials: len(m.Credentials) > 0,
	}
}

// RedactMounts returns the read-only API view for a slice of mounts.
func RedactMounts(mounts []MountSpec) []MountSpecRedacted {
	out := make([]MountSpecRedacted, 0, len(mounts))
	for i := range mounts {
		out = append(out, mounts[i].Redact())
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
