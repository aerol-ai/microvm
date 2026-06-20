package volumes

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// UC-07/08/09/22: name sanitization rejects empty, traversal, separators,
// over-length, and reserved names; accepts and lowercases valid names.
func TestSanitizeVolumeName(t *testing.T) {
	long := strings.Repeat("a", MaxVolumeNameLen+1)
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple", "data", "data", false},
		{"lowercased", "Data", "data", false},
		{"dotted-dashed", "my.vol_1-2", "my.vol_1-2", false},
		{"trimmed", "  data  ", "data", false},
		{"empty", "", "", true},
		{"whitespace-only", "   ", "", true},
		{"slash", "a/b", "", true},
		{"backslash-not-allowed", "a\\b", "", true},
		{"traversal", "..", "", true},
		{"single-dot", ".", "", true},
		{"embedded-traversal", "../etc", "", true},
		{"space-inside", "my vol", "", true},
		{"unicode", "café", "", true},
		{"too-long", long, "", true},
		{"max-len-ok", strings.Repeat("a", MaxVolumeNameLen), strings.Repeat("a", MaxVolumeNameLen), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeVolumeName(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SanitizeVolumeName(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SanitizeVolumeName(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("SanitizeVolumeName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// UC-18: tenant scope isolates tenants and is stable; operator/PAT path falls
// back to a deterministic token hash; unscopeable callers error.
func TestTenantScope(t *testing.T) {
	userA := Caller{HasAccess: true, Operator: false, OwnerRef: "tenant-a"}
	userB := Caller{HasAccess: true, Operator: false, OwnerRef: "tenant-b"}
	op := Caller{HasAccess: true, Operator: true, PATToken: "operator-pat"}

	sa, err := TenantScope(userA)
	if err != nil {
		t.Fatalf("TenantScope(userA) error: %v", err)
	}
	sb, err := TenantScope(userB)
	if err != nil {
		t.Fatalf("TenantScope(userB) error: %v", err)
	}
	if sa == sb {
		t.Fatalf("distinct tenants collided on scope %q", sa)
	}
	if !strings.HasPrefix(sa, "t-") {
		t.Fatalf("user scope %q missing t- prefix", sa)
	}

	// Stability: same identity → same scope across calls (survives restart).
	again, _ := TenantScope(userA)
	if again != sa {
		t.Fatalf("tenant scope not stable: %q vs %q", sa, again)
	}

	// Operator path hashes the token deterministically.
	so, err := TenantScope(op)
	if err != nil {
		t.Fatalf("TenantScope(op) error: %v", err)
	}
	if !strings.HasPrefix(so, "op-") {
		t.Fatalf("operator scope %q missing op- prefix", so)
	}
	if so2, _ := TenantScope(Caller{HasAccess: true, Operator: true, PATToken: "operator-pat"}); so2 != so {
		t.Fatalf("operator scope not stable: %q vs %q", so, so2)
	}

	// Scope must be a single clean path segment (no separators).
	for _, s := range []string{sa, sb, so} {
		if strings.ContainsAny(s, "/\\.") {
			t.Fatalf("scope %q is not a clean single segment", s)
		}
	}

	// Unscopeable callers error rather than silently sharing a namespace.
	if _, err := TenantScope(Caller{HasAccess: true, Operator: false, OwnerRef: ""}); err == nil {
		t.Fatal("user with empty owner ref should error")
	}
	if _, err := TenantScope(Caller{HasAccess: false}); err == nil {
		t.Fatal("no-access caller with no token should error")
	}
}

// UC-01/25/27: S3 backend synthesizes a valid bucket/prefix/tenant/name source
// with operator creds, region/endpoint options, and read-only propagation; the
// result passes the existing MountSpec.Validate.
func TestBuildMountSpec_S3(t *testing.T) {
	b := Backend{
		Kind:              BackendS3,
		S3Bucket:          "aerol-volumes",
		S3Prefix:          "volumes",
		S3Region:          "us-east-1",
		S3Endpoint:        "https://r2.example.com",
		S3AccessKeyID:     "AKIA",
		S3SecretAccessKey: "secret",
	}
	spec, err := BuildMountSpec(b, "t-abc", "data", "/workspace", true)
	if err != nil {
		t.Fatalf("BuildMountSpec error: %v", err)
	}
	if spec.Type != models.MountTypeS3 {
		t.Fatalf("type = %q, want s3", spec.Type)
	}
	if spec.Source != "aerol-volumes/volumes/t-abc/data" {
		t.Fatalf("source = %q", spec.Source)
	}
	if !spec.ReadOnly {
		t.Fatal("read-only not propagated")
	}
	if spec.Options["region"] != "us-east-1" || spec.Options["endpoint"] != "https://r2.example.com" {
		t.Fatalf("options = %v", spec.Options)
	}
	if spec.Credentials["access_key_id"] != "AKIA" || spec.Credentials["secret_access_key"] != "secret" {
		t.Fatalf("credentials = %v", spec.Credentials)
	}
	if err := spec.Validate("/.toolbox"); err != nil {
		t.Fatalf("synthesized spec fails MountSpec.Validate: %v", err)
	}
}

// Instance-role S3 (no static keys) sends no credentials profile.
func TestBuildMountSpec_S3_InstanceRole(t *testing.T) {
	b := Backend{Kind: BackendS3, S3Bucket: "bucket"}
	spec, err := BuildMountSpec(b, "t-abc", "data", "/data", false)
	if err != nil {
		t.Fatalf("BuildMountSpec error: %v", err)
	}
	if spec.Credentials != nil {
		t.Fatalf("expected no credentials for instance-role, got %v", spec.Credentials)
	}
	if spec.Source != "bucket/t-abc/data" {
		t.Fatalf("source = %q (empty prefix should collapse)", spec.Source)
	}
}

// UC-26/27: NFS backend synthesizes a host:/path source the adapter accepts and
// carries options under the "opts" key.
func TestBuildMountSpec_NFS(t *testing.T) {
	b := Backend{
		Kind:       BackendNFS,
		NFSServer:  "10.0.0.5",
		NFSExport:  "/exports/aerol",
		NFSOptions: "vers=4.1",
	}
	spec, err := BuildMountSpec(b, "t-abc", "data", "/mnt/data", false)
	if err != nil {
		t.Fatalf("BuildMountSpec error: %v", err)
	}
	if spec.Type != models.MountTypeNFS {
		t.Fatalf("type = %q, want nfs", spec.Type)
	}
	if spec.Source != "10.0.0.5:/exports/aerol/t-abc/data" {
		t.Fatalf("source = %q", spec.Source)
	}
	if spec.Options["opts"] != "vers=4.1" {
		t.Fatalf("opts = %v", spec.Options)
	}
	if err := spec.Validate("/.toolbox"); err != nil {
		t.Fatalf("synthesized nfs spec fails MountSpec.Validate: %v", err)
	}
}

// Invalid name / target / backend / missing-config inputs error.
func TestBuildMountSpec_Errors(t *testing.T) {
	tests := []struct {
		name   string
		b      Backend
		tenant string
		vol    string
		target string
	}{
		{"empty-tenant", Backend{Kind: BackendS3, S3Bucket: "b"}, "", "data", "/x"},
		{"empty-target", Backend{Kind: BackendS3, S3Bucket: "b"}, "t-a", "data", ""},
		{"bad-name", Backend{Kind: BackendS3, S3Bucket: "b"}, "t-a", "../x", "/x"},
		{"s3-no-bucket", Backend{Kind: BackendS3}, "t-a", "data", "/x"},
		{"nfs-no-export", Backend{Kind: BackendNFS, NFSServer: "h"}, "t-a", "data", "/x"},
		{"unknown-backend", Backend{Kind: "ftp"}, "t-a", "data", "/x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildMountSpec(tc.b, tc.tenant, tc.vol, tc.target, false); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

// UC-13b: per-tenant quota allows up to the cap and rejects beyond it; 0 = off.
func TestCheckQuota(t *testing.T) {
	tests := []struct {
		name    string
		current int
		max     int
		wantErr bool
	}{
		{"unlimited-zero", 1000, 0, false},
		{"unlimited-negative", 1000, -1, false},
		{"under-cap", 2, 5, false},
		{"at-cap", 5, 5, true},
		{"over-cap", 6, 5, true},
		{"first-of-one", 0, 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckQuota(tc.current, tc.max)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckQuota(%d,%d) err=%v, wantErr=%v", tc.current, tc.max, err, tc.wantErr)
			}
		})
	}
}
