package models

import (
	"strings"
	"testing"
)

func TestMountSpecValidate(t *testing.T) {
	good := []MountSpec{
		{Type: MountTypeS3, Source: "s3://my-bucket", Target: "/workspace"},
		{Type: MountTypeS3, Source: "bare-bucket-name", Target: "/data"},
		{Type: MountTypeNFS, Source: "nfs.internal:/exports/work", Target: "/mnt/nfs"},
		{Type: MountTypeSSHFS, Source: "ubuntu@build-host:/home/ubuntu", Target: "/home/dev"},
		{Type: MountTypeRclone, Source: "myremote:bucket/prefix", Target: "/workspace"},
	}
	for _, m := range good {
		if err := m.Validate("/usr/local/bin/toolboxd"); err != nil {
			t.Errorf("Validate(%v) returned err: %v", m, err)
		}
	}

	bad := []struct {
		name string
		m    MountSpec
	}{
		{"unknown type", MountSpec{Type: "ftp", Source: "x", Target: "/x"}},
		{"empty target", MountSpec{Type: MountTypeS3, Source: "b", Target: ""}},
		{"relative target", MountSpec{Type: MountTypeS3, Source: "b", Target: "workspace"}},
		{"unclean target", MountSpec{Type: MountTypeS3, Source: "b", Target: "/workspace/"}},
		{"dotdot target", MountSpec{Type: MountTypeS3, Source: "b", Target: "/foo/../etc"}},
		{"reserved /etc", MountSpec{Type: MountTypeS3, Source: "b", Target: "/etc"}},
		{"reserved /proc", MountSpec{Type: MountTypeS3, Source: "b", Target: "/proc"}},
		{"reserved /run", MountSpec{Type: MountTypeS3, Source: "b", Target: "/run"}},
		{"toolbox collision", MountSpec{Type: MountTypeS3, Source: "b", Target: "/usr/local/bin/toolboxd"}},
		{"empty source", MountSpec{Type: MountTypeS3, Source: "", Target: "/workspace"}},
		{"s3 source as path", MountSpec{Type: MountTypeS3, Source: "/etc/passwd", Target: "/workspace"}},
		{"nfs malformed", MountSpec{Type: MountTypeNFS, Source: "no-colon-slash", Target: "/mnt"}},
		{"sshfs malformed", MountSpec{Type: MountTypeSSHFS, Source: "no-at-sign", Target: "/mnt"}},
		{"rclone local path", MountSpec{Type: MountTypeRclone, Source: "/var/data", Target: "/workspace"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.m.Validate("/usr/local/bin/toolboxd"); err == nil {
				t.Fatalf("expected error for %v", tc.m)
			}
		})
	}
}

func TestMountSpecCredentialLimits(t *testing.T) {
	base := MountSpec{Type: MountTypeS3, Source: "b", Target: "/x"}

	// Too many keys.
	huge := base
	huge.Credentials = map[string]string{}
	for i := 0; i < MaxCredentialKeys+1; i++ {
		huge.Credentials[string(rune('a'+i%26))+strings.Repeat("k", i)] = "v"
	}
	if err := huge.Validate(""); err == nil {
		t.Fatal("expected error for too many credential keys")
	}

	// Too many bytes.
	big := base
	big.Credentials = map[string]string{"k": strings.Repeat("v", MaxCredentialBytes+1)}
	if err := big.Validate(""); err == nil {
		t.Fatal("expected error for credential payload too large")
	}

	// Null bytes rejected.
	bad := base
	bad.Credentials = map[string]string{"k": "v\x00"}
	if err := bad.Validate(""); err == nil {
		t.Fatal("expected error for null bytes in credentials")
	}
}

func TestRedactStripsCredentials(t *testing.T) {
	m := MountSpec{
		Type:        MountTypeS3,
		Source:      "s3://b",
		Target:      "/workspace",
		Options:     map[string]string{"region": "us-east-1"},
		Credentials: map[string]string{"access_key_id": "AKIA"},
	}
	r := m.Redact()
	if r.HasCredentials != true {
		t.Errorf("HasCredentials = false, want true")
	}
	if r.Source != "s3://b" {
		t.Errorf("Source = %q", r.Source)
	}
	// Make sure we didn't smuggle credentials anywhere.
	if r.Options["region"] != "us-east-1" {
		t.Errorf("Options lost: %v", r.Options)
	}
}

func TestRedactMounts(t *testing.T) {
	mounts := []MountSpec{
		{
			Source:  "s3://my-bucket",
			Target:  "/mnt/data",
			Type:    "s3",
			Options: map[string]string{"region": "us-east-1"},
			Credentials: map[string]string{
				"access_key_id":     "AKIA",
				"secret_access_key": "secret",
			},
		},
		{
			Source: "nfs://host/share",
			Target: "/mnt/nfs",
			Type:   "nfs",
		},
	}
	redacted := RedactMounts(mounts)
	if len(redacted) != 2 {
		t.Fatalf("len = %d, want 2", len(redacted))
	}
	if redacted[0].HasCredentials != true {
		t.Error("first mount should have credentials flagged")
	}
	if redacted[1].HasCredentials != false {
		t.Error("second mount should not have credentials flagged")
	}
	if redacted[0].Source != "s3://my-bucket" {
		t.Errorf("Source = %q, want s3://my-bucket", redacted[0].Source)
	}
}
