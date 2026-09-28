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

// source and options are stored and replicated in the clear; a credential
// placed there (an rclone connection-string parameter, a mount-tool flag, an
// NFS option, an invented key) would be replicated unsealed. Intake refuses
// credential-shaped names and points at the credentials field.
func TestMountSpecValidateRefusesCredentialsOutsideCredentials(t *testing.T) {
	const toolbox = "/usr/local/bin/toolboxd"
	rejected := []struct {
		name string
		m    MountSpec
		want string
	}{
		{"s3 extra_args secret flag", MountSpec{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: map[string]string{"extra_args": "--allow-delete --s3-secret-access-key=XYZ"}}, "options.extra_args flag"},
		{"s3 extra_args token flag space form", MountSpec{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: map[string]string{"extra_args": "--session-token ABC"}}, "options.extra_args flag"},
		{"options key password", MountSpec{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: map[string]string{"password": "x"}}, "options key"},
		{"options key mixed case", MountSpec{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: map[string]string{"Access-Key-Id": "x"}}, "options key"},
		{"nfs opts credential entry", MountSpec{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"opts": "vers=4,password=x"}}, "options.opts entry"},
		{"rclone backend connection string", MountSpec{Type: MountTypeRclone, Source: ":s3,access_key_id=A,secret_access_key=B:bucket", Target: "/d"}, "rclone source parameter"},
		{"rclone remote override token", MountSpec{Type: MountTypeRclone, Source: "drive,token=abc:path", Target: "/d"}, "rclone source parameter"},
		{"rclone remote override pass", MountSpec{Type: MountTypeRclone, Source: "sftp,pass=x:path", Target: "/d"}, "rclone source parameter"},
		{"rclone key_file_pass", MountSpec{Type: MountTypeRclone, Source: "sftp,key_file_pass=x:path", Target: "/d"}, "rclone source parameter"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.m.Validate(toolbox); err != nil {
				t.Fatalf("the shape is valid; only the placement rule must refuse it: %v", err)
			}
			err := tc.m.ValidateSecretsPlacement()
			if err == nil {
				t.Fatalf("accepted %+v", tc.m)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "put it in credentials") {
				t.Fatalf("error %q must name %s and point at credentials", err, tc.want)
			}
		})
	}
	if err := (*MountSpec)(nil).ValidateSecretsPlacement(); err == nil {
		t.Fatal("nil spec accepted")
	}
	accepted := []MountSpec{
		{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: map[string]string{"region": "us-east-1", "endpoint": "https://s3.example", "extra_args": "--sse aws:kms --sse-kms-key-id arn:aws:kms:us-east-1:1:key/abc --allow-delete --expected-bucket-owner 123"}},
		{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"opts": "vers=4.1,sec=krb5,hard,timeo=600,nolock"}},
		{Type: MountTypeRclone, Source: "myremote,region=eu-west-1:bucket/prefix", Target: "/d", Credentials: map[string]string{"rclone_conf": "[myremote]\ntype = s3\n"}},
		{Type: MountTypeRclone, Source: ":s3,provider=AWS,env_auth=true:bucket", Target: "/d"},
		{Type: MountTypeRclone, Source: "myremote:bucket", Target: "/d", Options: map[string]string{"vfs_cache_mode": "full"}},
		{Type: MountTypeS3, Source: "bucket", Target: "/d", Credentials: map[string]string{"access_key_id": "A", "secret_access_key": "B", "session_token": "C"}},
	}
	for _, m := range accepted {
		if err := m.Validate(toolbox); err != nil {
			t.Errorf("Validate(%+v) = %v, want accepted", m, err)
		}
		if err := m.ValidateSecretsPlacement(); err != nil {
			t.Errorf("ValidateSecretsPlacement(%+v) = %v, want accepted", m, err)
		}
	}
	names := map[string]bool{
		"--s3-secret-access-key": true, "SECRET-ACCESS-KEY": true, "session_token": true, "pass": true, "key_file_pass": true,
		"client_secret": true, "sas_url": true, "private-key": true, "api_key": true, "customer-key": true,
		"sec": false, "region": false, "extra_args": false, "opts": false, "vfs_cache_mode": false, "sse-kms-key-id": false,
		"expected-bucket-owner": false, "passthrough": false, "bypass": false, "": false, "--": false,
	}
	for name, want := range names {
		if got := isMountCredentialName(name); got != want {
			t.Errorf("isMountCredentialName(%q) = %v, want %v", name, got, want)
		}
	}
}
