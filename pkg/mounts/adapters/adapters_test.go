package adapters

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAdapters_DefaultMap(t *testing.T) {
	a := Adapters()
	if len(a) != 4 {
		t.Fatalf("len(Adapters) = %d, want 4", len(a))
	}
	if _, ok := a[models.MountTypeS3]; !ok {
		t.Fatal("missing S3 adapter")
	}
	if _, ok := a[models.MountTypeNFS]; !ok {
		t.Fatal("missing NFS adapter")
	}
	if _, ok := a[models.MountTypeSSHFS]; !ok {
		t.Fatal("missing SSHFS adapter")
	}
	if _, ok := a[models.MountTypeRclone]; !ok {
		t.Fatal("missing Rclone adapter")
	}
}

func TestS3Build(t *testing.T) {
	plan, err := (S3{}).Build("sb-1", 3, models.MountSpec{
		Source:   "s3://bucket/prefix/sub",
		ReadOnly: true,
		Credentials: map[string]string{
			"access_key_id":     "AKIA...",
			"secret_access_key": "secret",
			"session_token":     "token",
		},
		Options: map[string]string{
			"region":     "us-east-1",
			"endpoint":   "https://s3.example.com",
			"extra_args": "--allow-delete --uid 1000",
		},
	}, "/mnt/target", "/creds")
	if err != nil {
		t.Fatalf("S3.Build: %v", err)
	}
	wantPrefix := []string{"mount-s3", "bucket", "/mnt/target", "--foreground", "--profile", "sandbox", "--prefix", "prefix/sub"}
	if !reflect.DeepEqual(plan.Argv[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("argv prefix mismatch: got=%v want=%v", plan.Argv[:len(wantPrefix)], wantPrefix)
	}
	if !contains(plan.Argv, "--region") || !contains(plan.Argv, "us-east-1") {
		t.Fatalf("argv missing region: %v", plan.Argv)
	}
	if !contains(plan.Argv, "--endpoint-url") || !contains(plan.Argv, "https://s3.example.com") {
		t.Fatalf("argv missing endpoint: %v", plan.Argv)
	}
	if !contains(plan.Argv, "--read-only") || !contains(plan.Argv, "--allow-delete") || !contains(plan.Argv, "--uid") || !contains(plan.Argv, "1000") {
		t.Fatalf("argv missing readonly/extra args: %v", plan.Argv)
	}
	if plan.CredFile != "/creds/sb-1-3.aws" {
		t.Fatalf("CredFile = %q, want /creds/sb-1-3.aws", plan.CredFile)
	}
	if !plan.UnlinkCred {
		t.Fatal("UnlinkCred = false, want true")
	}
	if !contains(plan.Env, "AWS_PROFILE=sandbox") {
		t.Fatalf("env missing profile: %v", plan.Env)
	}
	if !contains(plan.Env, "AWS_SHARED_CREDENTIALS_FILE=/creds/sb-1-3.aws") {
		t.Fatalf("env missing credentials path: %v", plan.Env)
	}
	cred := string(plan.CredBody)
	if !strings.Contains(cred, "[sandbox]") || !strings.Contains(cred, "aws_access_key_id = AKIA...") || !strings.Contains(cred, "aws_secret_access_key = secret") || !strings.Contains(cred, "aws_session_token = token") {
		t.Fatalf("unexpected creds file:\n%s", cred)
	}
}

// With no static keys the operator relies on an ambient instance role; the
// adapter must not pin --profile/AWS_PROFILE to an empty credentials file, which
// would shadow the ambient chain and break the mount.
func TestS3Build_InstanceRole(t *testing.T) {
	plan, err := (S3{}).Build("sb-2", 0, models.MountSpec{
		Source: "s3://bucket/data",
	}, "/mnt/target", "/creds")
	if err != nil {
		t.Fatalf("S3.Build: %v", err)
	}
	if contains(plan.Argv, "--profile") {
		t.Fatalf("argv should omit --profile for instance-role creds: %v", plan.Argv)
	}
	if len(plan.Env) != 0 {
		t.Fatalf("env should be empty for instance-role creds: %v", plan.Env)
	}
	if plan.CredFile != "" || len(plan.CredBody) != 0 || plan.UnlinkCred {
		t.Fatalf("no credentials file expected: %+v", plan)
	}
}

func TestS3Build_MissingBucket(t *testing.T) {
	if _, err := (S3{}).Build("sb", 0, models.MountSpec{Source: "s3://"}, "/mnt", "/creds"); err == nil {
		t.Fatal("expected error for missing bucket")
	}
}

func TestParseS3Source(t *testing.T) {
	bucket, prefix := parseS3Source(" s3://my-bucket/a/b ")
	if bucket != "my-bucket" || prefix != "a/b" {
		t.Fatalf("parseS3Source mismatch: (%q,%q)", bucket, prefix)
	}
	bucket, prefix = parseS3Source("bucket-only")
	if bucket != "bucket-only" || prefix != "" {
		t.Fatalf("parseS3Source bucket-only mismatch: (%q,%q)", bucket, prefix)
	}
}

func TestNFSBuild(t *testing.T) {
	plan, err := (NFS{}).Build("sb", 0, models.MountSpec{Source: "10.0.0.2:/exports/data", ReadOnly: true}, "/mnt/nfs", "/creds")
	if err != nil {
		t.Fatalf("NFS.Build: %v", err)
	}
	want := []string{"mount", "-t", "nfs", "-o", "ro", "10.0.0.2:/exports/data", "/mnt/nfs"}
	if !reflect.DeepEqual(plan.Argv, want) {
		t.Fatalf("NFS argv mismatch: got=%v want=%v", plan.Argv, want)
	}
	if !plan.IsKernelMount {
		t.Fatal("IsKernelMount = false, want true")
	}

	plan, err = (NFS{}).Build("sb", 0, models.MountSpec{Source: "10.0.0.2:/exports/data", ReadOnly: true, Options: map[string]string{"opts": "rw,vers=4"}}, "/mnt/nfs", "/creds")
	if err != nil {
		t.Fatalf("NFS.Build with opts: %v", err)
	}
	if got := plan.Argv[4]; got != "rw,vers=4,ro" {
		t.Fatalf("NFS opts = %q, want rw,vers=4,ro", got)
	}
}

func TestSSHFSBuild(t *testing.T) {
	plan, err := (SSHFS{}).Build("sb-1", 1, models.MountSpec{
		Source:   "user@example.com:/home/user",
		ReadOnly: true,
		Credentials: map[string]string{
			"private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
		},
	}, "/mnt/ssh", "/creds")
	if err != nil {
		t.Fatalf("SSHFS.Build: %v", err)
	}
	if plan.CredFile != "/creds/sb-1-1.id" {
		t.Fatalf("CredFile = %q, want /creds/sb-1-1.id", plan.CredFile)
	}
	if plan.UnlinkCred {
		t.Fatal("UnlinkCred = true, want false")
	}
	if !contains(plan.Argv, "sshfs") || !contains(plan.Argv, "/mnt/ssh") {
		t.Fatalf("argv missing sshfs pieces: %v", plan.Argv)
	}
	if !strings.Contains(plan.Argv[2], "IdentityFile=/creds/sb-1-1.id") || !strings.Contains(plan.Argv[2], "ro") {
		t.Fatalf("sshfs opts missing identity or ro: %q", plan.Argv[2])
	}

	if _, err := (SSHFS{}).Build("sb", 0, models.MountSpec{Source: "x"}, "/mnt", "/creds"); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestRcloneBuild(t *testing.T) {
	plan, err := (Rclone{}).Build("sb-9", 2, models.MountSpec{
		Source:   "remote:bucket/path",
		ReadOnly: true,
		Credentials: map[string]string{
			"rclone_conf": "[remote]\ntype = s3\n",
		},
		Options: map[string]string{"vfs_cache_mode": "full"},
	}, "/mnt/rclone", "/creds")
	if err != nil {
		t.Fatalf("Rclone.Build: %v", err)
	}
	if plan.CredFile != "/creds/sb-9-2.rclone.conf" {
		t.Fatalf("CredFile = %q, want /creds/sb-9-2.rclone.conf", plan.CredFile)
	}
	if !plan.UnlinkCred {
		t.Fatal("UnlinkCred = false, want true")
	}
	if !contains(plan.Argv, "--vfs-cache-mode") || !contains(plan.Argv, "full") || !contains(plan.Argv, "--read-only") {
		t.Fatalf("argv missing rclone options: %v", plan.Argv)
	}

	plan, err = (Rclone{}).Build("sb-9", 2, models.MountSpec{
		Source:      "remote:bucket/path",
		Credentials: map[string]string{"rclone_conf": "[remote]\ntype = s3\n"},
	}, "/mnt/rclone", "/creds")
	if err != nil {
		t.Fatalf("Rclone.Build default cache mode: %v", err)
	}
	if !contains(plan.Argv, "writes") {
		t.Fatalf("argv missing default vfs cache mode: %v", plan.Argv)
	}

	if _, err := (Rclone{}).Build("sb", 0, models.MountSpec{Source: "remote:x"}, "/mnt", "/creds"); err == nil {
		t.Fatal("expected missing rclone conf error")
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
