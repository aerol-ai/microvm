package adapters

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// S3 mounts an S3-compatible bucket using AWS's mountpoint-s3 binary.
// Credentials are written as an AWS shared-credentials profile file the
// binary reads at startup; the file is unlinked once the mount is ready.
type S3 struct{}

func (S3) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (Plan, error) {
	bucket, prefix := parseS3Source(spec.Source)
	if bucket == "" {
		return Plan{}, fmt.Errorf("s3 source missing bucket: %q", spec.Source)
	}

	credFile := filepath.Join(credDir, fmt.Sprintf("%s-%d.aws", sandboxID, index))
	credBody := buildAWSCredentialsFile(spec.Credentials)

	argv := []string{"mount-s3", bucket, hostTarget, "--profile", "sandbox", "--foreground"}
	if prefix != "" {
		argv = append(argv, "--prefix", strings.TrimPrefix(prefix, "/"))
	}
	if region := spec.Options["region"]; region != "" {
		argv = append(argv, "--region", region)
	}
	if endpoint := spec.Options["endpoint"]; endpoint != "" {
		argv = append(argv, "--endpoint-url", endpoint)
	}
	if spec.ReadOnly {
		argv = append(argv, "--read-only")
	}
	if extra := spec.Options["extra_args"]; extra != "" {
		// Whitespace-split; we trust the operator's image policy here. Each
		// token becomes its own argv entry to avoid shell interpretation.
		argv = append(argv, strings.Fields(extra)...)
	}

	env := []string{
		"AWS_SHARED_CREDENTIALS_FILE=" + credFile,
		"AWS_PROFILE=sandbox",
	}

	return Plan{
		Argv:       argv,
		Env:        env,
		CredFile:   credFile,
		CredBody:   credBody,
		UnlinkCred: true, // mount-s3 reads creds once at startup
	}, nil
}

func parseS3Source(source string) (bucket, prefix string) {
	source = strings.TrimSpace(source)
	source = strings.TrimPrefix(source, "s3://")
	if i := strings.Index(source, "/"); i >= 0 {
		return source[:i], source[i+1:]
	}
	return source, ""
}

func buildAWSCredentialsFile(creds map[string]string) []byte {
	var b strings.Builder
	b.WriteString("[sandbox]\n")
	if v := creds["access_key_id"]; v != "" {
		b.WriteString("aws_access_key_id = " + v + "\n")
	}
	if v := creds["secret_access_key"]; v != "" {
		b.WriteString("aws_secret_access_key = " + v + "\n")
	}
	if v := creds["session_token"]; v != "" {
		b.WriteString("aws_session_token = " + v + "\n")
	}
	return []byte(b.String())
}
