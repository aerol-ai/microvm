package safety

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release workflow's `mirror` job copies every release file to the
// public download mirror (s3://aerolvm-downloads/aerolvm/<tag>/) with AWS
// credentials it gets through GitHub OIDC. These tests pin the parts that
// keep that safe: the tag is checked before it becomes part of an S3 key,
// the files are checked against checksums.txt before they are copied, the
// job holds no write access to the repository, and the IAM role it assumes
// can only write under aerolvm/ and only for this repository's v* tags.

// repoRootDir is the repository root, found the way
// TestTerraformReleaseURLsNameShippedAssets finds it.
func repoRootDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.Dir(buildScript(t)), "..", "..")
}

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Needs       any               `yaml:"needs"`
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

func TestReleaseMirrorJob(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRootDir(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	job, ok := wf.Jobs["mirror"]
	if !ok {
		t.Fatal("release.yml has no mirror job")
	}

	if needs, _ := job.Needs.(string); needs != "release" {
		t.Errorf("mirror needs %v, want release: it must run after the GitHub release is published, never hold it back", job.Needs)
	}
	if !strings.Contains(job.If, "vars.AEROLVM_MIRROR_ROLE_ARN") {
		t.Errorf("mirror if = %q; it must be skipped when AEROLVM_MIRROR_ROLE_ARN is unset (forks, before setup)", job.If)
	}
	wantPerms := map[string]string{"contents": "read", "id-token": "write"}
	if len(job.Permissions) != len(wantPerms) {
		t.Errorf("mirror permissions = %v, want exactly %v", job.Permissions, wantPerms)
	}
	for k, v := range wantPerms {
		if job.Permissions[k] != v {
			t.Errorf("mirror permissions[%s] = %q, want %q", k, job.Permissions[k], v)
		}
	}
	if job.Env["MIRROR_BUCKET"] != "aerolvm-downloads" {
		t.Errorf("MIRROR_BUCKET = %q, want aerolvm-downloads", job.Env["MIRROR_BUCKET"])
	}

	stepIndex := func(match func(workflowStep) bool) int {
		return slices.IndexFunc(job.Steps, match)
	}
	tagCheck := stepIndex(func(s workflowStep) bool {
		return strings.Contains(s.Run, `"$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+`)
	})
	checksums := stepIndex(func(s workflowStep) bool {
		return strings.Contains(s.Run, "sha256sum --check --strict checksums.txt")
	})
	creds := stepIndex(func(s workflowStep) bool {
		return strings.HasPrefix(s.Uses, "aws-actions/configure-aws-credentials@")
	})
	sync := stepIndex(func(s workflowStep) bool {
		return strings.Contains(s.Run, `aws s3 sync dist/ "s3://${MIRROR_BUCKET}/aerolvm/${VERSION}/"`)
	})
	served := stepIndex(func(s workflowStep) bool {
		return strings.Contains(s.Run, "cmp -s - dist/checksums.txt")
	})
	latest := stepIndex(func(s workflowStep) bool {
		return strings.Contains(s.Run, `"s3://${MIRROR_BUCKET}/aerolvm/latest.txt"`)
	})
	for name, i := range map[string]int{"tag check": tagCheck, "checksum check": checksums, "AWS credentials": creds, "S3 sync": sync, "served-checksums check": served, "latest.txt": latest} {
		if i < 0 {
			t.Fatalf("mirror job has no %s step", name)
		}
	}
	if tagCheck != 0 {
		t.Errorf("the tag check is step %d; it must run first, before the tag reaches gh or an S3 key", tagCheck)
	}
	if !(checksums < creds && creds < sync) {
		t.Errorf("steps out of order (checksums %d, credentials %d, sync %d): files must be checked before any credentials or upload", checksums, creds, sync)
	}
	// install.sh reads latest.txt to find the mirror's latest release, so it
	// must move only after every file is up and checked, and only for the
	// release GitHub calls latest.
	if !(sync < served && served < latest) {
		t.Errorf("latest.txt is written at step %d, before the sync (%d) or the served-checksums check (%d) finished", latest, sync, served)
	}
	if l := job.Steps[latest].Run; !strings.Contains(l, `gh release view --json tagName`) || !strings.Contains(l, `"$latest" != "$VERSION"`) {
		t.Errorf("the latest.txt step does not check that this release is GitHub's latest:\n%s", l)
	}
	c := job.Steps[creds]
	if !regexp.MustCompile(`^aws-actions/configure-aws-credentials@[0-9a-f]{40}$`).MatchString(c.Uses) {
		t.Errorf("credentials action %q is not pinned to a full commit SHA", c.Uses)
	}
	if c.With["role-to-assume"] != "${{ vars.AEROLVM_MIRROR_ROLE_ARN }}" {
		t.Errorf("role-to-assume = %q, want the AEROLVM_MIRROR_ROLE_ARN variable (no account id in the repo)", c.With["role-to-assume"])
	}
}

type iamPolicy struct {
	Statement []struct {
		Sid       string                    `json:"Sid"`
		Effect    string                    `json:"Effect"`
		Principal map[string]string         `json:"Principal"`
		Action    any                       `json:"Action"`
		Resource  any                       `json:"Resource"`
		Condition map[string]map[string]any `json:"Condition"`
	} `json:"Statement"`
}

func readPolicy(t *testing.T, name string) (iamPolicy, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootDir(t), "setup", "release-mirror", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var p iamPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return p, string(raw)
}

func TestReleaseMirrorRoleTrust(t *testing.T) {
	p, raw := readPolicy(t, "trust-policy.json")
	if regexp.MustCompile(`\b\d{12}\b`).MatchString(raw) {
		t.Error("trust-policy.json holds a 12-digit account id; keep the ACCOUNT_ID placeholder (create-role.sh fills it in)")
	}
	if len(p.Statement) != 1 {
		t.Fatalf("trust policy has %d statements, want 1", len(p.Statement))
	}
	s := p.Statement[0]
	if s.Effect != "Allow" || s.Action != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("trust statement = %s %v, want Allow sts:AssumeRoleWithWebIdentity", s.Effect, s.Action)
	}
	if s.Principal["Federated"] != "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com" {
		t.Errorf("trust principal = %v, want the GitHub OIDC provider", s.Principal)
	}
	if aud := s.Condition["StringEquals"]["token.actions.githubusercontent.com:aud"]; aud != "sts.amazonaws.com" {
		t.Errorf("aud condition = %v, want sts.amazonaws.com", aud)
	}
	if sub := s.Condition["StringLike"]["token.actions.githubusercontent.com:sub"]; sub != "repo:aerol-ai/microvm:ref:refs/tags/v*" {
		t.Errorf("sub condition = %v, want only this repository's v* tags", sub)
	}
}

func TestReleaseMirrorRolePermissions(t *testing.T) {
	p, _ := readPolicy(t, "permissions-policy.json")
	got := map[string]string{}
	for _, s := range p.Statement {
		action, _ := s.Action.(string)
		resource, _ := s.Resource.(string)
		if s.Effect != "Allow" || action == "" || resource == "" || strings.Contains(action, "*") {
			t.Fatalf("statement %q = %s %v on %v; want one plain Allow action on one resource", s.Sid, s.Effect, s.Action, s.Resource)
		}
		got[action] = resource
		if action == "s3:ListBucket" {
			prefix, _ := s.Condition["StringLike"]["s3:prefix"].([]any)
			if len(prefix) != 1 || prefix[0] != "aerolvm/*" {
				t.Errorf("ListBucket prefix condition = %v, want only aerolvm/*", s.Condition)
			}
		}
	}
	want := map[string]string{
		"s3:PutObject":  "arn:aws:s3:::aerolvm-downloads/aerolvm/*",
		"s3:ListBucket": "arn:aws:s3:::aerolvm-downloads",
	}
	if len(got) != len(want) {
		t.Errorf("role allows %v, want exactly %v (no delete, no other prefix or bucket)", got, want)
	}
	for a, r := range want {
		if got[a] != r {
			t.Errorf("%s on %q, want %q", a, got[a], r)
		}
	}
}
