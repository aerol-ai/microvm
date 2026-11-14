package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release publishes the Helm chart to oci://ghcr.io/aerol-ai/charts/aerolvm
// (release.yml, job "chart"), and the Kubernetes guide tells readers to
// install from there. These keep the two in step, and keep the job's
// guarantees: it runs after the images (a chart naming unpushed images
// installs pods stuck pulling), it stamps appVersion from the release tag (so
// the published chart runs its own release's images even when Chart.yaml
// lags, as v0.7.2 and v0.7.3 did), and it signs and attests the chart.

func TestReleaseWorkflowPublishesHelmChart(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	job, ok := wf.Jobs["chart"]
	if !ok {
		t.Fatal("release.yml has no chart job")
	}
	if job.Needs != "images" {
		t.Errorf("the chart job needs %v; it must wait for the images job", job.Needs)
	}
	for _, perm := range []string{"packages", "id-token", "attestations"} {
		if job.Permissions[perm] != "write" {
			t.Errorf("the chart job's %s permission is %q, want write", perm, job.Permissions[perm])
		}
	}
	if job.Env["CHART_REPO"] != "ghcr.io/aerol-ai/charts" {
		t.Errorf("the chart job publishes to %q, want ghcr.io/aerol-ai/charts", job.Env["CHART_REPO"])
	}

	var runs strings.Builder
	attested := false
	for _, s := range job.Steps {
		runs.WriteString(s.Run + "\n")
		if strings.HasPrefix(s.Uses, "actions/attest-build-provenance@") && s.With["subject-name"] == "ghcr.io/aerol-ai/charts/aerolvm" {
			attested = true
		}
	}
	for _, want := range []string{
		`helm package charts/aerolvm --version "$chart_version" --app-version "$VERSION"`,
		`helm push "chart-dist/aerolvm-$chart_version.tgz" "oci://$CHART_REPO"`,
		`cosign sign --yes "$CHART_REPO/aerolvm@$CHART_DIGEST"`,
	} {
		if !strings.Contains(runs.String(), want) {
			t.Errorf("the chart job does not run %q", want)
		}
	}
	if !attested {
		t.Error("the chart job does not attest ghcr.io/aerol-ai/charts/aerolvm")
	}

	// The same Helm the chart's CI checks run (test.yml), so the release
	// never packages with a Helm the chart was not tested with.
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "test.yml"))
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`https://get\.helm\.sh/helm-(v[0-9.]+)-linux-amd64\.tar\.gz\n\s*echo "([0-9a-f]{64})  helm\.tgz"`)
	rel, test := pin.FindStringSubmatch(runs.String()), pin.FindStringSubmatch(string(ci))
	switch {
	case rel == nil:
		t.Error("the chart job does not install a checksum-pinned Helm")
	case test == nil:
		t.Error("test.yml no longer installs a checksum-pinned Helm")
	case rel[1] != test[1] || rel[2] != test[2]:
		t.Errorf("release.yml packages with Helm %s (%s), test.yml checks the chart with %s (%s)", rel[1], rel[2], test[1], test[2])
	}

	// The guide's chart reference is the one the job publishes.
	guide, err := os.ReadFile(filepath.Join(root, "docs", "src", "content", "docs", "kubernetes", "index.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), "oci://ghcr.io/aerol-ai/charts/aerolvm") {
		t.Error("the Kubernetes guide does not name oci://ghcr.io/aerol-ai/charts/aerolvm, where release.yml publishes the chart")
	}
}
