package safety

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The chart's default image tag is its appVersion (charts/aerolvm/Chart.yaml),
// so a chart that still names an older release installs that release's
// images. v0.7.2 and v0.7.3 shipped with the chart on v0.7.1 (RELEASING.md
// says to bump it first; nothing checked). The release list the docs sync
// after each release (docs/src/data/releases.json) is the record: the chart
// may name a newer release (bumped ahead of publishing), never an older one.
func TestChartAppVersionIsNotBehindTheLatestRelease(t *testing.T) {
	root := repoRoot(t)
	chart, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^appVersion:\s*"?(v\d+\.\d+\.\d+)"?\s*$`).FindSubmatch(chart)
	if m == nil {
		t.Fatal("Chart.yaml has no appVersion vX.Y.Z")
	}
	app := string(m[1])
	raw, err := os.ReadFile(filepath.Join(root, "docs", "src", "data", "releases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var releases []struct {
		Tag        string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(raw, &releases); err != nil {
		t.Fatal(err)
	}
	latest := ""
	for _, r := range releases {
		if !r.Prerelease && semverParts(r.Tag) != nil && (latest == "" || semverLess(latest, r.Tag)) {
			latest = r.Tag
		}
	}
	if latest == "" {
		t.Fatal("releases.json lists no release")
	}
	if semverLess(app, latest) {
		t.Fatalf("charts/aerolvm/Chart.yaml appVersion is %s, but %s is released: a fresh install would pull %s's images. Set appVersion to %s.", app, latest, app, latest)
	}
}

func semverParts(v string) []int {
	m := regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`).FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

func semverLess(a, b string) bool {
	pa, pb := semverParts(a), semverParts(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}
