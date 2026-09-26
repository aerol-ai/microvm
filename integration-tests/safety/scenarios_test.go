// Offline validation of the committed scenario files. A scenario is a
// .tfvars + .caps.yml pair, and both halves are load-bearing in ways that
// fail SILENTLY: a capability the registry does not know gates nothing, so
// its use cases report a clean skip and the matrix goes green having tested
// less than it claims.
//
// This caught a real `gvisor-runtime` typo (the capability is `gvisor`) in
// the hetero security scenarios before they ever ran.
package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func scenarioDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.Dir(buildScript(t)), "..", "scenarios")
}

// knownCapabilities scrapes the registry rather than duplicating it, so a new
// capability needs no change here and a REMOVED one fails loudly.
func knownCapabilities(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(filepath.Dir(buildScript(t)), "..", "suite", "harness", "usecases.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`Capability\s*=\s*"([a-z0-9-]+)"`)
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = true
	}
	if len(out) < 5 {
		t.Fatalf("only scraped %d capabilities; the registry format probably changed", len(out))
	}
	return out
}

func capsFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(scenarioDir(t), "*.caps.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no scenario caps files found")
	}
	return files
}

// capsList pulls the capability names out of a caps file without a YAML
// dependency: they are one-per-line "  - name" entries under `capabilities:`.
func capsList(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	inList := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "capabilities:") {
			inList = true
			continue
		}
		if inList && strings.HasPrefix(trimmed, "- ") {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			continue
		}
		if inList && !strings.HasPrefix(line, " ") {
			inList = false
		}
	}
	return out
}

// An unknown capability gates nothing: harness.Require sees a name no use
// case asks for, every dependent case reports ⚪ skip, and the run looks
// clean. That is indistinguishable from "correctly not applicable".
func TestScenarioCapabilitiesAreKnown(t *testing.T) {
	known := knownCapabilities(t)
	for _, f := range capsFiles(t) {
		t.Run(filepath.Base(f), func(t *testing.T) {
			for _, c := range capsList(t, f) {
				if !known[c] {
					t.Errorf("unknown capability %q — it gates nothing, so its use cases will silently skip", c)
				}
			}
		})
	}
}

// Every caps file needs a tfvars twin; run.sh refuses the scenario otherwise,
// but only once someone tries to run it, which may be a flagship at $14/h.
func TestEveryScenarioHasBothHalves(t *testing.T) {
	for _, f := range capsFiles(t) {
		tfvars := strings.TrimSuffix(f, ".caps.yml") + ".tfvars"
		if _, err := os.Stat(tfvars); err != nil {
			t.Errorf("%s has no matching .tfvars", filepath.Base(f))
		}
	}
	tf, _ := filepath.Glob(filepath.Join(scenarioDir(t), "*.tfvars"))
	for _, f := range tf {
		if strings.HasSuffix(f, "domains.yml") {
			continue
		}
		caps := strings.TrimSuffix(f, ".tfvars") + ".caps.yml"
		if _, err := os.Stat(caps); err != nil {
			t.Errorf("%s has no matching .caps.yml", filepath.Base(f))
		}
	}
}

// cluster_name carries the itest marker the safety tripwire and the reaper
// both key on, and it must be unique or two scenarios share AWS resources and
// one destroy takes out the other's cluster.
func TestScenarioClusterNamesAreMarkedAndUnique(t *testing.T) {
	tf, _ := filepath.Glob(filepath.Join(scenarioDir(t), "*.tfvars"))
	re := regexp.MustCompile(`(?m)^\s*cluster_name\s*=\s*"([^"]+)"`)
	seen := map[string]string{}
	for _, f := range tf {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindStringSubmatch(string(raw))
		if m == nil {
			t.Errorf("%s sets no cluster_name", filepath.Base(f))
			continue
		}
		name := m[1]
		if !strings.Contains(name, "itest") {
			t.Errorf("%s: cluster_name %q lacks the itest marker; provision.sh will refuse it and the reaper cannot find it",
				filepath.Base(f), name)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("cluster_name %q is used by both %s and %s; they would share AWS resources",
				name, prev, filepath.Base(f))
		}
		seen[name] = filepath.Base(f)
	}
}

// A scenario that advertises audit-witness gets the -tags itestwitness
// daemon (run.sh derives it from this capability). Enterprise forces
// SB_SECRET_AUDIT_EXTERNAL_WITNESS and pkg/daemon refuses to boot without a
// non-noop Witness, so enterprise WITHOUT audit-witness is a scenario that
// cannot start at all — and it would fail 15 minutes into provisioning.
func TestEnterpriseScenariosRequestTheWitnessDaemon(t *testing.T) {
	for _, f := range capsFiles(t) {
		caps := capsList(t, f)
		hasEnterprise, hasWitness := false, false
		for _, c := range caps {
			switch c {
			case "enterprise":
				hasEnterprise = true
			case "audit-witness":
				hasWitness = true
			}
		}
		if hasEnterprise && !hasWitness {
			t.Errorf("%s advertises enterprise without audit-witness; the daemon would refuse to boot",
				filepath.Base(f))
		}
	}
}
