package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// packaging/eks/aerolvm-eks.yaml is the one-click EKS stack. Its installer
// is a bash script inside a CodeBuild buildspec inside the template, and
// nothing runs it until someone launches the stack, 30 minutes and real AWS
// money later. A typo in a variable name only shows there, as set -u
// stopping the install. These keep the script, its inputs and its pins
// honest in between.

func eksStack(t *testing.T) *yaml.Node {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "packaging", "eks", "aerolvm-eks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("aerolvm-eks.yaml: %v", err)
	}
	return &doc
}

// node walks mapping keys; CloudFormation's short tags (!Ref, !Sub) stay on
// the nodes and do not get in the way.
func node(n *yaml.Node, path ...string) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode {
		n = n.Content[0]
	}
	for _, key := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		n = next
	}
	return n
}

func mappingKeys(n *yaml.Node) []string {
	var keys []string
	if n != nil && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			keys = append(keys, n.Content[i].Value)
		}
	}
	return keys
}

func eksInstallerScript(t *testing.T, stack *yaml.Node) string {
	t.Helper()
	bs := node(stack, "Resources", "Installer", "Properties", "Source", "BuildSpec")
	if bs == nil {
		t.Fatal("the Installer project has no BuildSpec")
	}
	var spec struct {
		Phases struct {
			Build struct {
				Commands []string `yaml:"commands"`
			} `yaml:"build"`
		} `yaml:"phases"`
	}
	if err := yaml.Unmarshal([]byte(bs.Value), &spec); err != nil {
		t.Fatalf("the BuildSpec is not YAML: %v", err)
	}
	if len(spec.Phases.Build.Commands) != 1 {
		t.Fatalf("the BuildSpec has %d build commands, want the one installer script", len(spec.Phases.Build.Commands))
	}
	return spec.Phases.Build.Commands[0]
}

func TestEKSStackInstallerIsValidBash(t *testing.T) {
	script := eksInstallerScript(t, eksStack(t))
	path := filepath.Join(t.TempDir(), "installer.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Log("shellcheck is not installed; only bash -n ran")
		return
	}
	if out, err := exec.Command("shellcheck", "-s", "bash", path).CombinedOutput(); err != nil {
		t.Fatalf("shellcheck: %v\n%s", err, out)
	}
}

func TestEKSStackHelperIsValidPython(t *testing.T) {
	code := node(eksStack(t), "Resources", "Helper", "Properties", "Code", "ZipFile")
	if code == nil {
		t.Fatal("the Helper Lambda has no inline code")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	path := filepath.Join(t.TempDir(), "index.py")
	if err := os.WriteFile(path, []byte(code.Value), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("python3", "-c", "import ast, sys; ast.parse(open(sys.argv[1]).read())", path).CombinedOutput(); err != nil {
		t.Fatalf("the Helper Lambda is not valid Python: %v\n%s", err, out)
	}
}

// Every upper-case variable the installer reads must be set by the script,
// the Install custom resource, the CodeBuild project, the Helper Lambda or
// CodeBuild itself. The script runs under set -u, so a missing one stops a
// live install halfway.
func TestEKSStackInstallerInputsAreAllProvided(t *testing.T) {
	stack := eksStack(t)
	script := eksInstallerScript(t, stack)

	have := map[string]bool{
		// Set by CodeBuild in every build.
		"AWS_REGION": true, "CODEBUILD_BUILD_ID": true,
	}
	for _, k := range mappingKeys(node(stack, "Resources", "Install", "Properties")) {
		have[k] = true
	}
	if env := node(stack, "Resources", "Installer", "Properties", "Environment", "EnvironmentVariables"); env != nil {
		for _, v := range env.Content {
			if n := node(v, "Name"); n != nil {
				have[n.Value] = true
			}
		}
	}
	helper := node(stack, "Resources", "Helper", "Properties", "Code", "ZipFile").Value
	for _, m := range regexp.MustCompile(`\b([A-Z][A-Z_]+)=(?:event|physical_id)\b`).FindAllStringSubmatch(helper, -1) {
		have[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`(?m)(?:^|[\s;(])([A-Z][A-Z0-9_]*)=`).FindAllStringSubmatch(script, -1) {
		have[m[1]] = true
	}

	var missing []string
	for _, m := range regexp.MustCompile(`\$\{?([A-Z][A-Z0-9_]*)`).FindAllStringSubmatch(script, -1) {
		if !have[m[1]] && !slices.Contains(missing, m[1]) {
			missing = append(missing, m[1])
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the installer reads %v, which nothing sets", missing)
	}
}

// The installer's Karpenter and cert-manager are the ones the live EKS runs
// proved (integration-tests/k8s). Bump them there first.
func TestEKSStackPinsMatchTheLiveHarness(t *testing.T) {
	root := repoRoot(t)
	script := eksInstallerScript(t, eksStack(t))
	for _, pin := range []struct{ name, harness string }{
		{"KARPENTER_VERSION", filepath.Join("integration-tests", "k8s", "cluster.sh")},
		{"CERT_MANAGER_VERSION", filepath.Join("integration-tests", "k8s", "cell.sh")},
	} {
		re := regexp.MustCompile(`(?m)^\s*` + pin.name + `=(\S+)\s*$`)
		raw, err := os.ReadFile(filepath.Join(root, pin.harness))
		if err != nil {
			t.Fatal(err)
		}
		want := re.FindStringSubmatch(string(raw))
		got := re.FindStringSubmatch(script)
		if want == nil || got == nil {
			t.Fatalf("%s: harness %v, installer %v", pin.name, want, got)
		}
		if got[1] != want[1] {
			t.Errorf("the installer pins %s=%s; the live harness (%s) proved %s", pin.name, got[1], pin.harness, want[1])
		}
	}
}

// The stack installs the chart's release unless the person changes it, and
// the release workflow stamps the shipped copy with the release's own tag.
func TestEKSStackVersionDefault(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "packaging", "eks", "aerolvm-eks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	marked := regexp.MustCompile(`(?m)^    Default: "([^"]+)" # release-version$`).FindAllStringSubmatch(string(raw), -1)
	if len(marked) != 1 {
		t.Fatalf("want one `    Default: \"X.Y.Z\" # release-version` line for release.yml to stamp, found %d", len(marked))
	}
	if d := node(eksStack(t), "Parameters", "AerolvmVersion", "Default"); d == nil || d.Value != marked[0][1] {
		t.Errorf("the release-version line is not AerolvmVersion's default")
	}
	chart, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	app := regexp.MustCompile(`(?m)^appVersion:\s*"?v([^"\s]+)"?\s*$`).FindSubmatch(chart)
	if app == nil || string(app[1]) != marked[0][1] {
		t.Errorf("AerolvmVersion defaults to %s; the chart's appVersion is %s. Bump them together.", marked[0][1], app)
	}

	wf, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"packaging/eks/aerolvm-eks.yaml", "# release-version", "dist/aerolvm-eks.yaml"} {
		if !strings.Contains(string(wf), want) {
			t.Errorf("release.yml does not mention %s: the stack must ship with each release", want)
		}
	}
}

// TestEKSStackLaunchCopyWaitsForTheChart pins the job that moves the
// Launch Stack button's copy (aerolvm/latest/aerolvm-eks.yaml). That stack
// installs the release's Helm chart, and the release job does not wait for
// the chart job, so a copy made any earlier would point every new stack at
// a chart that may never be published.
func TestEKSStackLaunchCopyWaitsForTheChart(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	const dest = `"s3://${MIRROR_BUCKET}/aerolvm/latest/aerolvm-eks.yaml"`
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if strings.Contains(s.Run, "aerolvm/latest/aerolvm-eks.yaml") && name != "eks-launch-stack" {
				t.Errorf("job %s writes the Launch Stack copy; only eks-launch-stack may, after the chart job", name)
			}
		}
	}
	job, ok := wf.Jobs["eks-launch-stack"]
	if !ok {
		t.Fatal("release.yml has no eks-launch-stack job")
	}
	var needs []string
	switch n := job.Needs.(type) {
	case string:
		needs = []string{n}
	case []any:
		for _, v := range n {
			needs = append(needs, fmt.Sprint(v))
		}
	}
	for _, want := range []string{"chart", "mirror"} {
		if !slices.Contains(needs, want) {
			t.Errorf("eks-launch-stack needs %v; it must need %s", needs, want)
		}
	}
	if !strings.Contains(job.If, "vars.AEROLVM_MIRROR_ROLE_ARN") {
		t.Errorf("eks-launch-stack if = %q; it must be skipped when the mirror role is unset", job.If)
	}
	if len(job.Permissions) != 2 || job.Permissions["contents"] != "read" || job.Permissions["id-token"] != "write" {
		t.Errorf("eks-launch-stack permissions = %v, want exactly contents: read, id-token: write", job.Permissions)
	}
	check := slices.IndexFunc(job.Steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "checksums.txt") && strings.Contains(s.Run, "sha256sum --check --strict")
	})
	copyStep := slices.IndexFunc(job.Steps, func(s workflowStep) bool { return strings.Contains(s.Run, dest) })
	if check < 0 || copyStep < 0 || check > copyStep {
		t.Fatalf("eks-launch-stack must check the stack against checksums.txt (step %d) before copying it to %s (step %d)", check, dest, copyStep)
	}
	if run := job.Steps[copyStep].Run; !strings.Contains(run, `gh release view --json tagName`) || !strings.Contains(run, `"$latest" != "$VERSION"`) {
		t.Errorf("the copy step does not check that this release is GitHub's latest:\n%s", run)
	}
}

// The values the installer writes name only settings the chart has, so a
// renamed chart setting fails here and not in a customer's install.
func TestEKSStackValuesNameChartSettings(t *testing.T) {
	root := repoRoot(t)
	script := eksInstallerScript(t, eksStack(t))
	m := regexp.MustCompile(`(?s)cat > /tmp/values\.yaml <<EOF\n(.*?)\nEOF\n`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("the installer writes no /tmp/values.yaml")
	}
	body := regexp.MustCompile(`\$\{[A-Za-z0-9_]+\}`).ReplaceAllString(m[1], "x")
	var values yaml.Node
	if err := yaml.Unmarshal([]byte(body), &values); err != nil {
		t.Fatalf("the installer's values are not YAML: %v", err)
	}
	chart, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var walk func(n *yaml.Node, path []string)
	walk = func(n *yaml.Node, path []string) {
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := append(slices.Clone(path), n.Content[i].Value)
			indent := strings.Repeat("  ", len(p)-1)
			if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(indent+p[len(p)-1]) + `:`).Match(chart) {
				t.Errorf("the installer sets %s, which charts/aerolvm/values.yaml does not have", strings.Join(p, "."))
			}
			walk(n.Content[i+1], p)
		}
	}
	walk(values.Content[0], nil)
}

// CloudFormation deletes a resource as soon as nothing that depends on it
// remains, so a resource nothing depends on goes in the first seconds of a
// stack delete, while the installer is still removing AerolVM. The first
// live delete lost PublicDefaultRoute that way: the NAT gateway had no way
// out, and the installer's delete path hung with no network. Every resource
// but the Install custom resource (the last thing made, the first deleted)
// must have a dependent. AdminAccess is the one other: no part of the
// delete needs a person's access.
func TestEKSStackEveryResourceOutlivesTheInstaller(t *testing.T) {
	stack := eksStack(t)
	resources := node(stack, "Resources")
	names := mappingKeys(resources)
	dependents := map[string][]string{}
	subRef := regexp.MustCompile(`\$\{([A-Za-z0-9]+)(?:\.[A-Za-z0-9.]+)?\}`)
	var refs func(n *yaml.Node, add func(string))
	refs = func(n *yaml.Node, add func(string)) {
		switch n.Tag {
		case "!Ref":
			add(n.Value)
		case "!GetAtt":
			add(strings.SplitN(n.Value, ".", 2)[0])
		case "!Sub":
			s := n.Value
			if n.Kind == yaml.SequenceNode && len(n.Content) > 0 {
				s = n.Content[0].Value
			}
			for _, m := range subRef.FindAllStringSubmatch(s, -1) {
				add(m[1])
			}
		}
		for _, c := range n.Content {
			refs(c, add)
		}
	}
	for i := 0; i+1 < len(resources.Content); i += 2 {
		from, body := resources.Content[i].Value, resources.Content[i+1]
		add := func(to string) {
			if to != from && slices.Contains(names, to) && !slices.Contains(dependents[to], from) {
				dependents[to] = append(dependents[to], from)
			}
		}
		refs(body, add)
		if d := node(body, "DependsOn"); d != nil {
			if d.Kind == yaml.ScalarNode {
				add(d.Value)
			}
			for _, c := range d.Content {
				add(c.Value)
			}
		}
	}
	for _, name := range names {
		if name == "Install" || name == "AdminAccess" {
			continue
		}
		if len(dependents[name]) == 0 {
			t.Errorf("nothing depends on %s, so a stack delete removes it while the installer still runs; add it to a DependsOn (NetworkCleanup's, for network parts)", name)
		}
	}
	if len(dependents["Install"]) != 0 {
		t.Errorf("%v depend on Install; it must be the first thing a delete removes", dependents["Install"])
	}
}

// The chart is told each worker type's size; a type with no size would
// stop the stack at FindInMap.
func TestEKSStackWorkerTypesHaveSizes(t *testing.T) {
	stack := eksStack(t)
	allowed := node(stack, "Parameters", "WorkerInstanceType", "AllowedValues")
	sizes := mappingKeys(node(stack, "Mappings", "WorkerMachine"))
	if allowed == nil || len(allowed.Content) == 0 {
		t.Fatal("WorkerInstanceType has no AllowedValues")
	}
	for _, v := range allowed.Content {
		if !slices.Contains(sizes, v.Value) {
			t.Errorf("worker type %s has no WorkerMachine size", v.Value)
		}
	}
	if d := node(stack, "Parameters", "WorkerInstanceType", "Default"); d == nil || !slices.Contains(sizes, d.Value) {
		t.Errorf("the default worker type has no size")
	}
}

// TestEKSStackKarpenterRoleIsScoped keeps Karpenter's role to its reference
// policy's limits. Karpenter's service account is a pod's credential, so an
// unscoped write there reaches the whole account: CreateTags on any
// instance let it tag a stranger's machine as this cluster's and then
// terminate it, instance-profile writes on any profile could strip the IAM
// role from unrelated machines, and ssm:GetParameter on "*" reads
// SecureString secrets.
func TestEKSStackKarpenterRoleIsScoped(t *testing.T) {
	policies := node(eksStack(t), "Resources", "KarpenterRole", "Properties", "Policies")
	if policies == nil || policies.Kind != yaml.SequenceNode || len(policies.Content) == 0 {
		t.Fatal("KarpenterRole has no inline policies")
	}
	type statement struct {
		Sid       string
		Effect    string
		Action    any
		Resource  any
		Condition map[string]any
	}
	list := func(v any) []string {
		switch v := v.(type) {
		case string:
			return []string{v}
		case []any:
			out := make([]string, 0, len(v))
			for _, s := range v {
				out = append(out, fmt.Sprint(s))
			}
			return out
		}
		return nil
	}
	readOnly := regexp.MustCompile(`^[a-z0-9-]+:(Describe|Get|List)[A-Za-z]*$`)
	mustBeConditioned := regexp.MustCompile(`^(ec2:(CreateTags|TerminateInstances|DeleteLaunchTemplate)|iam:(Create|Tag|AddRoleTo|RemoveRoleFrom|Delete)InstanceProfile)$`)
	seen := 0
	for _, p := range policies.Content {
		doc := node(p, "PolicyDocument")
		if doc == nil {
			t.Fatal("a KarpenterRole policy has no PolicyDocument")
		}
		var body struct{ Statement []statement }
		if err := json.Unmarshal([]byte(doc.Value), &body); err != nil {
			t.Fatalf("KarpenterRole policy is not JSON: %v", err)
		}
		for _, s := range body.Statement {
			seen++
			actions, resources := list(s.Action), list(s.Resource)
			if s.Effect != "Allow" {
				continue
			}
			for _, a := range actions {
				if slices.Contains(resources, "*") && !readOnly.MatchString(a) && len(s.Condition) == 0 {
					t.Errorf("%s: %s on every resource with no condition", s.Sid, a)
				}
				if mustBeConditioned.MatchString(a) && len(s.Condition) == 0 {
					t.Errorf("%s: %s has no condition; limit it to this cluster's tags", s.Sid, a)
				}
				if a == "ssm:GetParameter" {
					for _, r := range resources {
						if !strings.HasSuffix(r, ":parameter/aws/service/*") {
							t.Errorf("%s: ssm:GetParameter on %s; Karpenter needs only parameter/aws/service/*", s.Sid, r)
						}
					}
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("KarpenterRole's policies have no statements")
	}
}
