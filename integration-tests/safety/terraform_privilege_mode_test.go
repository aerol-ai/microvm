package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Terraform/privilege_mode.tf decides what privilege_mode: split in
// config/cluster.yml runs on VMs, and validate_cluster_ops (locals.tf) fails
// the plan with its split_problems. A plan of the real module needs the AWS
// and Cloudflare providers, so these tests load that file, unchanged, into a
// fixture module whose variables stand in for the locals it reads, and run
// terraform on it offline: no providers, no state, nothing in AWS.

// splitCase is one cluster.yml and tfvars, from the defaults up.
type splitCase struct {
	mode        string            // privilege_mode
	docker      bool              // container_engine: docker
	oldJoin     bool              // one_line_join = false
	noNetnsPool bool              // containerd.native_netns_pool_enabled: false
	wasm        bool              // wasm.enabled
	wasmModules string            // wasm.modules_dir; "" is cluster.yml's
	firecracker bool              // a node with with_firecracker
	isolate     bool              // a node with with_isolate
	fc          map[string]string // var.firecracker fields, as HCL values

	// want is the start of each split_problems line, in order.
	want []string
	// wantKernel is SB_FIRECRACKER_KERNEL, when not "".
	wantKernel string
	// wantJailer is SB_JAILER_UID and SB_JAILER_GID: "null" writes none.
	wantJailer string
}

const (
	pEngine   = "container_engine must be containerd"
	pJoin     = "one_line_join must be true"
	pNetns    = "containerd.native_netns_pool_enabled must be true"
	pJailer   = "firecracker.use_jailer must be true"
	pChroot   = "firecracker.jailer_chroot_base must be /srv/jailer"
	pKernel   = "firecracker.kernel_path must not be in /var/lib/sandboxd or /run/sandboxd"
	pAgentDir = "firecracker.run_dir, firecracker.templates_dir, wasm.modules_dir and wasm.cache_dir must be in /var/lib/sandboxd or /run/sandboxd"

	singleKernel = "/var/lib/sandboxd/firecracker/vmlinux"
	splitKernel  = "/usr/local/lib/aerolvm-firecracker/vmlinux"
)

var splitCases = map[string]splitCase{
	// Single is untouched: whatever it ran before, it runs.
	"single_every_runtime": {mode: "single", firecracker: true, isolate: true, wasm: true,
		fc:         map[string]string{"use_jailer": "false", "jailer_chroot_base": `"/data/jailer"`},
		wantKernel: singleKernel, wantJailer: "1000"},
	"single_docker_old_join": {mode: "single", docker: true, oldJoin: true, noNetnsPool: true},

	// Split runs every runtime with the defaults and the shipped cluster.yml.
	"split_firecracker": {mode: "split", firecracker: true, wantKernel: splitKernel, wantJailer: "null"},
	"split_isolate":     {mode: "split", isolate: true},
	"split_wasm":        {mode: "split", wasm: true},
	"split_every_runtime": {mode: "split", firecracker: true, isolate: true, wasm: true,
		wantKernel: splitKernel, wantJailer: "null"},
	// What the operator set is kept.
	"split_own_kernel": {mode: "split", firecracker: true,
		fc: map[string]string{"kernel_path": `"/opt/aerolvm/vmlinux"`}, wantKernel: "/opt/aerolvm/vmlinux"},
	"split_own_jailer_ids": {mode: "split", firecracker: true,
		fc: map[string]string{"jailer_uid": "2000", "jailer_gid": "2000"}, wantJailer: "2000"},
	// Firecracker settings with no Firecracker node change nothing.
	"split_firecracker_settings_no_node": {mode: "split",
		fc: map[string]string{"use_jailer": "false", "jailer_chroot_base": `"/data/jailer"`, "kernel_path": `"/run/sandboxd/vmlinux"`}},
	"split_wasm_off_own_dirs": {mode: "split", wasmModules: "/srv/wasm/modules"},

	// What split still refuses, one at a time.
	"split_docker":          {mode: "split", docker: true, want: []string{pEngine}},
	"split_old_join":        {mode: "split", oldJoin: true, want: []string{pJoin}},
	"split_no_netns_pool":   {mode: "split", noNetnsPool: true, want: []string{pNetns}},
	"split_unjailed":        {mode: "split", firecracker: true, fc: map[string]string{"use_jailer": "false"}, want: []string{pJailer}},
	"split_own_chroot_base": {mode: "split", firecracker: true, fc: map[string]string{"jailer_chroot_base": `"/data/jailer"`}, want: []string{pChroot}},
	"split_kernel_in_data": {mode: "split", firecracker: true,
		fc: map[string]string{"kernel_path": `"/var/lib/sandboxd/kernels/vmlinux"`}, want: []string{pKernel}},
	"split_kernel_in_run": {mode: "split", firecracker: true,
		fc: map[string]string{"kernel_path": `"/run/sandboxd/vmlinux"`}, want: []string{pKernel}},
	"split_templates_outside": {mode: "split", firecracker: true,
		fc: map[string]string{"templates_dir": `"/data/templates"`}, want: []string{pAgentDir}},
	"split_wasm_modules_outside": {mode: "split", wasm: true, wasmModules: "/srv/wasm/modules", want: []string{pAgentDir}},
	"split_every_problem": {mode: "split", docker: true, oldJoin: true, noNetnsPool: true, firecracker: true, wasm: true,
		fc: map[string]string{"use_jailer": "false", "jailer_chroot_base": `"/data/jailer"`,
			"kernel_path": `"/var/lib/sandboxd/kernels/vmlinux"`, "run_dir": `"/var/run/fc"`},
		want: []string{pEngine, pJoin, pNetns, pJailer, pChroot, pKernel, pAgentDir}},
}

func TestSplitRunsEveryRuntimeAndRefusesOnlyWhatItCannotRun(t *testing.T) {
	names := make([]string, 0, len(splitCases))
	for name := range splitCases {
		names = append(names, name)
	}
	sort.Strings(names)
	dir := splitFixture(t, names, false)
	terraformRun(t, dir, "apply", "-auto-approve", "-input=false")
	raw := terraformRun(t, dir, "output", "-json")
	var outputs map[string]struct {
		Value struct {
			Problems   []string        `json:"problems"`
			KernelPath string          `json:"kernel_path"`
			JailerUID  json.RawMessage `json:"jailer_uid"`
			JailerGID  json.RawMessage `json:"jailer_gid"`
		} `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &outputs); err != nil {
		t.Fatalf("terraform output -json: %v\n%s", err, raw)
	}
	for _, name := range names {
		c, got := splitCases[name], outputs[name].Value
		t.Run(name, func(t *testing.T) {
			if len(got.Problems) != len(c.want) {
				t.Fatalf("split_problems = %q, want lines starting %q", got.Problems, c.want)
			}
			for i, w := range c.want {
				if !strings.HasPrefix(got.Problems[i], w) {
					t.Errorf("split_problems[%d] = %q, want it to start %q", i, got.Problems[i], w)
				}
			}
			if c.wantKernel != "" && got.KernelPath != c.wantKernel {
				t.Errorf("SB_FIRECRACKER_KERNEL = %q, want %q", got.KernelPath, c.wantKernel)
			}
			if c.wantJailer != "" {
				for k, v := range map[string]json.RawMessage{"SB_JAILER_UID": got.JailerUID, "SB_JAILER_GID": got.JailerGID} {
					if string(v) != c.wantJailer {
						t.Errorf("%s = %s, want %s", k, v, c.wantJailer)
					}
				}
			}
		})
	}
}

// The plan itself fails on a refused setting and names every problem, and
// passes split with every runtime. This is validate_cluster_ops's own
// precondition, cut from locals.tf.
func TestSplitPlanFailsWithEveryProblemNamed(t *testing.T) {
	block := hclBlock(readRepoFile(t, "Terraform", "locals.tf"), `resource "terraform_data" "validate_cluster_ops" {`)
	if block == "" {
		t.Fatal("Terraform/locals.tf has no validate_cluster_ops")
	}
	// Split's only refusals are split_problems: the one other precondition
	// that reads the mode checks its spelling.
	if n := strings.Count(block, "local.containerd_cfg.privilege_mode"); n != 1 {
		t.Errorf("validate_cluster_ops reads privilege_mode in %d places, want 1 (its spelling); "+
			"a refusal of split belongs in split_problems (Terraform/privilege_mode.tf)", n)
	}
	dir := splitFixture(t, []string{"split_every_problem", "split_every_runtime"}, true)
	out, err := terraformCmd(dir, "plan", "-input=false", "-no-color")
	if err == nil {
		t.Fatalf("the plan passed with every split problem set:\n%s", out)
	}
	// Terraform wraps the message; compare with each run of space as one.
	plain := strings.Join(strings.Fields(strings.ReplaceAll(out, "│", " ")), " ")
	if !strings.Contains(plain, "privilege_mode: split in config/cluster.yml cannot run with these settings:") {
		t.Errorf("the plan failed without the split message:\n%s", plain)
	}
	for _, w := range splitCases["split_every_problem"].want {
		if !strings.Contains(plain, "- "+w) {
			t.Errorf("the plan's message does not name %q:\n%s", w, plain)
		}
	}
	// The error does not name its module, so: one failure, and the other
	// module's check planned.
	if n := strings.Count(plain, "Error: Resource precondition failed"); n != 1 {
		t.Errorf("the plan failed %d preconditions, want 1 (split with every runtime and the defaults passes):\n%s", n, plain)
	}
	if !strings.Contains(plain, "module.split_every_runtime.terraform_data.check[0] will be created") {
		t.Errorf("the plan did not pass split with every runtime and the defaults:\n%s", plain)
	}
}

// splitFixture writes a root with one module call per case, each a copy of
// Terraform/privilege_mode.tf beside stand-ins for the locals it reads, and
// runs terraform init. check gives each module validate_cluster_ops's split
// precondition.
func splitFixture(t *testing.T, names []string, check bool) string {
	t.Helper()
	if _, err := exec.LookPath("terraform"); err != nil {
		t.Skip("terraform not on PATH")
	}
	// Reading the module's files keeps Go's test cache honest about what a
	// terraform subprocess reads.
	src := readRepoFile(t, "Terraform", "privilege_mode.tf")
	var cluster struct {
		Wasm struct {
			ModulesDir string `yaml:"modules_dir"`
			CacheDir   string `yaml:"cache_dir"`
		} `yaml:"wasm"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "config", "cluster.yml")), &cluster); err != nil {
		t.Fatal(err)
	}
	defaults := firecrackerDefaults(t)

	dir := t.TempDir()
	mod := filepath.Join(dir, "split")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		t.Fatal(err)
	}
	inputs := `variable "containerd_cfg" { type = any }
variable "container_engine" { type = string }
variable "one_line_join" { type = bool }
variable "wasm_cfg" { type = any }
variable "nodes_resolved" { type = any }
variable "firecracker" { type = any }
variable "check" { type = bool }
locals {
  containerd_cfg   = var.containerd_cfg
  container_engine = var.container_engine
  wasm_cfg         = var.wasm_cfg
  nodes_resolved   = var.nodes_resolved
}
output "problems" { value = local.split_problems }
output "kernel_path" { value = local.firecracker_kernel_path }
output "jailer_uid" { value = local.firecracker_jailer_uid }
output "jailer_gid" { value = local.firecracker_jailer_gid }
`
	if check {
		pre := splitPrecondition(t)
		inputs += "resource \"terraform_data\" \"check\" {\n  count = var.check ? 1 : 0\n  lifecycle {\n" + pre + "\n  }\n}\n"
	}
	for name, body := range map[string]string{"privilege_mode.tf": src, "inputs.tf": inputs} {
		if err := os.WriteFile(filepath.Join(mod, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var root strings.Builder
	for _, name := range names {
		c, ok := splitCases[name]
		if !ok {
			t.Fatalf("no split case %s", name)
		}
		engine, netns, wasm := "containerd", "true", "false"
		if c.docker {
			engine = "docker"
		}
		if c.noNetnsPool {
			netns = "false"
		}
		if c.wasm {
			wasm = "true"
		}
		modules := cluster.Wasm.ModulesDir
		if c.wasmModules != "" {
			modules = c.wasmModules
		}
		fc := map[string]string{}
		for k, v := range defaults {
			fc[k] = v
		}
		for k, v := range c.fc {
			if _, ok := fc[k]; !ok {
				t.Fatalf("%s sets firecracker.%s, which Terraform/variables.tf does not declare", name, k)
			}
			fc[k] = v
		}
		fmt.Fprintf(&root, `module %q {
  source           = "./split"
  check            = %t
  containerd_cfg   = { privilege_mode = %q, native_netns_pool_enabled = %q }
  container_engine = %q
  one_line_join    = %t
  wasm_cfg         = { enabled = %q, modules_dir = %q, cache_dir = %q }
  nodes_resolved   = { srv = { with_firecracker = false, with_isolate = false }, wrk = { with_firecracker = %t, with_isolate = %t } }
  firecracker      = %s
}
output %q { value = module.%s }
`, name, check, c.mode, netns, engine, !c.oldJoin, wasm, modules, cluster.Wasm.CacheDir,
			c.firecracker, c.isolate, hclObject(fc), name, name)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(root.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	terraformRun(t, dir, "init", "-backend=false", "-input=false")
	return dir
}

// firecrackerDefaults is var.firecracker's default for each field, from
// Terraform/variables.tf, as an HCL value ("null" for no default).
func firecrackerDefaults(t *testing.T) map[string]string {
	t.Helper()
	block := hclBlock(readRepoFile(t, "Terraform", "variables.tf"), `variable "firecracker" {`)
	field := regexp.MustCompile(`(?m)^\s+([a-z_]+)\s+= optional\((?:string|bool|number)(?:, (.+))?\)$`)
	out := map[string]string{}
	for _, m := range field.FindAllStringSubmatch(block, -1) {
		v := m[2]
		if v == "" {
			v = "null"
		}
		out[m[1]] = v
	}
	for _, k := range []string{"kernel_path", "run_dir", "templates_dir", "use_jailer", "jailer_chroot_base", "jailer_uid", "jailer_gid"} {
		if _, ok := out[k]; !ok {
			t.Fatalf("Terraform/variables.tf: firecracker has no field %s", k)
		}
	}
	return out
}

// splitPrecondition is validate_cluster_ops's precondition on split_problems.
func splitPrecondition(t *testing.T) string {
	t.Helper()
	block := hclBlock(readRepoFile(t, "Terraform", "locals.tf"), `resource "terraform_data" "validate_cluster_ops" {`)
	for rest := block; ; {
		i := strings.Index(rest, "precondition {")
		if i < 0 {
			break
		}
		pre := hclBlock(rest[i:], "precondition {")
		if strings.Contains(pre, "local.split_problems") {
			return pre
		}
		rest = rest[i+len(pre):]
	}
	t.Fatal("validate_cluster_ops has no precondition on local.split_problems")
	return ""
}

func hclObject(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+" = "+m[k])
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func terraformCmd(dir string, args ...string) (string, error) {
	cmd := exec.Command("terraform", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func terraformRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := terraformCmd(dir, args...)
	if err != nil {
		t.Fatalf("terraform %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// A split node with each runtime gets the install.sh flags that set it up,
// and the root helper restarts after the bootstrap's settings are written,
// since it reads cluster.env too. Single renders as before: Terraform
// installs Firecracker itself, the jailer runs as uid 1000, and only
// sandboxd restarts.
func TestBootstrapSplitRunsEveryRuntime(t *testing.T) {
	const (
		split       = "INSTALL_ARGS+=(--with-containerd-engine --privilege-mode split)"
		withFC      = "INSTALL_ARGS+=(--with-firecracker)"
		install     = `| sudo bash -s -- "${INSTALL_ARGS[@]}" join`
		opsEnv      = "sudo tee -a /etc/sandboxd/cluster.env < /tmp/aerolvm-ops.env"
		bothRestart = "\nsudo systemctl restart aerolvm-rootd sandboxd\n"
		oneRestart  = "\nsudo systemctl restart sandboxd\n"
	)
	runtimes := map[string][]string{
		"joiner_join_privilege_split_firecracker": {withFC, "SB_ENABLE_FIRECRACKER=true",
			"SB_FIRECRACKER_KERNEL=/usr/local/lib/aerolvm-firecracker/vmlinux", "SB_FIRECRACKER_USE_JAILER=true"},
		"joiner_join_privilege_split_isolate": {"INSTALL_ARGS+=(--with-isolate)"},
		"joiner_join_privilege_split_wasm":    {"SB_ENABLE_WASM=true", "SB_WASM_POOL_ENABLED=true"},
		"joiner_join_privilege_split_pool":    {"SB_CONTAINERD_POOL_ENABLED=true"},
	}
	singles := []string{"joiner_join_firecracker", "joiner_join", "joiner"}
	names := append([]string{}, singles...)
	for name := range runtimes {
		names = append(names, name)
	}
	rendered := renderBootstrapOutputs(t, bootstrapTemplatePath(t), names...)

	before := func(t *testing.T, out, a, b string) {
		t.Helper()
		i, j := strings.Index(out, a), strings.Index(out, b)
		if i < 0 || j < 0 || i > j {
			t.Errorf("want %q before %q (at %d and %d)", a, b, i, j)
		}
	}
	for name, wants := range runtimes {
		t.Run(name, func(t *testing.T) {
			out := rendered[name]
			for _, w := range append([]string{split}, wants...) {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q", w)
				}
			}
			before(t, out, split, install)
			if name == "joiner_join_privilege_split_firecracker" {
				before(t, out, split, withFC)
				before(t, out, withFC, install)
				// install.sh's sandboxd-jailer user runs the VMs.
				if strings.Contains(out, "SB_JAILER_UID=") || strings.Contains(out, "SB_JAILER_GID=") {
					t.Error("split writes the jailer's ids over install.sh's sandboxd-jailer user")
				}
			} else if strings.Contains(out, withFC) {
				t.Errorf("passes %s with no Firecracker on the node", withFC)
			}
			before(t, out, opsEnv, bothRestart)
			if strings.Contains(out, oneRestart) {
				t.Error("restarts sandboxd alone: the root helper keeps the settings it started with")
			}
		})
	}
	for _, name := range singles {
		t.Run(name, func(t *testing.T) {
			out := rendered[name]
			if !strings.Contains(out, oneRestart) || strings.Contains(out, "aerolvm-rootd") {
				t.Error("single restarts something other than sandboxd")
			}
			if strings.Contains(out, withFC) {
				t.Errorf("single passes %s; Terraform installs Firecracker itself there", withFC)
			}
		})
	}
	if out := rendered["joiner_join_firecracker"]; !strings.Contains(out, "SB_JAILER_UID=1000\nSB_JAILER_GID=1000\n") {
		t.Error("single Firecracker no longer runs the jailer as uid 1000")
	}
}
