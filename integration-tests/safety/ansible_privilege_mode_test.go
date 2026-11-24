package safety

import (
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

// Ansible's configure-ops.yml checks a node's settings for its privilege mode
// before it changes anything (Ansible/playbooks/tasks/privilege-mode-checks.yml).
// Split runs every runtime through the root helper, so the checks refuse only
// what split cannot run with, the same list as Terraform's split_problems
// (terraform_privilege_mode_test.go).

const privilegeChecks = "Ansible/playbooks/tasks/privilege-mode-checks.yml"

// The check tasks a case can fail, by name.
const (
	aUnknownMode = "Refuse an unknown privilege_mode"
	aEngine      = "Refuse a split node without the containerd engine or its netns pool"
	aFirecracker = "Refuse Firecracker settings privilege mode split cannot run"
	aFolders     = "Refuse runtime folders a split sandboxd cannot write"
	aUnit        = "Refuse Firecracker on a split node install.sh did not set up for it"
)

// splitUnit is a split sandboxd unit install.sh wrote with --with-firecracker,
// as `systemctl cat` prints it; noFirecrackerUnit is one written without.
const (
	splitUnit = "# /etc/systemd/system/sandboxd.service\n[Service]\n" +
		"ReadWritePaths=/var/lib/sandboxd -/run/aerolvm-procid -/etc/sandboxd/tls -/etc/sandboxd/cluster-ca -/srv/jailer\n"
	noFirecrackerUnit = "# /etc/systemd/system/sandboxd.service\n[Service]\n" +
		"ReadWritePaths=/var/lib/sandboxd -/run/aerolvm-procid -/etc/sandboxd/tls -/etc/sandboxd/cluster-ca\n"
)

type ansibleCase struct {
	set        map[string]any // cluster.yml values over the shipped file, by dotted path
	unit       string         // what `systemctl cat sandboxd` prints
	wantFailed string         // the check task that fails, or ""
	wantKernel string         // sandboxd_firecracker_kernel_path, when not ""
}

var ansibleCases = map[string]ansibleCase{
	// Single is untouched.
	"single_every_runtime": {set: map[string]any{"firecracker.enabled": true, "firecracker.use_jailer": false,
		"firecracker.jailer_chroot_base": "/data/jailer", "wasm.enabled": true, "containerd.pool.enabled": true},
		wantKernel: "/var/lib/sandboxd/firecracker/vmlinux"},
	"single_docker": {set: map[string]any{"container_engine": "docker", "containerd.native_netns_pool_enabled": false}},

	// Split runs every runtime with the shipped cluster.yml.
	"split_every_runtime": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"wasm.enabled": true, "containerd.pool.enabled": true}, unit: splitUnit,
		wantKernel: "/usr/local/lib/aerolvm-firecracker/vmlinux"},
	"split_wasm": {set: map[string]any{"privilege_mode": "split", "wasm.enabled": true}},
	"split_pool": {set: map[string]any{"privilege_mode": "split", "containerd.pool.enabled": true}},
	"split_own_kernel": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.kernel_path": "/opt/aerolvm/vmlinux"}, unit: splitUnit, wantKernel: "/opt/aerolvm/vmlinux"},

	// What split still refuses.
	"unknown_mode":     {set: map[string]any{"privilege_mode": "dual"}, wantFailed: aUnknownMode},
	"split_docker":     {set: map[string]any{"privilege_mode": "split", "container_engine": "docker"}, wantFailed: aEngine},
	"split_no_netns":   {set: map[string]any{"privilege_mode": "split", "containerd.native_netns_pool_enabled": false}, wantFailed: aEngine},
	"split_unjailed":   {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true, "firecracker.use_jailer": false}, unit: splitUnit, wantFailed: aFirecracker},
	"split_chroot":     {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true, "firecracker.jailer_chroot_base": "/data/jailer"}, unit: splitUnit, wantFailed: aFirecracker},
	"split_kernel_run": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true, "firecracker.kernel_path": "/run/sandboxd/vmlinux"}, unit: splitUnit, wantFailed: aFirecracker},
	"split_templates": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.templates_dir": "/data/templates"}, unit: splitUnit, wantFailed: aFolders},
	"split_wasm_modules": {set: map[string]any{"privilege_mode": "split", "wasm.enabled": true,
		"wasm.modules_dir": "/srv/wasm/modules"}, wantFailed: aFolders},
	"split_unit_without_firecracker": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true},
		unit: noFirecrackerUnit, wantFailed: aUnit},
}

func TestAnsiblePrivilegeChecks(t *testing.T) {
	playbook, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not on PATH")
	}
	root := repoRoot(t)
	checks, err := filepath.Abs(filepath.Join(root, privilegeChecks))
	if err != nil {
		t.Fatal(err)
	}
	// Read for Go's test cache: ansible-playbook reads it in a subprocess.
	readRepoFile(t, privilegeChecks)
	playVars := configureOpsPlay(t).Vars
	var cluster map[string]any
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "config", "cluster.yml")), &cluster); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	names := make([]string, 0, len(ansibleCases))
	for name := range ansibleCases {
		names = append(names, name)
	}
	sort.Strings(names)
	var inventory strings.Builder
	for _, name := range names {
		fmt.Fprintf(&inventory, "%s ansible_connection=local\n", name)
		c := ansibleCases[name]
		vars := deepCopy(cluster)
		for path, v := range c.set {
			setDotted(t, vars, path, v)
		}
		vars["sandboxd_unit"] = map[string]any{"stdout": c.unit}
		writeYAML(t, filepath.Join(dir, "host_vars", name+".yml"), vars)
	}
	writeFile(t, filepath.Join(dir, "hosts.ini"), inventory.String())
	// The play's own derived settings, as configure-ops.yml writes them.
	writeYAML(t, filepath.Join(dir, "play.yml"), []any{map[string]any{
		"hosts": "all", "gather_facts": false,
		"vars": map[string]any{
			"sandboxd_privilege_mode":          playVars["sandboxd_privilege_mode"],
			"sandboxd_firecracker_kernel_path": playVars["sandboxd_firecracker_kernel_path"],
		},
		"tasks": []any{
			map[string]any{
				"block":  []any{map[string]any{"ansible.builtin.import_tasks": checks}},
				"rescue": []any{map[string]any{"ansible.builtin.set_fact": map[string]any{"check_failed": "{{ ansible_failed_task.name }}"}}},
			},
			map[string]any{"ansible.builtin.debug": map[string]any{
				"msg": "RESULT {{ inventory_hostname }} kernel={{ sandboxd_firecracker_kernel_path }} failed={{ check_failed | default('') }}|"}},
		},
	}})
	writeFile(t, filepath.Join(dir, "ansible.cfg"), "[defaults]\nhost_key_checking = False\nretry_files_enabled = False\n"+
		"local_tmp = "+filepath.Join(dir, "tmp")+"\n[inventory]\nenable_plugins = ini\n")

	cmd := exec.Command(playbook, "-i", "hosts.ini", "play.yml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+filepath.Join(dir, "ansible.cfg"),
		"ANSIBLE_HOME="+filepath.Join(dir, "home"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	result := regexp.MustCompile(`RESULT (\S+) kernel=(\S*) failed=([^|]*)\|`)
	got := map[string][2]string{}
	for _, m := range result.FindAllStringSubmatch(string(out), -1) {
		got[m[1]] = [2]string{m[2], m[3]}
	}
	for _, name := range names {
		c := ansibleCases[name]
		t.Run(name, func(t *testing.T) {
			r, ok := got[name]
			if !ok {
				t.Fatalf("no result for %s:\n%s", name, out)
			}
			if r[1] != c.wantFailed {
				t.Errorf("failed check = %q, want %q", r[1], c.wantFailed)
			}
			if c.wantKernel != "" && r[0] != c.wantKernel {
				t.Errorf("SB_FIRECRACKER_KERNEL = %q, want %q", r[0], c.wantKernel)
			}
		})
	}
}

// The wiring around the checks, read from the playbooks: CI has no Ansible,
// so this part runs without it.
func TestAnsiblePrivilegeWiring(t *testing.T) {
	play := configureOpsPlay(t)
	var imported, readsUnit bool
	for _, task := range play.PreTasks {
		if task["ansible.builtin.import_tasks"] == "tasks/privilege-mode-checks.yml" {
			if !readsUnit {
				t.Error("configure-ops.yml imports the privilege checks before it reads sandboxd's unit")
			}
			imported = true
		}
		if task["register"] == "sandboxd_unit" {
			readsUnit = true
		}
	}
	if !imported {
		t.Error("configure-ops.yml's pre_tasks do not import tasks/privilege-mode-checks.yml")
	}
	// Split runs these now; a refusal of one by name is a regression.
	for _, f := range []string{"Ansible/playbooks/configure-ops.yml", privilegeChecks} {
		src := readRepoFile(t, f)
		for _, gone := range []string{"not (firecracker.enabled", "not (wasm.enabled", "not (containerd.pool.enabled", "does not run Firecracker"} {
			if strings.Contains(src, gone) {
				t.Errorf("%s still refuses a runtime split runs: %q", f, gone)
			}
		}
	}
	if v := fmt.Sprint(play.Vars["SB_FIRECRACKER_KERNEL"]); v != "<nil>" {
		t.Errorf("SB_FIRECRACKER_KERNEL is a play var: %s", v)
	}
	ops, _ := play.Vars["sandboxd_ops_env"].(map[string]any)
	if got := fmt.Sprint(ops["SB_FIRECRACKER_KERNEL"]); got != "{{ sandboxd_firecracker_kernel_path }}" {
		t.Errorf("SB_FIRECRACKER_KERNEL = %q, want the split-aware sandboxd_firecracker_kernel_path", got)
	}
	// Split: the helper reads cluster.env too, so it restarts with sandboxd.
	var single, split bool
	for _, h := range play.Handlers {
		when := fmt.Sprint(h["when"])
		if c, ok := h["ansible.builtin.command"].(map[string]any); ok && fmt.Sprint(c["argv"]) == "[systemctl restart aerolvm-rootd {{ sandboxd_service_name }}]" {
			split = strings.Contains(when, "sandboxd_privilege_mode == 'split'")
		}
		if s, ok := h["ansible.builtin.systemd"].(map[string]any); ok && s["state"] == "restarted" {
			single = strings.Contains(when, "sandboxd_privilege_mode != 'split'")
		}
	}
	if !split {
		t.Error("no handler restarts aerolvm-rootd and sandboxd together in split")
	}
	if !single {
		t.Error("the single-mode sandboxd restart also runs in split")
	}
	// A split sandboxd writes checkpoints in the WASM modules folder.
	stage := readRepoFile(t, "Ansible", "playbooks", "stage-wasm-modules.yml")
	if !strings.Contains(stage, `wasm_modules_owner: "{{ 'sandboxd' if (privilege_mode | default('single')) == 'split' else 'root' }}"`) ||
		strings.Contains(stage, "owner: root") {
		t.Error("stage-wasm-modules.yml gives the modules folder to root in split")
	}
}

type ansiblePlay struct {
	Vars     map[string]any   `yaml:"vars"`
	PreTasks []map[string]any `yaml:"pre_tasks"`
	Handlers []map[string]any `yaml:"handlers"`
}

// configureOpsPlay parses configure-ops.yml strictly: yaml.v3 refuses a key
// given twice, which Ansible would read as the last one alone.
func configureOpsPlay(t *testing.T) ansiblePlay {
	t.Helper()
	var plays []ansiblePlay
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "Ansible", "playbooks", "configure-ops.yml")), &plays); err != nil {
		t.Fatalf("configure-ops.yml: %v", err)
	}
	if len(plays) != 1 {
		t.Fatalf("configure-ops.yml has %d plays, want 1", len(plays))
	}
	return plays[0]
}

func setDotted(t *testing.T, m map[string]any, path string, v any) {
	t.Helper()
	keys := strings.Split(path, ".")
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			t.Fatalf("config/cluster.yml has no map %s (in %s)", k, path)
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}

func deepCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			v = deepCopy(sub)
		}
		out[k] = v
	}
	return out
}

func writeYAML(t *testing.T, path string, v any) {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
