package safety

import (
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

	"github.com/aerol-ai/microvm/internal/rootd"
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
	aClean       = "Refuse paths privilege mode split cannot check"
	aRootFiles   = "Refuse root-run Firecracker files in sandboxd's folders"
	aLinks       = "Refuse root-run Firecracker files under a merged /usr's links"
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
	"split_kernel_run": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true, "firecracker.kernel_path": "/run/sandboxd/vmlinux"}, unit: splitUnit, wantFailed: aRootFiles},
	"split_kernel_tls": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true, "firecracker.kernel_path": "/etc/sandboxd/tls/vmlinux"}, unit: splitUnit, wantFailed: aRootFiles},
	"split_jailer_in_data": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.jailer_path": "/var/lib/sandboxd/bin/jailer"}, unit: splitUnit, wantFailed: aRootFiles},
	"split_firecracker_in_procid": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.binary_path": "/run/aerolvm-procid/firecracker"}, unit: splitUnit, wantFailed: aRootFiles},
	// Nor through a merged /usr's link: the helper refuses each at start.
	"split_jailer_under_sbin": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.jailer_path": "/sbin/jailer"}, unit: splitUnit, wantFailed: aLinks},
	"split_firecracker_under_bin": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.binary_path": "/bin/firecracker"}, unit: splitUnit, wantFailed: aLinks},
	"split_kernel_under_lib": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.kernel_path": "/lib/vmlinux"}, unit: splitUnit, wantFailed: aLinks},
	"split_kernel_dotdot": {set: map[string]any{"privilege_mode": "split", "firecracker.enabled": true,
		"firecracker.kernel_path": "/usr/local/lib/../../../var/lib/sandboxd/vmlinux"}, unit: splitUnit, wantFailed: aClean},
	"split_modules_doubleslash": {set: map[string]any{"privilege_mode": "split", "wasm.enabled": true,
		"wasm.modules_dir": "/var/lib//sandboxd/wasm"}, wantFailed: aClean},
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
				"msg": "RESULT {{ inventory_hostname }} kernel={{ sandboxd_firecracker_kernel_path }} failed={{ check_failed | default('') }}|" +
					" files={{ sandboxd_split_root_files | default([]) | join(',') }} dirs={{ sandboxd_split_agent_dirs | default([]) | join(',') }}|"}},
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
	result := regexp.MustCompile(`RESULT (\S+) kernel=(\S*) failed=([^|]*)\| files=([^ ]*) dirs=([^|]*)\|`)
	got := map[string][4]string{}
	for _, m := range result.FindAllStringSubmatch(string(out), -1) {
		got[m[1]] = [4]string{m[2], m[3], m[4], m[5]}
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
			// The files root runs or links (SB_FIRECRACKER_BINARY,
			// SB_JAILER_BINARY, the kernel) against the root helper's own
			// path rule: the checks refuse exactly when the helper would.
			if c.set["privilege_mode"] == "split" && slices.Contains([]string{"", aClean, aRootFiles, aLinks}, r[1]) {
				var refused []string
				for _, f := range strings.Split(r[2], ",") {
					if f == "" {
						continue
					}
					if err := rootd.CheckRootProgramPath(f, strings.Split(r[3], ",")); err != nil {
						refused = append(refused, err.Error())
					}
				}
				// A path that is not clean fails its own check, whatever the
				// file (a WASM folder's too).
				switch {
				case len(refused) > 0 && r[1] == "":
					t.Errorf("the root helper refuses %q, but the checks pass", refused)
				case len(refused) == 0 && (r[1] == aRootFiles || r[1] == aLinks):
					t.Errorf("the checks failed %q on root files %q that the root helper takes", r[1], r[2])
				}
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
}

// splitPlaybooks are the playbooks that run on a split node and write files.
var splitPlaybooks = []string{"configure-ops.yml", "stage-wasm-modules.yml"}

// In privilege mode split, sandboxd's user owns its folders and can swap any
// name in them for a link. Ansible's modules follow links, in every folder of
// a path (follow: false covers only the last part), so a task that runs as
// root, or that sets an owner or group (a chown as root), must not act on a
// path inside them. This walks every task of the playbooks that can run in
// split and checks each path its arguments name, with the variables they
// use filled in from group_vars, the play's vars and config/cluster.yml.
func TestAnsibleSplitRootStaysOutOfAgentFolders(t *testing.T) {
	bad, handed := splitRootTasksInAgentFolders(t, nil)
	for _, b := range bad {
		t.Errorf("acts as root inside a folder sandboxd's user owns in split: %s", b)
	}
	if len(handed) != 0 {
		t.Errorf("tasks hand these folders to sandboxd's user and so make them its own: %q", handed)
	}
}

// splitRootTasksInAgentFolders returns the split tasks that act as root on a
// path inside sandboxd's folders, and the folders a split task hands that
// user. edit, when set, changes a playbook's text before it is read.
func splitRootTasksInAgentFolders(t *testing.T, edit func(name, src string) string) (bad, handed []string) {
	t.Helper()
	vars := ansibleStringVars(t)
	var tasks []ansibleTaskView
	for _, pb := range splitPlaybooks {
		src := readRepoFile(t, "Ansible", "playbooks", pb)
		if edit != nil {
			src = edit(pb, src)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal([]byte(src), &plays); err != nil {
			t.Fatalf("%s: %v", pb, err)
		}
		for _, play := range plays {
			playVars, _ := play["vars"].(map[string]any)
			for k, v := range playVars {
				if sv, ok := v.(string); ok && !strings.Contains(sv, " if ") {
					vars[k] = sv
				}
			}
			view := ansibleTaskView{become: play["become"] == true, becomeUser: fmt.Sprint(play["become_user"])}
			for _, list := range []string{"pre_tasks", "tasks", "handlers"} {
				tasks = append(tasks, walkAnsibleTasks(pb, play[list], view)...)
			}
		}
	}
	dirs := append([]string{}, splitAgentDirs...)
	for _, task := range tasks {
		if task.split() && task.dir != "" && (task.owner == "sandboxd" || strings.Contains(task.owner, "sandboxd_file_owner")) {
			d := expandAnsible(task.dir, vars)
			dirs = append(dirs, d)
			handed = append(handed, d)
		}
	}
	for _, task := range tasks {
		if !task.split() || !task.asRoot() {
			continue
		}
		text := expandAnsible(task.text, vars)
		for _, d := range dirs {
			if strings.Contains(text, d+"/") {
				bad = append(bad, fmt.Sprintf("%s %q (%s)", task.playbook, task.name, d))
				break
			}
		}
	}
	return bad, handed
}

// ansibleTaskView is what the walk needs of one task.
type ansibleTaskView struct {
	playbook, name string
	when           []string
	become         bool
	becomeUser     string
	text           string // the module's arguments and the loop, as YAML
	setsOwner      bool   // owner: or group: in the arguments
	owner, dir     string // owner:, and path: of a state: directory task
}

// split: not left out of privilege mode split by its when.
func (v ansibleTaskView) split() bool {
	for _, w := range v.when {
		w = strings.Join(strings.Fields(w), " ")
		if strings.Contains(w, "!= 'split'") || strings.Contains(w, "== 'single'") {
			return false
		}
	}
	return true
}

// asRoot: becomes root in split, or chowns.
func (v ansibleTaskView) asRoot() bool {
	agent := v.becomeUser == "sandboxd" ||
		(strings.Contains(v.becomeUser, "'sandboxd' if") && strings.Contains(v.becomeUser, "== 'split'"))
	return (v.become && !agent) || v.setsOwner
}

var ansibleKeywords = map[string]bool{"name": true, "when": true, "loop": true, "loop_control": true, "register": true,
	"notify": true, "listen": true, "no_log": true, "changed_when": true, "failed_when": true, "check_mode": true,
	"become": true, "become_user": true, "run_once": true, "vars": true, "tags": true, "delegate_to": true,
	"block": true, "rescue": true, "always": true, "args": true, "environment": true, "ignore_errors": true,
	"until": true, "retries": true, "delay": true}

func walkAnsibleTasks(playbook string, list any, parent ansibleTaskView) []ansibleTaskView {
	items, _ := list.([]any)
	var out []ansibleTaskView
	for _, it := range items {
		task, ok := it.(map[string]any)
		if !ok {
			continue
		}
		v := parent
		v.playbook, v.name = playbook, fmt.Sprint(task["name"])
		v.when = append(append([]string{}, parent.when...), whenList(task["when"])...)
		if b, ok := task["become"].(bool); ok {
			v.become = b
		}
		if u, ok := task["become_user"]; ok {
			v.becomeUser = fmt.Sprint(u)
		}
		if _, ok := task["block"]; ok {
			for _, k := range []string{"block", "rescue", "always"} {
				out = append(out, walkAnsibleTasks(playbook, task[k], v)...)
			}
			continue
		}
		for k, args := range task {
			if ansibleKeywords[k] {
				continue
			}
			b, _ := yaml.Marshal(map[string]any{k: args, "loop": task["loop"]})
			v.text = string(b)
			if m, ok := args.(map[string]any); ok {
				_, o := m["owner"]
				_, g := m["group"]
				v.setsOwner = o || g
				if m["state"] == "directory" {
					v.owner, v.dir = fmt.Sprint(m["owner"]), fmt.Sprint(m["path"])
				}
			}
		}
		out = append(out, v)
	}
	return out
}

func whenList(w any) []string {
	switch w := w.(type) {
	case string:
		return []string{w}
	case []any:
		var out []string
		for _, x := range w {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

// ansibleStringVars are the string settings a task can name: group_vars'
// defaults, and config/cluster.yml's, by dotted path (wasm.modules_dir).
func ansibleStringVars(t *testing.T) map[string]string {
	t.Helper()
	vars := map[string]string{}
	var defaults map[string]any
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "Ansible", "inventory", "group_vars", "all", "defaults.yml")), &defaults); err != nil {
		t.Fatal(err)
	}
	for k, v := range defaults {
		if sv, ok := v.(string); ok {
			vars[k] = sv
		}
	}
	var cluster map[string]any
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "config", "cluster.yml")), &cluster); err != nil {
		t.Fatal(err)
	}
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			switch v := v.(type) {
			case string:
				vars[prefix+k] = v
			case map[string]any:
				walk(prefix+k+".", v)
			}
		}
	}
	walk("", cluster)
	return vars
}

// expandAnsible fills in the variables a text names, a few rounds deep, and
// drops Jinja's braces, so "{{ sandboxd_secrets_dir }}/k" reads as a path.
func expandAnsible(text string, vars map[string]string) string {
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for round := 0; round < 4; round++ {
		for _, k := range names {
			text = regexp.MustCompile(`(^|[^A-Za-z0-9_.])`+regexp.QuoteMeta(k)+`($|[^A-Za-z0-9_])`).
				ReplaceAllString(text, "${1}"+strings.ReplaceAll(vars[k], "$", "$$")+"${2}")
		}
	}
	return regexp.MustCompile(`\{\{\s*|\s*\}\}`).ReplaceAllString(text, "")
}

// The walk finds what this branch fixed, put back one at a time.
func TestAnsibleSplitRootCheckFindsTheBugs(t *testing.T) {
	cases := map[string]struct {
		playbook, from, to string
	}{
		"root makes Firecracker's folders": {"configure-ops.yml",
			"        - firecracker.enabled | default(false) | bool\n        - sandboxd_privilege_mode != 'split'\n      ansible.builtin.file:\n        path: \"{{ item }}\"\n        state: directory\n        mode: \"0755\"\n        owner: root",
			"        - firecracker.enabled | default(false) | bool\n      ansible.builtin.file:\n        path: \"{{ item }}\"\n        state: directory\n        mode: \"0755\"\n        owner: root"},
		"root stages the WASM modules": {"stage-wasm-modules.yml",
			"  become_user: \"{{ 'sandboxd' if (privilege_mode | default('single')) == 'split' else 'root' }}\"\n", ""},
		"the secrets folder is sandboxd's": {"configure-ops.yml",
			"        owner: root\n        group: \"{{ sandboxd_file_owner }}\"\n",
			"        owner: \"{{ sandboxd_file_owner }}\"\n        group: \"{{ sandboxd_file_owner }}\"\n"},
		"root writes the SSH host key in /var/lib/sandboxd": {"configure-ops.yml",
			"      when:\n        - sandboxd_privilege_mode != 'split'\n        - (ssh | default({})).host_key | default('') | length > 0\n",
			"      when:\n        - (ssh | default({})).host_key | default('') | length > 0\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			found := false
			bad, _ := splitRootTasksInAgentFolders(t, func(pb, src string) string {
				if pb != c.playbook {
					return src
				}
				if strings.Count(src, c.from) != 1 {
					t.Fatalf("%s: the text to put back is not there once", pb)
				}
				found = true
				return strings.Replace(src, c.from, c.to, 1)
			})
			if !found {
				t.Fatalf("%s not read", c.playbook)
			}
			if len(bad) == 0 {
				t.Error("the walk does not find it")
			}
			t.Logf("found: %q", bad)
		})
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
