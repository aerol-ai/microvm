package safety

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// In single, Ansible's configure-ops.yml gives Firecracker's jailer a system
// user of its own, as install.sh --with-firecracker does: it makes
// sandboxd-jailer (its own group, no login shell, no other group) and
// writes its ids to the env file it manages, replacing the uid 1000 a
// Terraform bootstrap wrote before. sandboxd refuses a login user there.
// Split leaves both to install.sh. Read from the playbook: CI has no
// Ansible, and the tasks need root.
func TestAnsibleSingleJailerUser(t *testing.T) {
	var plays []struct {
		Tasks []map[string]any `yaml:"tasks"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "Ansible", "playbooks", "configure-ops.yml")), &plays); err != nil || len(plays) != 1 {
		t.Fatalf("configure-ops.yml: %d plays, %v", len(plays), err)
	}
	tasks := plays[0].Tasks
	find := func(module string, match func(map[string]any) bool) (int, map[string]any, map[string]any) {
		for i, task := range tasks {
			if args, ok := task[module].(map[string]any); ok && match(args) {
				return i, task, args
			}
		}
		t.Fatalf("configure-ops.yml has no %s task for the jailer's user", module)
		return 0, nil, nil
	}
	named := func(args map[string]any) bool { return args["name"] == "sandboxd-jailer" }
	gi, groupTask, group := find("ansible.builtin.group", named)
	ui, userTask, user := find("ansible.builtin.user", named)
	// The env writer whose loop names the jailer's ids.
	wi, writeTask, write := -1, map[string]any(nil), map[string]any(nil)
	for i, task := range tasks {
		args, ok := task["ansible.builtin.lineinfile"].(map[string]any)
		if ok && strings.Contains(fmt.Sprint(task["loop"]), "SB_JAILER_UID") {
			wi, writeTask, write = i, task, args
		}
	}
	if writeTask == nil {
		t.Fatal("configure-ops.yml writes no SB_JAILER_UID")
	}

	if group["system"] != true || groupTask["register"] != "sandboxd_jailer_group" {
		t.Errorf("group task %v: want a system group, registered as sandboxd_jailer_group", groupTask)
	}
	for k, want := range map[string]any{"group": "sandboxd-jailer", "system": true, "create_home": false, "shell": "/usr/sbin/nologin"} {
		if user[k] != want {
			t.Errorf("user task: %s = %v, want %v", k, user[k], want)
		}
	}
	if g, ok := user["groups"].([]any); !ok || len(g) != 0 {
		t.Errorf("user task: groups = %v, want [] (no other group)", user["groups"])
	}
	if userTask["register"] != "sandboxd_jailer_user" {
		t.Errorf("user task registers %v, want sandboxd_jailer_user", userTask["register"])
	}
	// Same user and shell as install.sh's.
	install := readRepoFile(t, "scripts", "install.sh")
	if !strings.Contains(install, `JAILER_USER="sandboxd-jailer"`) || !strings.Contains(install, `useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$JAILER_USER"`) {
		t.Error("install.sh's jailer user is no longer sandboxd-jailer with /usr/sbin/nologin")
	}

	if write["path"] != "{{ sandboxd_ops_env_file }}" || writeTask["notify"] != "Apply sandboxd ops config" {
		t.Errorf("ids task writes %v and notifies %v, want the ops env file and a restart", write["path"], writeTask["notify"])
	}
	loop := fmt.Sprint(writeTask["loop"])
	for _, w := range []string{"SB_JAILER_UID", "{{ sandboxd_jailer_user.uid }}", "SB_JAILER_GID", "{{ sandboxd_jailer_group.gid }}"} {
		if !strings.Contains(loop, w) {
			t.Errorf("ids task loop %s does not name %q", loop, w)
		}
	}
	if !(gi < ui && ui < wi) {
		t.Errorf("tasks out of order: group %d, user %d, ids %d", gi, ui, wi)
	}
	for name, task := range map[string]map[string]any{"group": groupTask, "user": userTask, "ids": writeTask} {
		when := fmt.Sprint(task["when"])
		if !strings.Contains(when, "firecracker.enabled") || !strings.Contains(when, "sandboxd_privilege_mode != 'split'") {
			t.Errorf("%s task runs when %s; want single nodes with Firecracker only", name, when)
		}
	}
	if !strings.Contains(fmt.Sprint(writeTask["when"]), "sandboxd_jailer_user.uid is defined") {
		t.Error("ids task would write an empty uid in check mode")
	}
	// No other task writes the jailer's ids or uid 1000.
	src := readRepoFile(t, "Ansible", "playbooks", "configure-ops.yml")
	if n := strings.Count(src, "SB_JAILER_UID"); n != 1 {
		t.Errorf("configure-ops.yml names SB_JAILER_UID %d times, want 1", n)
	}
}
