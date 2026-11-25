package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// unitWouldStart reports whether systemd would start a unit with this text
// now, as far as its ConditionPathExists= lines go: each "!path" needs the
// path absent, each plain path needs it there. Those are the only
// conditions install.sh writes.
func unitWouldStart(unit string) bool {
	for _, line := range strings.Split(unit, "\n") {
		v, ok := strings.CutPrefix(line, "ConditionPathExists=")
		if !ok {
			continue
		}
		v, absent := strings.CutPrefix(v, "!")
		_, err := os.Stat(v)
		if (err == nil) == absent {
			return false
		}
	}
	return true
}

// TestInstallRootUnitWaitsForTheSwitchBack: on a switch back from split,
// install.sh writes root's sandboxd.service before leave_split_mode has
// given split's folders back to root. A reboot in that window used to let
// systemd start sandboxd as root on them. Root's unit now does not start
// while the switch-back marker is there, and the marker is there for the
// whole window: mark_switch_back runs before the unit is written, and
// leave_split_mode removes the marker last. A plain single node and a
// finished switch start as before; split's unit has no such condition.
func TestInstallRootUnitWaitsForTheSwitchBack(t *testing.T) {
	src := installShSource(t)

	// The order of the writes in the main flow, and the marker's path.
	main := strings.Index(src, "\nrecord_sandboxd_state\ninstall_binaries\nmark_switch_back\nwrite_environment\n")
	if main < 0 {
		t.Fatal("the main flow does not mark the switch back right before write_environment")
	}
	unitAt := strings.Index(src[main:], "\nwrite_systemd_unit\n")
	leaveAt := strings.Index(src[main:], "\nleave_split_mode\n")
	if unitAt < 0 || leaveAt < 0 || unitAt > leaveAt {
		t.Fatalf("want mark_switch_back, then write_systemd_unit, then leave_split_mode in the main flow (unit at %d, leave at %d)", unitAt, leaveAt)
	}
	leave := strings.TrimRight(installShFunction(t, src, "leave_split_mode"), "\n")
	if body := leave[:strings.LastIndex(leave, "\n}")]; !strings.HasSuffix(body, "\trm -f \"$PRIVILEGE_SWITCH_BACK_MARKER\"") {
		t.Fatalf("leave_split_mode does not remove the marker as its last step:\n%s", leave)
	}
	if m := regexp.MustCompile(`(?m)^PRIVILEGE_SWITCH_BACK_MARKER="([^"]+)"$`).FindStringSubmatch(src); m == nil || m[1] != "/etc/sandboxd/privilege-mode-switch-back" {
		t.Fatalf("PRIVILEGE_SWITCH_BACK_MARKER = %q", m)
	}

	// write_systemd_unit itself, writing into the test's folder.
	newHost := func(t *testing.T, env string) (*switchBackHost, string, string) {
		h := newSwitchBackHost(t, env)
		p, err := exec.LookPath("cat")
		if err != nil {
			t.Skip("cat not available")
		}
		if err := os.Symlink(p, filepath.Join(h.bin, "cat")); err != nil {
			t.Fatal(err)
		}
		unit := filepath.Join(h.dir, "sandboxd.service")
		write := strings.ReplaceAll(installShFunction(t, src, "write_systemd_unit", "split_sandboxd_unit"), "/etc/systemd/system/sandboxd.service", unit)
		return h, unit, write
	}
	unitVars := []string{"INSTALL_PREFIX", "/usr/local/bin", "ROOTD_SOCKET_GROUP", "aerolvm", "WASM_WORKER_GROUP", "aerolvm-wasm",
		"ROOTD_BIN_DIR", "/usr/local/lib/aerolvm-rootd"}
	read := func(t *testing.T, path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	t.Run("switch back: root's unit waits until the switch is done", func(t *testing.T) {
		h, unit, write := newHost(t, "SB_PRIVILEGE_MODE=split\n")
		// The run stops right after root's unit is written, as a reboot
		// there would stop it.
		h.run("single", write+writeEnvMarks+"setup_privilege_mode\nwrite_environment\nwrite_systemd_unit\nexit 0\n", unitVars...)
		text := read(t, unit)
		if !strings.Contains(text, "\nConditionPathExists=!"+h.marker+"\n") {
			t.Fatalf("root's unit has no condition on the marker:\n%s", text)
		}
		if !h.markerThere() {
			t.Fatal("root's unit is on disk and the marker is not")
		}
		if unitWouldStart(text) {
			t.Fatal("after a reboot here, systemd would start sandboxd as root")
		}

		// The next run finishes the switch: the marker goes, root's unit
		// starts.
		h.run("single", write+writeEnvMarks+"setup_privilege_mode\nwrite_environment\nwrite_systemd_unit\nleave_split_mode\n", unitVars...)
		if h.markerThere() {
			t.Fatal("the marker is still there after the switch")
		}
		if !unitWouldStart(read(t, unit)) {
			t.Fatal("root's unit does not start after a finished switch back")
		}
	})

	t.Run("plain single starts as before", func(t *testing.T) {
		h, unit, write := newHost(t, "SB_API_PORT=21212\n")
		h.run("single", write+writeEnvMarks+"setup_privilege_mode\nwrite_environment\nwrite_systemd_unit\nleave_split_mode\n", unitVars...)
		text := read(t, unit)
		if !strings.HasPrefix(text, "[Unit]\nDescription=AerolVM daemon\n") || !unitWouldStart(text) {
			t.Fatalf("a plain single node's unit would not start:\n%s", text)
		}
	})

	t.Run("split's unit has no condition", func(t *testing.T) {
		h, unit, write := newHost(t, "SB_PRIVILEGE_MODE=split\n")
		h.run("split", write+writeEnvMarks+"setup_privilege_mode\nwrite_environment\nwrite_systemd_unit\n", unitVars...)
		text := read(t, unit)
		if !strings.Contains(text, "Description=AerolVM daemon (privilege mode split)") || strings.Contains(text, "Condition") {
			t.Fatalf("split's unit:\n%s", text)
		}
	})
}
