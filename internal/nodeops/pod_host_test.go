package nodeops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeProc writes one /proc/<pid>/cmdline per entry (argv joined by NULs).
func fakeProc(t *testing.T, procs map[int][]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, argv := range procs {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		raw := ""
		if len(argv) > 0 {
			raw = strings.Join(argv, "\x00") + "\x00"
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Entries that are not processes are skipped.
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte("1 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPodHostUnitActive(t *testing.T) {
	cases := []struct {
		name  string
		procs map[int][]string
		unit  string
		want  bool
	}{
		{name: "the daemon runs", procs: map[int][]string{1: {"/usr/local/bin/sandboxd"}}, unit: "sandboxd", want: true},
		{name: "maintenance: a holding process only", procs: map[int][]string{1: {"sleep", "infinity"}}, unit: "sandboxd", want: false},
		{name: "the tool itself is not the daemon", procs: map[int][]string{1: {"sleep", "infinity"}, 42: {"sandboxd", "recover-quorum", "--node-id", "s1"}}, unit: "sandboxd", want: false},
		{name: "a wasm helper is not the daemon", procs: map[int][]string{7: {"/usr/local/bin/sandboxd", "--wasm-worker"}}, unit: "sandboxd", want: false},
		{name: "a kernel thread has no cmdline", procs: map[int][]string{2: nil}, unit: "sandboxd", want: false},
		{name: "this process never counts", procs: map[int][]string{99: {"sandboxd"}}, unit: "sandboxd", want: false},
		{name: "another unit", procs: map[int][]string{1: {"sandboxd"}}, unit: "caddy", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &PodHost{ProcRoot: fakeProc(t, tc.procs), Self: 99}
			if got := h.UnitActive(context.Background(), tc.unit); got != tc.want {
				t.Fatalf("UnitActive = %v, want %v", got, tc.want)
			}
		})
	}
	// The binary says which command lines are its daemon: one started with
	// a flag still counts, the tools and helpers still do not.
	daemon := func(argv []string) bool { return len(argv) == 1 || argv[1] == "--log-json" }
	withFlag := &PodHost{ProcRoot: fakeProc(t, map[int][]string{1: {"sandboxd", "--log-json"}, 2: {"sandboxd", "backup"}}), Self: 99, IsDaemon: daemon}
	if !withFlag.UnitActive(context.Background(), "sandboxd") {
		t.Fatal("a daemon started with a flag read as not running")
	}
	toolOnly := &PodHost{ProcRoot: fakeProc(t, map[int][]string{2: {"sandboxd", "backup"}}), Self: 99, IsDaemon: daemon}
	if toolOnly.UnitActive(context.Background(), "sandboxd") {
		t.Fatal("a tool read as the daemon")
	}
	// An unreadable /proc reads as running, so a tool refuses rather than
	// races a live daemon.
	h := &PodHost{ProcRoot: filepath.Join(t.TempDir(), "missing")}
	if !h.UnitActive(context.Background(), "sandboxd") {
		t.Fatal("unreadable /proc read as not running")
	}
}

func TestPodHostStopStartRefuse(t *testing.T) {
	h := NewPodHost()
	if h.ProcRoot != "/proc" || h.Self != os.Getpid() {
		t.Fatalf("NewPodHost = %+v", h)
	}
	for _, err := range []error{h.StopUnit(context.Background(), "sandboxd"), h.StartUnit(context.Background(), "sandboxd")} {
		if !errors.Is(err, errPodUnit) || !strings.Contains(err.Error(), "aerolvm.io/maintenance") {
			t.Fatalf("err = %v", err)
		}
	}
	// The default root works when unset.
	if (&PodHost{}).UnitActive(context.Background(), "nothing") {
		t.Fatal("unknown unit active")
	}
	_ = InPod() // depends on the machine; both answers are valid here
	if h.StopHint() == "" || !strings.Contains(h.StopHint(), "aerolvm.io/maintenance=true") {
		t.Fatalf("StopHint = %q", h.StopHint())
	}
}

// A pod is a container kubelet made (KUBERNETES_SERVICE_HOST) with no
// systemd. No systemd alone is a plain container or VM, not a server pod.
func TestInPod(t *testing.T) {
	missing := func(string) error { return os.ErrNotExist }
	present := func(string) error { return nil }
	for _, tc := range []struct {
		name    string
		k8s     string
		systemd func(string) error
		want    bool
	}{
		{name: "a server pod", k8s: "10.96.0.1", systemd: missing, want: true},
		{name: "a plain container without systemd", systemd: missing, want: false},
		{name: "a systemd machine", systemd: present, want: false},
		{name: "a systemd machine that is also a kubelet node", k8s: "10.96.0.1", systemd: present, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := func(k string) string {
				if k == "KUBERNETES_SERVICE_HOST" {
					return tc.k8s
				}
				return ""
			}
			if got := inPod(env, tc.systemd); got != tc.want {
				t.Fatalf("inPod = %v, want %v", got, tc.want)
			}
		})
	}
}

// recover-quorum in a maintenance pod: with only the holding process it runs
// and writes peers.json; with the daemon still up it refuses, and --start
// says to leave maintenance mode instead of starting a unit.
func TestRecoverQuorumInAPod(t *testing.T) {
	n := survivor(t, "")
	running := &PodHost{ProcRoot: fakeProc(t, map[int][]string{1: {"/usr/local/bin/sandboxd"}}), Self: 2}
	if _, _, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Host: running}); err == nil || !strings.Contains(err.Error(), "sandboxd is running here") ||
		strings.Contains(err.Error(), "systemctl") || !strings.Contains(err.Error(), "aerolvm.io/maintenance=true") {
		t.Fatalf("with the daemon up: %v", err)
	}
	held := &PodHost{ProcRoot: fakeProc(t, map[int][]string{1: {"sleep", "infinity"}, 2: {"sandboxd", "recover-quorum"}}), Self: 2}
	res, out, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Host: held})
	if err != nil || !exists(res.PeersFile) {
		t.Fatalf("in maintenance: %+v %v\n%s", res, err, out)
	}
	// The next steps are a pod's: annotate and kubectl exec, no systemctl.
	if strings.Contains(out, "systemctl") || !strings.Contains(out, "kubectl exec") {
		t.Fatalf("rejoin steps in a pod:\n%s", out)
	}
	if _, _, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Force: true, Start: true, Host: held}); err == nil || !strings.Contains(err.Error(), "aerolvm.io/maintenance") {
		t.Fatalf("--start in a pod: %v", err)
	}
}
