package harness

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestParseRuntimeCensus(t *testing.T) {
	tests := []struct {
		name        string
		out         string
		wantErr     string
		wantDown    bool
		wantRunning []string
		wantStates  map[string]string
	}{
		{
			name:        "containerd up, a banner line and mixed states",
			out:         "Warning: something from sudo\nENGINE containerd\nTASK sb-a RUNNING\nTASK sb-b PAUSED\nTASK sb-c STOPPED\nENGINE-UP\nCENSUS-DONE\n",
			wantRunning: []string{"sb-a"},
			wantStates:  map[string]string{"sb-a": "running", "sb-b": "paused", "sb-c": "stopped"},
		},
		{
			name:        "docker states",
			out:         "ENGINE docker\nTASK sb-x running\nTASK sb-y exited\nTASK sb-z restarting\nENGINE-UP\nCENSUS-DONE\n",
			wantRunning: []string{"sb-x", "sb-z"},
		},
		{
			name:     "containerd stopped and no shim: nothing runs",
			out:      "ENGINE containerd\nUNMAPPED 0\nCENSUS-DONE\n",
			wantDown: true,
		},
		{
			// A killed task's shim outlives both the task and containerd;
			// the shim with a child is the one whose container still runs.
			name:        "containerd stopped, read from the shims",
			out:         "ENGINE containerd\nTASK sb-killed stopped\nTASK sb-alive running\nUNMAPPED 0\nCENSUS-DONE\n",
			wantDown:    true,
			wantRunning: []string{"sb-alive"},
		},
		{
			name:    "docker stopped with live shims is unknown, never none",
			out:     "ENGINE docker\nUNMAPPED 4\nCENSUS-DONE\n",
			wantErr: "unknown",
		},
		{
			name:    "engine stopped without a shim reading is incomplete",
			out:     "ENGINE containerd\nCENSUS-DONE\n",
			wantErr: "incomplete",
		},
		{
			name:    "cut short (ssh dropped) is an error, never none",
			out:     "ENGINE containerd\nTASK sb-a RUNNING\n",
			wantErr: "incomplete",
		},
		{
			name:    "empty output is an error",
			out:     "",
			wantErr: "incomplete",
		},
		{
			name:    "bad unmapped count",
			out:     "ENGINE docker\nUNMAPPED lots\nCENSUS-DONE\n",
			wantErr: "unmapped shim count",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseRuntimeCensus(tt.out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.EngineDown != tt.wantDown {
				t.Errorf("EngineDown = %v, want %v", c.EngineDown, tt.wantDown)
			}
			if got := strings.Join(c.RunningIDs(), ","); got != strings.Join(tt.wantRunning, ",") {
				t.Errorf("running = %q, want %q", got, strings.Join(tt.wantRunning, ","))
			}
			for id, st := range tt.wantStates {
				if c.States[id] != st {
					t.Errorf("state[%s] = %q, want %q", id, c.States[id], st)
				}
			}
			if c.Running("sb-b") {
				t.Error("a paused task must not count as a running copy")
			}
		})
	}
}

func TestParseHardKill(t *testing.T) {
	eng, n, err := ParseHardKill("REMAINING 0\nHARD-KILLED containerd\n")
	if err != nil || eng != "containerd" || n != 0 {
		t.Fatalf("got %q %d %v", eng, n, err)
	}
	if _, n, err := ParseHardKill("REMAINING 2\nHARD-KILLED docker\n"); err != nil || n != 2 {
		t.Fatalf("remaining must be reported, got %d %v", n, err)
	}
	for _, bad := range []string{"", "REMAINING 0\n", "HARD-KILLED containerd\n", "REMAINING x\nHARD-KILLED containerd\n"} {
		if _, _, err := ParseHardKill(bad); err == nil {
			t.Errorf("ParseHardKill(%q) accepted an unfinished kill", bad)
		}
	}
	if s := HardKillRestoreEngineScript("containerd"); !strings.Contains(s, "start containerd") {
		t.Errorf("containerd restore = %q", s)
	}
	if s := HardKillRestoreEngineScript("docker"); !strings.Contains(s, "start docker.socket docker") {
		t.Errorf("docker restore = %q", s)
	}
}

func TestChaosPartitionScripts(t *testing.T) {
	ips := []string{"10.0.1.5", "54.1.2.3"}
	p := ChaosPartitionScript(ips, 10*time.Minute)
	for _, want := range []string{
		"set -e",
		"--on-active=600",
		"systemd-run --unit " + chaosPartitionUnit,
		"iptables -I INPUT -s 10.0.1.5 -m comment --comment " + chaosPartitionComment + " -j DROP",
		"iptables -I OUTPUT -d 10.0.1.5 -m comment --comment " + chaosPartitionComment + " -j DROP",
		"iptables -I INPUT -s 54.1.2.3",
		"echo PARTITIONED",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("partition script lacks %q:\n%s", want, p)
		}
	}
	// The dead-man is armed before any rule goes in, so a failure to arm it
	// (set -e) leaves the node connected rather than cut off for good.
	if strings.Index(p, "systemd-run") > strings.Index(p, "iptables -I") {
		t.Error("the dead-man must be armed before the first DROP rule")
	}
	h := ChaosHealScript(ips)
	for _, want := range []string{
		"systemctl stop " + chaosPartitionUnit + ".timer",
		"iptables -D INPUT -s 10.0.1.5 -m comment --comment " + chaosPartitionComment,
		"iptables -D OUTPUT -d 54.1.2.3 -m comment --comment " + chaosPartitionComment,
		"echo HEALED",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("heal script lacks %q:\n%s", want, h)
		}
	}
}

func TestNetemScriptsTouchPeersOnly(t *testing.T) {
	s := NetemScript([]string{"10.0.1.5", "10.0.2.9"}, "200ms", "5%", 15*time.Minute)
	for _, want := range []string{
		"prio bands 4",
		"parent 1:4 handle 40: netem delay 200ms loss 5%",
		"match ip dst 10.0.1.5/32 flowid 1:4",
		"match ip dst 10.0.2.9/32 flowid 1:4",
		"--on-active=900",
		"modprobe sch_netem",
		"NETEM-ON",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("netem script lacks %q:\n%s", want, s)
		}
	}
	// netem on the root qdisc would delay the operator's SSH and the API
	// domain too; it must sit on the filtered band only.
	if strings.Contains(s, "root netem") || strings.Contains(s, "root handle 1: netem") {
		t.Error("netem must not be the root qdisc")
	}
	if c := NetemClearScript(); !strings.Contains(c, "tc qdisc del dev") || !strings.Contains(c, chaosNetemUnit+".timer") {
		t.Errorf("clear script = %q", c)
	}
}

func TestParseReconcileInterval(t *testing.T) {
	def := 5 * time.Minute
	tests := map[string]time.Duration{
		"RECONCILE=60s\n":                    time.Minute,
		"banner\nRECONCILE=2m\n":             2 * time.Minute,
		"RECONCILE=\n":                       def,
		"RECONCILE=soon\n":                   def,
		"":                                   def,
		"RECONCILE=0s\n":                     def,
		"Warning: x\nRECONCILE=90s\nother\n": 90 * time.Second,
	}
	for out, want := range tests {
		if got := ParseReconcileInterval(out, def); got != want {
			t.Errorf("ParseReconcileInterval(%q) = %s, want %s", out, got, want)
		}
	}
}

// The scripts run on nodes over SSH, where a quoting slip shows up as a
// syntax error halfway through a paid run. bash -n parses without running.
func TestChaosScriptsParse(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	scripts := map[string]string{
		"census":    RuntimeCensusScript,
		"hard kill": "sudo systemctl stop sandboxd\n" + HardKillRuntimeScript,
		"partition": ChaosPartitionScript([]string{"10.0.1.5"}, time.Minute),
		"heal":      ChaosHealScript([]string{"10.0.1.5"}),
		"netem":     NetemScript([]string{"10.0.1.5"}, "200ms", "5%", time.Minute),
		"netem off": NetemClearScript(),
		"reconcile": ReconcileIntervalScript,
		"restore":   HardKillRestoreEngineScript("containerd"),
		"kill":      KillSandboxdScript,
		"fp arm":    FailpointArmScript("create-before-persist", "cluster-chaos-it's-a-name"),
		"fp hit":    FailpointHitScript("create-before-persist"),
		"fp disarm": FailpointDisarmScript("create-before-persist"),
		"soak":      SoakNodeScript,
	}
	for name, s := range scripts {
		if out, err := exec.Command(bash, "-n", "-c", s).CombinedOutput(); err != nil {
			t.Errorf("%s script does not parse: %v\n%s\n---\n%s", name, err, out, s)
		}
	}
}

func TestFailpointScriptsTargetTheDaemonsDirectory(t *testing.T) {
	arm := FailpointArmScript("create-before-persist", "chaos-480-")
	for _, want := range []string{
		"/run/sandboxd/failpoints/create-before-persist.hit", // a stale marker is cleared first
		"'chaos-480-' | sudo tee '/run/sandboxd/failpoints/create-before-persist'",
		"echo ARMED",
	} {
		if !strings.Contains(arm, want) {
			t.Errorf("arm script lacks %q:\n%s", want, arm)
		}
	}
	if !strings.Contains(FailpointDisarmScript("create-before-persist"), "'/run/sandboxd/failpoints/create-before-persist' '/run/sandboxd/failpoints/create-before-persist.hit'") {
		t.Errorf("disarm does not remove both files: %s", FailpointDisarmScript("create-before-persist"))
	}
}

func TestParseFailpointHit(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		wantKey string
		wantHit bool
		wantErr bool
	}{
		{name: "hit", out: "HIT cluster-chaos-x-1\nFP-DONE\n", wantKey: "cluster-chaos-x-1", wantHit: true},
		{name: "no hit", out: "NOHIT\nFP-DONE\n"},
		{name: "a banner line is ignored", out: "Warning: something\nNOHIT\nFP-DONE\n"},
		// An SSH drop must never read as "the failpoint did not fire":
		// that answer makes UC-480 skip.
		{name: "cut short", out: "NOHIT\n", wantErr: true},
		{name: "empty", out: "", wantErr: true},
		{name: "marker without a key", out: "HIT\nFP-DONE\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, hit, err := ParseFailpointHit(tt.out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if key != tt.wantKey || hit != tt.wantHit {
				t.Fatalf("got (%q, %v), want (%q, %v)", key, hit, tt.wantKey, tt.wantHit)
			}
		})
	}
}

func TestRecoveredAt(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	p := func(sent, answered float64, ok bool) RecoveryProbe {
		return RecoveryProbe{Sent: at(sent), Answered: at(answered), OK: ok}
	}
	tests := []struct {
		name       string
		probes     []RecoveryProbe
		want       float64
		wantOutage bool
		wantOK     bool
		wantStreak int
	}{
		{
			name:       "fails then recovers",
			probes:     []RecoveryProbe{p(0, 0.1, false), p(1, 1.1, false), p(2, 2.2, true), p(3, 3.1, true)},
			want:       2.2,
			wantOutage: true, wantOK: true, wantStreak: 2,
		},
		{
			// A node answered from its cache before it noticed the kill.
			name:       "an early cached success does not count",
			probes:     []RecoveryProbe{p(0, 0.1, true), p(1, 1.1, false), p(2, 2.1, false), p(3, 3.4, true)},
			want:       3.4,
			wantOutage: true, wantOK: true, wantStreak: 1,
		},
		{
			// Sent during the outage, it waited for the leader and then
			// succeeded: the signal was back when it answered.
			name:       "a hung probe counts from its answer",
			probes:     []RecoveryProbe{p(0, 0.2, false), p(1, 9, true), p(2, 9.1, true)},
			want:       9,
			wantOutage: true, wantOK: true, wantStreak: 2,
		},
		{
			name:       "flapped back down: only the last streak counts",
			probes:     []RecoveryProbe{p(0, 0.1, false), p(1, 1.1, true), p(2, 2.1, false), p(3, 3.2, true)},
			want:       3.2,
			wantOutage: true, wantOK: true, wantStreak: 1,
		},
		{
			name:       "probes out of order are sorted by send time",
			probes:     []RecoveryProbe{p(3, 3.2, true), p(0, 0.1, false), p(2, 2.6, true), p(1, 1.1, false)},
			want:       2.6,
			wantOutage: true, wantOK: true, wantStreak: 2,
		},
		{
			name:       "never failed",
			probes:     []RecoveryProbe{p(0, 0.1, true), p(1, 1.1, true)},
			want:       0.1,
			wantOutage: false, wantOK: true, wantStreak: 2,
		},
		{
			name:       "never came back",
			probes:     []RecoveryProbe{p(0, 0.1, true), p(1, 1.1, false)},
			wantOutage: true, wantOK: false, wantStreak: 0,
		},
		{name: "no probes", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, outage, ok := RecoveredAt(tt.probes)
			if ok != tt.wantOK || outage != tt.wantOutage {
				t.Fatalf("ok=%v outage=%v, want ok=%v outage=%v", ok, outage, tt.wantOK, tt.wantOutage)
			}
			if ok && !got.Equal(at(tt.want)) {
				t.Fatalf("recovered at +%s, want +%vs", got.Sub(t0), tt.want)
			}
			if s := RecoveryStreak(tt.probes); s != tt.wantStreak {
				t.Fatalf("streak %d, want %d", s, tt.wantStreak)
			}
		})
	}
}
