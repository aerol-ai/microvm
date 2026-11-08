package harness

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/failpoint"
)

// Node-side scripts and parsers for the cluster-correctness fault cases
// (UC-470..UC-479, suite/z_cluster_chaos_test.go). They live here, outside
// the integration build tag, so the parsing that decides "how many copies of
// this sandbox are running" is unit-tested offline: a parser that read an
// SSH failure as "no copies" would turn every two-copies violation green.

// nodeEnvPrelude prints the sandboxd env values a script needs, read the way
// the daemon reads them (sandboxd.env, then cluster.env on top).
const nodeEnvPrelude = `vals=$(sudo bash -c '. /etc/sandboxd/sandboxd.env 2>/dev/null; . /etc/sandboxd/cluster.env 2>/dev/null; printf "%s %s" "${SB_CONTAINER_ENGINE:-docker}" "${SB_CONTAINERD_NAMESPACE:-aerolvm}"')
eng=${vals%% *}
ns=${vals#* }
`

// RuntimeCensusScript lists every sandbox container the node's engine knows,
// with its state, as "TASK <sandbox id> <state>" lines. A sandbox's
// containerd task id and docker container name are its sandbox id (the
// containerd warm pool, the one exception, is off on the chaos scenario).
//
// When the engine is not answering (a case stopped it), the containers may
// still run: a containerd shim outlives containerd, and a killed task's shim
// lives on until the task is deleted. So the script reads the shims
// themselves. For containerd each shim's command line names its task id
// (-namespace <ns> -id <id>), and the task runs exactly when the shim still
// has a child (the container's init, which the shim reaps). For docker the
// shim's id is a container hash, not the sandbox's name, so live shims are
// only counted, as UNMAPPED, and ParseRuntimeCensus refuses to answer rather
// than say "none". The pgrep patterns start with a bracket so they do not
// match this script's own command line.
const RuntimeCensusScript = "set -u\n" + nodeEnvPrelude + `echo "ENGINE $eng"
if [ "$eng" = containerd ]; then
  if sudo ctr -n "$ns" version >/dev/null 2>&1; then
    sudo ctr -n "$ns" task ls 2>/dev/null | awk 'NR>1 && NF>=3 {print "TASK", $1, $3}'
    echo ENGINE-UP
  else
    for pid in $(pgrep -f "[c]ontainerd-shim.*-namespace $ns -id" || true); do
      id=$(sudo cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' '\n' | awk 'p {print; exit} $0 == "-id" {p = 1}')
      [ -n "$id" ] || continue
      if pgrep -P "$pid" >/dev/null 2>&1; then echo "TASK $id running"; else echo "TASK $id stopped"; fi
    done
    echo "UNMAPPED 0"
  fi
elif sudo docker info >/dev/null 2>&1; then
  sudo docker ps -a --filter label=aerolvm.managed=true --format 'TASK {{.Names}} {{.State}}' 2>/dev/null
  echo ENGINE-UP
else
  n=0
  for pid in $(pgrep -f "[c]ontainerd-shim.*-namespace moby -id" || true); do
    pgrep -P "$pid" >/dev/null 2>&1 && n=$((n + 1))
  done
  echo "UNMAPPED $n"
fi
echo CENSUS-DONE
`

// RuntimeCensus is what one node's engine (or, with the engine down, its
// shims) says is there.
type RuntimeCensus struct {
	Engine string
	// EngineDown is true when the engine did not answer and the states
	// come from the containerd shims instead.
	EngineDown bool
	// States maps sandbox id to its lower-cased state: containerd
	// running|paused|stopped|created, docker running|paused|exited|created|
	// restarting|dead.
	States map[string]string
}

// Running reports whether id runs. A paused task is not running: pausing a
// copy the node may no longer own is one of the plan's C4 fixes.
func (c RuntimeCensus) Running(id string) bool {
	switch c.States[id] {
	case "running", "restarting":
		return true
	}
	return false
}

// RunningIDs is every id that runs, sorted.
func (c RuntimeCensus) RunningIDs() []string {
	var out []string
	for id := range c.States {
		if c.Running(id) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// ParseRuntimeCensus reads RuntimeCensusScript's output. Lines it does not
// know (an SSH banner, a sudo warning) are ignored. A missing CENSUS-DONE,
// or an engine that is down with no shim reading, is an error, because a
// census cut short must never read as "nothing runs"; so is a live shim that
// cannot be mapped to a sandbox.
func ParseRuntimeCensus(out string) (RuntimeCensus, error) {
	c := RuntimeCensus{States: map[string]string{}}
	done, up := false, false
	unmapped := -1
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(raw)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "ENGINE":
			if len(f) == 2 {
				c.Engine = f[1]
			}
		case "ENGINE-UP":
			up = true
		case "TASK":
			if len(f) == 3 {
				c.States[f[1]] = strings.ToLower(f[2])
			}
		case "UNMAPPED":
			if len(f) == 2 {
				n, err := strconv.Atoi(f[1])
				if err != nil {
					return RuntimeCensus{}, fmt.Errorf("census: bad unmapped shim count %q", f[1])
				}
				unmapped = n
			}
		case "CENSUS-DONE":
			done = true
		}
	}
	if !done || c.Engine == "" || (!up && unmapped < 0) {
		return RuntimeCensus{}, fmt.Errorf("census incomplete (the script did not finish): %s", strings.TrimSpace(snippet([]byte(out))))
	}
	if !up {
		c.EngineDown = true
		if unmapped > 0 {
			return RuntimeCensus{}, fmt.Errorf("census: the %s engine is down and %d of its shims still run a container that cannot be mapped to a sandbox, so which sandboxes run is unknown", c.Engine, unmapped)
		}
	}
	return c, nil
}

// HardKillRuntimeScript kills every sandbox container on the node and stops
// the engine. Callers stop sandboxd first, in the same script: the point is a
// node that died, with nothing of AerolVM left running, which is what the
// existing failover cases never model (they stop sandboxd only, so the old
// copy keeps running and nobody checks that it dies). It prints
// "REMAINING <n>" (containers still running after the kill, which must be 0)
// and "HARD-KILLED <engine>".
const HardKillRuntimeScript = nodeEnvPrelude + `if [ "$eng" = containerd ]; then
  for id in $(sudo ctr -n "$ns" task ls -q 2>/dev/null); do sudo ctr -n "$ns" task kill -s SIGKILL "$id" >/dev/null 2>&1 || true; done
  n=0
  for i in 1 2 3 4 5 6 7 8 9 10; do
    n=$(sudo ctr -n "$ns" task ls 2>/dev/null | awk 'NR>1 && $3=="RUNNING"' | wc -l)
    [ "$n" -eq 0 ] && break
    sleep 1
  done
  echo "REMAINING $n"
  sudo systemctl stop containerd
else
  ids=$(sudo docker ps -q --filter label=aerolvm.managed=true 2>/dev/null || true)
  [ -n "$ids" ] && sudo docker kill $ids >/dev/null 2>&1 || true
  n=$(sudo docker ps -q --filter label=aerolvm.managed=true 2>/dev/null | wc -l)
  echo "REMAINING $n"
  sudo systemctl stop docker.socket docker
fi
echo "HARD-KILLED $eng"
`

// HardKillRestoreEngineScript starts the engine HardKillRuntimeScript
// stopped. sandboxd is started separately, by the suite's restore helper,
// which also waits for the node to rejoin.
func HardKillRestoreEngineScript(engine string) string {
	if engine == "containerd" {
		return "sudo systemctl start containerd && echo ENGINE-STARTED"
	}
	return "sudo systemctl start docker.socket docker && echo ENGINE-STARTED"
}

// ParseHardKill reads HardKillRuntimeScript's output: the engine it stopped
// and how many containers were still running after the kill.
func ParseHardKill(out string) (engine string, remaining int, err error) {
	remaining = -1
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(raw)
		switch {
		case len(f) == 2 && f[0] == "REMAINING":
			if remaining, err = strconv.Atoi(f[1]); err != nil {
				return "", 0, fmt.Errorf("hard kill: bad remaining count %q", f[1])
			}
		case len(f) == 2 && f[0] == "HARD-KILLED":
			engine = f[1]
		}
	}
	if engine == "" || remaining < 0 {
		return "", 0, fmt.Errorf("hard kill did not finish: %s", strings.TrimSpace(snippet([]byte(out))))
	}
	return engine, remaining, nil
}

// Partition mechanism: the one UC-291 uses (iptables DROP in both directions
// on the cut-off node, tagged with a comment, plus a dead-man heal armed with
// systemd-run on the node itself), with its own comment and a fixed unit name
// so a heal also disarms the dead-man. Without that, the timer a healed
// partition left behind would fire inside the NEXT case's partition of the
// same node and heal it early.
const (
	chaosPartitionComment = "aerolvm-itest-chaos-partition"
	chaosPartitionUnit    = "aerolvm-itest-chaos-heal"
	chaosNetemUnit        = "aerolvm-itest-chaos-netem"
)

// chaosHealBody removes every rule ChaosPartitionScript added for ips and
// disarms the dead-man. It runs as root (from the dead-man itself, or under
// sudo from ChaosHealScript).
func chaosHealBody(ips []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "systemctl stop %s.timer >/dev/null 2>&1; ", chaosPartitionUnit)
	for _, ip := range ips {
		fmt.Fprintf(&b, "while iptables -D INPUT -s %s -m comment --comment %s -j DROP 2>/dev/null; do :; done; ", ip, chaosPartitionComment)
		fmt.Fprintf(&b, "while iptables -D OUTPUT -d %s -m comment --comment %s -j DROP 2>/dev/null; do :; done; ", ip, chaosPartitionComment)
	}
	b.WriteString("true")
	return b.String()
}

// ChaosPartitionScript cuts the node it runs on off from ips, both ways, and
// arms a dead-man heal that fires after deadman unless ChaosHealScript runs
// first. It prints PARTITIONED only once every rule is in; set -e makes a
// failure to arm the dead-man abort before any rule is added.
func ChaosPartitionScript(ips []string, deadman time.Duration) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	fmt.Fprintf(&b, "sudo systemctl stop %[1]s.timer %[1]s.service >/dev/null 2>&1 || true\n", chaosPartitionUnit)
	fmt.Fprintf(&b, "sudo systemctl reset-failed %[1]s.timer %[1]s.service >/dev/null 2>&1 || true\n", chaosPartitionUnit)
	fmt.Fprintf(&b, "sudo systemd-run --unit %s --on-active=%d /bin/sh -c %s >/dev/null\n",
		chaosPartitionUnit, int(deadman.Seconds()), shQuote(chaosHealBody(ips)))
	for _, ip := range ips {
		fmt.Fprintf(&b, "sudo iptables -I INPUT -s %s -m comment --comment %s -j DROP\n", ip, chaosPartitionComment)
		fmt.Fprintf(&b, "sudo iptables -I OUTPUT -d %s -m comment --comment %s -j DROP\n", ip, chaosPartitionComment)
	}
	b.WriteString("echo PARTITIONED\n")
	return b.String()
}

// ChaosHealScript undoes ChaosPartitionScript for ips and prints HEALED.
func ChaosHealScript(ips []string) string {
	return "sudo sh -c " + shQuote(chaosHealBody(ips)) + " && echo HEALED"
}

// NetemScript delays and drops the node's packets to peers only: a 4-band
// prio qdisc whose default priomap uses bands 1..3, a netem qdisc on band 4,
// and one u32 filter per peer address sending it there. SSH from the
// operator and traffic to the internet are untouched, so the case measures
// the cluster's links and the harness stays in control. A dead-man removes
// the qdisc after deadman. sch_netem is not loaded on a fresh Ubuntu cloud
// kernel; the script loads it, installing linux-modules-extra if needed.
func NetemScript(peers []string, delay, loss string, deadman time.Duration) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString(`dev=$(ip -o route show default | awk '{print $5; exit}')` + "\n")
	b.WriteString(`[ -n "$dev" ]` + "\n")
	b.WriteString(`sudo modprobe sch_netem 2>/dev/null || { sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 && sudo modprobe sch_netem; }` + "\n")
	fmt.Fprintf(&b, "sudo systemctl stop %[1]s.timer %[1]s.service >/dev/null 2>&1 || true\n", chaosNetemUnit)
	fmt.Fprintf(&b, "sudo systemctl reset-failed %[1]s.timer %[1]s.service >/dev/null 2>&1 || true\n", chaosNetemUnit)
	fmt.Fprintf(&b, "sudo systemd-run --unit %s --on-active=%d /bin/sh -c \"tc qdisc del dev $dev root\" >/dev/null\n",
		chaosNetemUnit, int(deadman.Seconds()))
	b.WriteString(`sudo tc qdisc del dev "$dev" root >/dev/null 2>&1 || true` + "\n")
	b.WriteString(`sudo tc qdisc add dev "$dev" root handle 1: prio bands 4` + "\n")
	fmt.Fprintf(&b, "sudo tc qdisc add dev \"$dev\" parent 1:4 handle 40: netem delay %s loss %s\n", delay, loss)
	for _, ip := range peers {
		fmt.Fprintf(&b, "sudo tc filter add dev \"$dev\" parent 1: protocol ip prio 1 u32 match ip dst %s/32 flowid 1:4\n", ip)
	}
	b.WriteString(`echo "NETEM-ON $dev"` + "\n")
	return b.String()
}

// NetemClearScript removes NetemScript's qdisc and disarms its dead-man.
func NetemClearScript() string {
	return fmt.Sprintf(`dev=$(ip -o route show default | awk '{print $5; exit}'); sudo systemctl stop %s.timer >/dev/null 2>&1 || true; sudo tc qdisc del dev "$dev" root >/dev/null 2>&1 || true; echo NETEM-OFF`, chaosNetemUnit)
}

// ReconcileIntervalScript prints the node's SB_RECONCILE_INTERVAL as the
// daemon reads it (empty when unset).
const ReconcileIntervalScript = `sudo bash -c '. /etc/sandboxd/sandboxd.env 2>/dev/null; . /etc/sandboxd/cluster.env 2>/dev/null; printf "RECONCILE=%s\n" "${SB_RECONCILE_INTERVAL:-}"'`

// ParseReconcileInterval reads ReconcileIntervalScript's output, falling back
// to def (the daemon's default) when the variable is unset or unreadable.
func ParseReconcileInterval(out string, def time.Duration) time.Duration {
	for _, raw := range strings.Split(out, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(raw), "RECONCILE=")
		if !ok {
			continue
		}
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// KillSandboxdScript SIGKILLs sandboxd the way a crash or the OOM killer
// does: no shutdown path runs, nothing is flushed or handed off. systemd
// then restarts it by itself (Restart=always, RestartSec=5), which is the
// recovery a real node gets; a stop would run the graceful path instead.
const KillSandboxdScript = "sudo systemctl kill -s SIGKILL sandboxd && echo KILLED"

// FailpointArmScript arms failpoint name on the node for sandbox names that
// start with prefix (internal/failpoint), clearing a stale marker first so a
// hit read later is this arm's.
func FailpointArmScript(name, prefix string) string {
	path := failpoint.Dir + "/" + name
	return "set -e\n" +
		"sudo mkdir -p " + shQuote(failpoint.Dir) + "\n" +
		"sudo rm -f " + shQuote(path+failpoint.HitSuffix) + "\n" +
		"printf '%s\\n' " + shQuote(prefix) + " | sudo tee " + shQuote(path) + " >/dev/null\n" +
		"echo ARMED\n"
}

// FailpointDisarmScript removes the arm and the marker.
func FailpointDisarmScript(name string) string {
	path := failpoint.Dir + "/" + name
	return "sudo rm -f " + shQuote(path) + " " + shQuote(path+failpoint.HitSuffix) + " && echo DISARMED"
}

// FailpointHitScript prints "HIT <key>" when the failpoint fired on the node
// and "NOHIT" when it did not, then FP-DONE.
func FailpointHitScript(name string) string {
	marker := shQuote(failpoint.Dir + "/" + name + failpoint.HitSuffix)
	return "if sudo test -f " + marker + "; then printf 'HIT %s\\n' \"$(sudo cat " + marker + ")\"; else echo NOHIT; fi; echo FP-DONE"
}

// ParseFailpointHit reads FailpointHitScript's output. Output cut short is an
// error, never "no hit": a missed hit makes UC-480 skip as if the binary had
// no failpoints, which would hide the case rather than fail it.
func ParseFailpointHit(out string) (key string, hit bool, err error) {
	done, seen := false, false
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(raw)
		switch {
		case len(f) == 0:
		case f[0] == "HIT" && len(f) == 2:
			key, hit, seen = f[1], true, true
		case f[0] == "NOHIT" && len(f) == 1:
			seen = true
		case f[0] == "FP-DONE":
			done = true
		}
	}
	if !done || !seen {
		return "", false, fmt.Errorf("failpoint check incomplete: %s", strings.TrimSpace(snippet([]byte(out))))
	}
	return key, hit, nil
}

// RecoveryProbe is one probe of something the control plane must answer
// (UC-481): when it was sent, when the answer came, and whether it was right.
type RecoveryProbe struct {
	Sent     time.Time
	Answered time.Time
	OK       bool
}

// RecoveredAt is when a probed signal came back for good: the answer time of
// the first success sent after the last failure. "For good" matters both
// ways. A node may answer from a cache for a moment after a kill before it
// notices, so an early success must not count when failures follow it. And a
// probe sent during the outage that hung and then succeeded proves the
// signal was back when it answered, not when it was sent.
//
// sawOutage is false when no probe failed (the signal never went away, or
// was served from a cache throughout); ok is false when no success follows
// the last failure.
func RecoveredAt(probes []RecoveryProbe) (at time.Time, sawOutage, ok bool) {
	ps := append([]RecoveryProbe(nil), probes...)
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Sent.Before(ps[j].Sent) })
	last := -1
	for i, p := range ps {
		if !p.OK {
			last = i
		}
	}
	for _, p := range ps[last+1:] {
		if p.OK {
			return p.Answered, last >= 0, true
		}
	}
	return time.Time{}, last >= 0, false
}

// RecoveryStreak is how many probes (by send time) have succeeded since the
// last failure: the prober keeps going until every signal has a streak, so a
// recovery that flaps back down is still seen.
func RecoveryStreak(probes []RecoveryProbe) int {
	ps := append([]RecoveryProbe(nil), probes...)
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Sent.Before(ps[j].Sent) })
	n := 0
	for _, p := range ps {
		if p.OK {
			n++
		} else {
			n = 0
		}
	}
	return n
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }
