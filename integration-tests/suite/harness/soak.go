package harness

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Soak driver pieces for UC-482 (suite/z_cluster_soak_test.go): the per-node
// sample script, its parser and the pass rule. They live here, outside the
// integration build tag, so the rule that decides "this leaks" is
// unit-tested offline: a rule that read a missing reading as no growth, or a
// cut-short sample as a zero count, would pass every leak it exists to catch.

// SoakNodeScript prints one node's reading as "<key> <integer>" lines and
// ends with SOAK-DONE. A key the node cannot read (no containerd on a server,
// no python3, no Raft directory on a worker) is left out, never printed as 0.
//
//	pid               sandboxd's MainPID (0 when it is not running)
//	rss_kb, fds       its resident memory and open descriptors, from /proc
//	db_bytes          the SQLite store; wal_bytes its write-ahead log
//	raft_kb           the Raft directory (log segments, snapshots), on disk
//	tasks, containers containerd tasks and containers in the sandbox
//	                  namespace (containers only, on the docker engine)
//	active_snapshots  containerd's Active snapshots: one per container
//	                  rootfs; committed image layers are not counted, so a
//	                  first pull does not read as a leak
//	sandbox_rows      rows in the sandboxes table
//	netns_in_use      netns pool slots held (not free, not prewarmed)
//	host_ports        TCP host ports held by exposed ports
//
// RSS is printed in kB as /proc has it: mawk, Ubuntu's awk, prints a large
// product in exponent form. The store is read through python3's sqlite3 in
// read-only mode (nodes have no sqlite3 binary); a WAL reader takes no lock
// the daemon's writer waits on.
const SoakNodeScript = `set -u
vals=$(sudo bash -c '. /etc/sandboxd/sandboxd.env 2>/dev/null; . /etc/sandboxd/cluster.env 2>/dev/null; printf "%s\n%s\n%s\n%s\n" "${SB_CONTAINER_ENGINE:-docker}" "${SB_CONTAINERD_NAMESPACE:-aerolvm}" "${SB_DB_PATH:-/var/lib/sandboxd/state.db}" "${SB_RAFT_DATA_DIR:-}"')
eng=$(printf '%s\n' "$vals" | sed -n 1p)
ns=$(printf '%s\n' "$vals" | sed -n 2p)
db=$(printf '%s\n' "$vals" | sed -n 3p)
raft=$(printf '%s\n' "$vals" | sed -n 4p)
[ -n "$raft" ] || raft="$(dirname "$db")/raft"
pid=$(systemctl show -p MainPID --value sandboxd 2>/dev/null)
echo "pid ${pid:-0}"
if [ "${pid:-0}" != 0 ]; then
  kb=$(sudo awk '$1 == "VmRSS:" {print $2}' "/proc/$pid/status" 2>/dev/null)
  [ -n "$kb" ] && echo "rss_kb $kb"
  echo "fds $(sudo ls -1 "/proc/$pid/fd" 2>/dev/null | wc -l)"
fi
if sudo test -f "$db"; then
  echo "db_bytes $(sudo stat -c %s "$db")"
  if sudo test -f "$db-wal"; then echo "wal_bytes $(sudo stat -c %s "$db-wal")"; else echo "wal_bytes 0"; fi
fi
if sudo test -d "$raft"; then echo "raft_kb $(sudo du -sk "$raft" | cut -f1)"; fi
if [ "$eng" = containerd ]; then
  if sudo ctr -n "$ns" version >/dev/null 2>&1; then
    echo "tasks $(sudo ctr -n "$ns" task ls -q 2>/dev/null | wc -l)"
    echo "containers $(sudo ctr -n "$ns" containers ls -q 2>/dev/null | wc -l)"
    echo "active_snapshots $(sudo ctr -n "$ns" snapshots ls 2>/dev/null | awk 'NR > 1 && $NF == "Active"' | wc -l)"
  fi
elif sudo docker info >/dev/null 2>&1; then
  echo "containers $(sudo docker ps -aq --filter label=aerolvm.managed=true 2>/dev/null | wc -l)"
fi
if sudo test -f "$db" && command -v python3 >/dev/null 2>&1; then
  sudo python3 - "$db" <<'PY' 2>/dev/null || true
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True, timeout=5)
for key, sql in (
    ("sandbox_rows", "SELECT COUNT(*) FROM sandboxes"),
    ("netns_in_use", "SELECT COUNT(*) FROM container_netns_slots WHERE state NOT IN ('free', 'pooled')"),
    ("host_ports", "SELECT COUNT(*) FROM exposed_ports WHERE host_port > 0"),
):
    try:
        print(key, db.execute(sql).fetchone()[0])
    except sqlite3.Error:
        pass
PY
fi
echo SOAK-DONE
`

var soakKeyRE = regexp.MustCompile(`^[a-z_]+$`)

// ParseSoakNode reads SoakNodeScript's output. Lines it does not know (an SSH
// banner, a sudo warning) are ignored. Output without SOAK-DONE is an error,
// so a dropped SSH session never reads as a node holding nothing; so is a
// sandboxd that is not running, whose readings say nothing about it.
func ParseSoakNode(out string) (map[string]int64, error) {
	vals := map[string]int64{}
	done := false
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(raw)
		if len(f) == 1 && f[0] == "SOAK-DONE" {
			done = true
			continue
		}
		if len(f) != 2 || !soakKeyRE.MatchString(f[0]) {
			continue
		}
		if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			vals[f[0]] = n
		}
	}
	if !done {
		return nil, fmt.Errorf("soak sample incomplete (the script did not finish): %s", strings.TrimSpace(snippet([]byte(out))))
	}
	if vals["pid"] <= 0 {
		return vals, fmt.Errorf("sandboxd is not running (MainPID %d)", vals["pid"])
	}
	return vals, nil
}

// SoakNode is one node's reading in one sample. Values also carries what the
// suite reads from the node's /v1/metrics: goroutines
// (aerolvm_go_goroutines) and routes (aerolvm_ingress_routes_total).
type SoakNode struct {
	Role   string           `json:"role"`
	Values map[string]int64 `json:"values,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// SoakSample is one sample of the whole fleet, written as one JSON line.
type SoakSample struct {
	At    time.Time `json:"at"`
	Phase string    `json:"phase"` // baseline | load | settled
	// Placements is the cluster's placement count, -1 when the index could
	// not be read.
	Placements int64               `json:"placements"`
	Nodes      map[string]SoakNode `json:"nodes"`
	// The load's progress when the sample was taken, so each line explains
	// itself without the test log.
	Cycles int64 `json:"cycles,omitempty"`
	Errors int64 `json:"errors,omitempty"`
}

// SoakCounts are the per-node readings that must be back at (or below) their
// pre-soak value once the load has drained and a reconcile interval has
// passed. Each is something a create takes and its delete must give back.
var SoakCounts = []string{"tasks", "containers", "active_snapshots", "netns_in_use", "host_ports", "sandbox_rows", "routes"}

// SoakLimit is how far a reading's median over the last third of the load
// may sit above its median over the first third: the larger of Ratio of the
// first and Floor. The floor keeps a small number's ordinary jitter (40
// goroutines becoming 52) from reading as a 30% leak; the ratio is what a
// real leak, which grows with the cycle count, crosses on a long run.
type SoakLimit struct {
	Ratio float64
	Floor float64
}

// SoakGrowthLimits are the readings that grow under load and must level off.
// The floors are each reading's normal step under steady load, not a guess
// at a leak's size:
var SoakGrowthLimits = map[string]SoakLimit{
	// Requests in flight when the sample lands each hold a few goroutines.
	"goroutines": {Ratio: 0.20, Floor: 200},
	// Go's heap goal steps up and the scavenger returns pages lazily.
	"rss_kb": {Ratio: 0.20, Floor: 64 << 10},
	// Each in-flight request holds a socket or two.
	"fds": {Ratio: 0.20, Floor: 64},
	// SQLite never shrinks the WAL after a checkpoint: it sits at its
	// high-water mark, which a burst can raise once.
	"wal_bytes": {Ratio: 0.20, Floor: 64 << 20},
	// raft-wal works in segment files and a snapshot every 1024 entries
	// (internal/cluster/raft.go), so the directory moves in steps.
	"raft_kb": {Ratio: 0.20, Floor: 128 << 10},
}

// SoakGrowthResult is the growth rule applied to one reading on one node.
type SoakGrowthResult struct {
	Node    string
	Key     string
	First   float64 // median of the first third
	Last    float64 // median of the last third
	Allowed float64
	Samples int
}

// OK reports whether the reading levelled off.
func (r SoakGrowthResult) OK() bool { return r.Last <= r.Allowed }

func (r SoakGrowthResult) String() string {
	return fmt.Sprintf("%s %s: first-third median %.0f, last-third %.0f (allowed %.0f, %d samples)", r.Node, r.Key, r.First, r.Last, r.Allowed, r.Samples)
}

// SoakGrowth applies the rule to one series. ok is false when there are
// fewer than three samples, so no third has a sample of its own.
func SoakGrowth(series []int64, lim SoakLimit) (SoakGrowthResult, bool) {
	n := len(series)
	if n < 3 {
		return SoakGrowthResult{Samples: n}, false
	}
	k := n / 3
	first, last := median(series[:k]), median(series[n-k:])
	return SoakGrowthResult{
		First:   first,
		Last:    last,
		Allowed: first + math.Max(first*lim.Ratio, lim.Floor),
		Samples: n,
	}, true
}

func median(xs []int64) float64 {
	s := append([]int64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	m := len(s) / 2
	if len(s)%2 == 1 {
		return float64(s[m])
	}
	return float64(s[m-1]+s[m]) / 2
}

// SoakResult is UC-482's pass rule applied to one run.
type SoakResult struct {
	// Problems fail the case. Notes say where the rule could not be applied
	// and why.
	Problems []string
	Notes    []string
	// Growth is every growth result, passing or not, for the log.
	Growth []SoakGrowthResult
	// CountsBack is true when every node was read after the drain and every
	// count, the placements included, was back at or below its baseline:
	// the convergence half of the rule, reported as I6.
	CountsBack bool
}

// SoakVerdict applies UC-482's pass rule to a run: the baseline taken before
// the load, every load sample, and the sample taken after the drain plus a
// reconcile interval.
//
// A reading the baseline never had (python3 missing, a server with no
// containerd) is skipped; one the baseline had and the settled sample lost is
// a problem, because "not read" must never pass as "back to baseline". A
// sandboxd restart anywhere in the run is a problem too: it resets every
// counter the soak watches and would hide the leak that caused it.
func SoakVerdict(baseline SoakSample, load []SoakSample, settled SoakSample) SoakResult {
	var problems, notes []string
	var growth []SoakGrowthResult
	countsBack := true
	nodes := make([]string, 0, len(baseline.Nodes))
	for n := range baseline.Nodes {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	growthKeys := make([]string, 0, len(SoakGrowthLimits))
	for k := range SoakGrowthLimits {
		growthKeys = append(growthKeys, k)
	}
	sort.Strings(growthKeys)

	for _, node := range nodes {
		base := baseline.Nodes[node]
		if base.Error != "" {
			problems = append(problems, fmt.Sprintf("%s: no baseline reading: %s", node, base.Error))
			countsBack = false
			continue
		}
		after, ok := settled.Nodes[node]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: no reading after the drain", node))
			countsBack = false
		case after.Error != "":
			problems = append(problems, fmt.Sprintf("%s: no reading after the drain: %s", node, after.Error))
			countsBack = false
		}

		// One sandboxd process throughout.
		pid := base.Values["pid"]
		missed := 0
		readings := append(append([]SoakSample(nil), load...), settled)
		for _, s := range readings {
			r, ok := s.Nodes[node]
			if !ok || r.Error != "" {
				if s.Phase == "load" {
					missed++
				}
				continue
			}
			if p := r.Values["pid"]; p != pid {
				problems = append(problems, fmt.Sprintf("%s: sandboxd restarted during the soak (pid %d, then %d at %s); a restart resets the counters the soak watches", node, pid, p, s.At.Format(time.RFC3339)))
				break
			}
		}
		if missed > 0 {
			notes = append(notes, fmt.Sprintf("%s: %d of %d load samples could not be read", node, missed, len(load)))
		}

		// Counts back to the baseline.
		if ok && after.Error == "" {
			for _, key := range SoakCounts {
				b, had := base.Values[key]
				if !had {
					continue
				}
				a, has := after.Values[key]
				switch {
				case !has:
					problems = append(problems, fmt.Sprintf("%s: %s was read before the soak (%d) but not after the drain", node, key, b))
					countsBack = false
				case a > b:
					problems = append(problems, fmt.Sprintf("%s: %s is %d after the drain, %d before the soak", node, key, a, b))
					countsBack = false
				}
			}
		}

		// Growth levelled off.
		for _, key := range growthKeys {
			var series []int64
			for _, s := range load {
				if r, ok := s.Nodes[node]; ok && r.Error == "" {
					if v, ok := r.Values[key]; ok {
						series = append(series, v)
					}
				}
			}
			if _, had := base.Values[key]; !had && len(series) == 0 {
				continue
			}
			res, enough := SoakGrowth(series, SoakGrowthLimits[key])
			res.Node, res.Key = node, key
			if !enough {
				notes = append(notes, fmt.Sprintf("%s %s: %d load samples, too few for the growth rule (it needs 3)", node, key, len(series)))
				continue
			}
			growth = append(growth, res)
			if !res.OK() {
				problems = append(problems, "grew under steady load: "+res.String())
			}
		}
	}

	switch {
	case baseline.Placements < 0 || settled.Placements < 0:
		problems = append(problems, fmt.Sprintf("the placement count was not read (before %d, after %d)", baseline.Placements, settled.Placements))
		countsBack = false
	case settled.Placements > baseline.Placements:
		problems = append(problems, fmt.Sprintf("%d placements after the drain, %d before the soak", settled.Placements, baseline.Placements))
		countsBack = false
	}
	return SoakResult{Problems: problems, Notes: notes, Growth: growth, CountsBack: countsBack}
}
