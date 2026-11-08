package harness

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

func TestParseSoakNode(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    map[string]int64
		wantErr string
	}{
		{
			name: "worker reading with a banner and a sudo warning",
			out: "Warning: Permanently added\nsudo: unable to resolve host w1: Name or service not known\n" +
				"pid 812\nrss_kb 154320\nfds 97\ndb_bytes 4096000\nwal_bytes 0\ntasks 3\ncontainers 3\nactive_snapshots 3\n" +
				"sandbox_rows 3\nnetns_in_use 3\nhost_ports 0\nSOAK-DONE\n",
			want: map[string]int64{"pid": 812, "rss_kb": 154320, "fds": 97, "db_bytes": 4096000, "wal_bytes": 0,
				"tasks": 3, "containers": 3, "active_snapshots": 3, "sandbox_rows": 3, "netns_in_use": 3, "host_ports": 0},
		},
		{
			// What a node cannot read is absent, never zero.
			name: "server reading has no containerd keys",
			out:  "pid 77\nrss_kb 9000\nfds 40\nraft_kb 2048\nSOAK-DONE\n",
			want: map[string]int64{"pid": 77, "rss_kb": 9000, "fds": 40, "raft_kb": 2048},
		},
		{
			name: "a non-integer value is dropped",
			out:  "pid 9\nfds lots\nSOAK-DONE\n",
			want: map[string]int64{"pid": 9},
		},
		{name: "cut short is an error, never zero counts", out: "pid 812\ntasks 0\n", wantErr: "incomplete"},
		{name: "empty", out: "", wantErr: "incomplete"},
		{name: "sandboxd not running", out: "pid 0\nSOAK-DONE\n", wantErr: "not running"},
		{name: "no pid line", out: "tasks 1\nSOAK-DONE\n", wantErr: "not running"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSoakNode(tt.out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Fatalf("%s = %d, want %d (all: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

func TestSoakGrowth(t *testing.T) {
	lim := SoakLimit{Ratio: 0.20, Floor: 50}
	tests := []struct {
		name    string
		series  []int64
		enough  bool
		ok      bool
		first   float64
		last    float64
		allowed float64
	}{
		{name: "flat", series: []int64{400, 410, 405, 398, 402, 409}, enough: true, ok: true, first: 405, last: 405.5, allowed: 486},
		{name: "a leak", series: []int64{400, 450, 500, 550, 600, 650}, enough: true, ok: false, first: 425, last: 625, allowed: 510},
		// 30 -> 70 is +133% but within the floor: small numbers jitter.
		{name: "small numbers stay under the floor", series: []int64{30, 31, 50, 60, 70, 70}, enough: true, ok: true, first: 30.5, last: 70, allowed: 80.5},
		// One spike in the last third does not move its median.
		{name: "a single spike", series: []int64{400, 400, 400, 400, 400, 400, 400, 2000, 400}, enough: true, ok: true, first: 400, last: 400, allowed: 480},
		{name: "three samples is the minimum", series: []int64{100, 100, 200}, enough: true, ok: false, first: 100, last: 200, allowed: 150},
		{name: "two samples are too few", series: []int64{1, 2}},
		{name: "none", series: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, enough := SoakGrowth(tt.series, lim)
			if enough != tt.enough {
				t.Fatalf("enough = %v, want %v", enough, tt.enough)
			}
			if !enough {
				return
			}
			if r.OK() != tt.ok || r.First != tt.first || r.Last != tt.last || r.Allowed != tt.allowed {
				t.Fatalf("got %+v ok=%v, want first %v last %v allowed %v ok=%v", r, r.OK(), tt.first, tt.last, tt.allowed, tt.ok)
			}
		})
	}
}

func soakNode(role string, kv ...int64) SoakNode {
	keys := []string{"pid", "goroutines", "tasks", "netns_in_use"}
	n := SoakNode{Role: role, Values: map[string]int64{}}
	for i, v := range kv {
		n.Values[keys[i]] = v
	}
	return n
}

func soakRun(goroutines []int64, settledTasks int64, settledPlacements int64) (SoakSample, []SoakSample, SoakSample) {
	base := SoakSample{Phase: "baseline", Placements: 10, Nodes: map[string]SoakNode{
		"worker-1": soakNode("worker", 100, 300, 2, 2),
	}}
	var load []SoakSample
	for _, g := range goroutines {
		load = append(load, SoakSample{Phase: "load", Placements: 14, Nodes: map[string]SoakNode{
			"worker-1": soakNode("worker", 100, g, 6, 6),
		}})
	}
	settled := SoakSample{Phase: "settled", Placements: settledPlacements, Nodes: map[string]SoakNode{
		"worker-1": soakNode("worker", 100, 300, settledTasks, 2),
	}}
	return base, load, settled
}

func TestSoakVerdict(t *testing.T) {
	flat := []int64{400, 410, 405, 398, 402, 409}
	t.Run("a clean run", func(t *testing.T) {
		r := SoakVerdict(soakRun(flat, 2, 10))
		if len(r.Problems) != 0 || len(r.Notes) != 0 || !r.CountsBack {
			t.Fatalf("%+v", r)
		}
		if len(r.Growth) != 1 || r.Growth[0].Key != "goroutines" || !r.Growth[0].OK() {
			t.Fatalf("growth = %v", r.Growth)
		}
	})
	t.Run("counts below the baseline pass", func(t *testing.T) {
		if r := SoakVerdict(soakRun(flat, 1, 9)); len(r.Problems) != 0 || !r.CountsBack {
			t.Fatalf("a count that fell is not a leak: %+v", r)
		}
	})
	// expect checks a problem is reported and whether the counts still
	// count as back (growth and restarts are not convergence failures).
	expect := func(t *testing.T, r SoakResult, want string, countsBack bool) {
		t.Helper()
		if r.CountsBack != countsBack {
			t.Errorf("CountsBack = %v, want %v (%v)", r.CountsBack, countsBack, r.Problems)
		}
		for _, p := range r.Problems {
			if strings.Contains(p, want) {
				return
			}
		}
		t.Fatalf("no problem mentions %q: %v", want, r.Problems)
	}
	t.Run("goroutines that keep growing", func(t *testing.T) {
		expect(t, SoakVerdict(soakRun([]int64{400, 500, 600, 700, 800, 900}, 2, 10)), "grew under steady load: worker-1 goroutines", true)
	})
	t.Run("a task left after the drain", func(t *testing.T) {
		expect(t, SoakVerdict(soakRun(flat, 3, 10)), "worker-1: tasks is 3 after the drain, 2 before", false)
	})
	t.Run("a placement left after the drain", func(t *testing.T) {
		expect(t, SoakVerdict(soakRun(flat, 2, 11)), "11 placements after the drain, 10 before", false)
	})
	t.Run("placements not read", func(t *testing.T) {
		expect(t, SoakVerdict(soakRun(flat, 2, -1)), "placement count was not read", false)
	})
	t.Run("a reading lost after the drain is not a pass", func(t *testing.T) {
		base, load, settled := soakRun(flat, 2, 10)
		delete(settled.Nodes["worker-1"].Values, "netns_in_use")
		expect(t, SoakVerdict(base, load, settled), "netns_in_use was read before the soak (2) but not after", false)
	})
	t.Run("no settled reading", func(t *testing.T) {
		base, load, settled := soakRun(flat, 2, 10)
		settled.Nodes["worker-1"] = SoakNode{Role: "worker", Error: "ssh: timeout"}
		expect(t, SoakVerdict(base, load, settled), "no reading after the drain: ssh: timeout", false)
	})
	t.Run("no baseline reading", func(t *testing.T) {
		base, load, settled := soakRun(flat, 2, 10)
		base.Nodes["worker-1"] = SoakNode{Role: "worker", Error: "census incomplete"}
		expect(t, SoakVerdict(base, load, settled), "worker-1: no baseline reading", false)
	})
	t.Run("a restart during the load", func(t *testing.T) {
		base, load, settled := soakRun(flat, 2, 10)
		load[3].Nodes["worker-1"].Values["pid"] = 4242
		expect(t, SoakVerdict(base, load, settled), "sandboxd restarted during the soak (pid 100, then 4242", true)
	})
	t.Run("missed load samples and too few for growth are notes", func(t *testing.T) {
		base, load, settled := soakRun(flat[:4], 2, 10)
		load[0].Nodes["worker-1"] = SoakNode{Role: "worker", Error: "ssh"}
		load[1].Nodes["worker-1"] = SoakNode{Role: "worker", Error: "ssh"}
		r := SoakVerdict(base, load, settled)
		if len(r.Problems) != 0 || !r.CountsBack {
			t.Fatalf("%+v", r)
		}
		joined := strings.Join(r.Notes, "\n")
		if !strings.Contains(joined, "2 of 4 load samples could not be read") || !strings.Contains(joined, "too few for the growth rule") {
			t.Fatalf("notes %v", r.Notes)
		}
	})
	t.Run("a reading no node has is skipped", func(t *testing.T) {
		// raft_kb on a worker: absent before and during, never a problem.
		r := SoakVerdict(soakRun(flat, 2, 10))
		for _, s := range append(r.Problems, r.Notes...) {
			if strings.Contains(s, "raft_kb") || strings.Contains(s, "host_ports") {
				t.Fatalf("an absent reading was judged: %s", s)
			}
		}
	})
}

// The store half of SoakNodeScript runs its SQL against a real schema here
// (internal/store creates it), so a renamed table or column fails offline
// rather than as a silently missing reading on a paid run.
func TestSoakScriptSQLMatchesTheStoreSchema(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ctx := context.Background()
	now := time.Now()
	for _, id := range []string{"slot-1", "slot-2", "slot-3"} {
		if err := st.SeedContainerNetnsSlot(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-1", now); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	start := strings.Index(SoakNodeScript, "<<'PY'")
	body := SoakNodeScript[start:]
	body = body[strings.Index(body, "\n")+1:]
	body = body[:strings.Index(body, "\nPY\n")]
	cmd := exec.Command(python, "-I", "-c", body, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the script's python failed: %v\n%s", err, out)
	}
	vals, err := ParseSoakNode("pid 1\n" + string(out) + "SOAK-DONE\n")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"sandbox_rows": 0, "netns_in_use": 1, "host_ports": 0}
	for k, v := range want {
		got, ok := vals[k]
		if !ok || got != v {
			t.Errorf("%s = %d (present %v), want %d; output:\n%s", k, got, ok, v, out)
		}
	}
}
