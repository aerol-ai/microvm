package usagemetrics

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

// value returns the series of family name for owner ("" for a family with
// no owner label) and whether it exists.
func value(fams []Family, name, owner string) (float64, bool) {
	for _, f := range fams {
		if f.Name != name {
			continue
		}
		for _, s := range f.Samples {
			o, hasOwner := "", false
			for _, l := range s.Labels {
				if l.Name == "owner" {
					o, hasOwner = l.Value, true
				}
			}
			if o == owner || (!hasOwner && owner == "") {
				return s.Value, true
			}
		}
	}
	return 0, false
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// step is one call on a meter: an Observe (rows set) or a Close (closeID set).
type step struct {
	now     int
	rows    []Sandbox
	closeID string
}

func run(m *Meter, steps []step) {
	for _, s := range steps {
		if s.closeID != "" {
			m.Close(s.closeID, at(s.now))
			continue
		}
		m.Observe(at(s.now), s.rows, 0)
	}
}

func running(id, owner string, cpu float64, memMB int, created int) Sandbox {
	return Sandbox{ID: id, Owner: owner, CPU: cpu, MemoryMB: memMB, Running: true, CreatedAt: at(created), UpdatedAt: at(created)}
}

func stopped(sb Sandbox, updated int) Sandbox {
	sb.Running = false
	sb.UpdatedAt = at(updated)
	return sb
}

func TestMeterReserved(t *testing.T) {
	a := running("a", "acme", 2, 1024, 5) // made 5 s after the process
	old := running("old", "acme", 1, 512, -100)
	cases := []struct {
		name    string
		steps   []step
		wantCPU float64
		wantMem float64
	}{
		{
			name:    "a sandbox made between samples is charged from its creation",
			steps:   []step{{now: 0}, {now: 15, rows: []Sandbox{a}}},
			wantCPU: 2 * 10, wantMem: 1024 * 10,
		},
		{
			name:    "an older sandbox is charged from the process start on the first sample",
			steps:   []step{{now: 15, rows: []Sandbox{old}}},
			wantCPU: 15, wantMem: 512 * 15,
		},
		{
			name:    "a running sandbox keeps being charged sample after sample",
			steps:   []step{{now: 15, rows: []Sandbox{a}}, {now: 30, rows: []Sandbox{a}}, {now: 45, rows: []Sandbox{a}}},
			wantCPU: 2 * 40, wantMem: 1024 * 40,
		},
		{
			name:    "a stopped sandbox is charged up to its row's last write",
			steps:   []step{{now: 15, rows: []Sandbox{a}}, {now: 30, rows: []Sandbox{stopped(a, 20)}}},
			wantCPU: 2 * 15, wantMem: 1024 * 15,
		},
		{
			name: "a stop time before the last sample charges nothing more",
			steps: []step{{now: 15, rows: []Sandbox{a}}, {now: 30, rows: []Sandbox{a}},
				{now: 45, rows: []Sandbox{stopped(a, 25)}}},
			wantCPU: 2 * 25, wantMem: 1024 * 25,
		},
		{
			name: "a stop time after the sample is held to the sample",
			steps: []step{{now: 15, rows: []Sandbox{a}},
				{now: 30, rows: []Sandbox{stopped(a, 99)}}},
			wantCPU: 2 * 25, wantMem: 1024 * 25,
		},
		{
			name:    "a sandbox removed mid-interval is charged up to its removal",
			steps:   []step{{now: 15, rows: []Sandbox{a}}, {now: 22, closeID: "a"}, {now: 30}},
			wantCPU: 2 * 17, wantMem: 1024 * 17,
		},
		{
			name: "a store read from before the removal does not open it again",
			steps: []step{{now: 15, rows: []Sandbox{a}}, {now: 22, closeID: "a"},
				{now: 30, rows: []Sandbox{a}}, {now: 45}},
			wantCPU: 2 * 17, wantMem: 1024 * 17,
		},
		{
			name:    "a sandbox that vanished with no stop time is charged up to the last sample",
			steps:   []step{{now: 15, rows: []Sandbox{a}}, {now: 30}},
			wantCPU: 2 * 10, wantMem: 1024 * 10,
		},
		{
			name: "a resize counts from the sample that sees it",
			steps: []step{{now: 15, rows: []Sandbox{a}},
				{now: 30, rows: []Sandbox{{ID: "a", Owner: "acme", CPU: 4, MemoryMB: 2048, Running: true, CreatedAt: at(5)}}},
				{now: 45, rows: []Sandbox{{ID: "a", Owner: "acme", CPU: 4, MemoryMB: 2048, Running: true, CreatedAt: at(5)}}}},
			wantCPU: 2*25 + 4*15, wantMem: 1024*25 + 2048*15,
		},
		{
			name: "a sandbox that starts again is charged again",
			steps: []step{{now: 15, rows: []Sandbox{a}}, {now: 30, rows: []Sandbox{stopped(a, 20)}},
				{now: 45, rows: []Sandbox{a}}, {now: 60, rows: []Sandbox{a}}},
			wantCPU: 2*15 + 2*30, wantMem: 1024*15 + 1024*30,
		},
		{
			name: "a clock that steps back charges nothing",
			steps: []step{{now: 15, rows: []Sandbox{a}}, {now: 10, rows: []Sandbox{a}},
				{now: 30, rows: []Sandbox{a}}},
			wantCPU: 2 * 25, wantMem: 1024 * 25,
		},
		{
			name:    "a sandbox dated in the future is charged nothing yet",
			steps:   []step{{now: 15, rows: []Sandbox{running("f", "acme", 2, 1024, 60)}}},
			wantCPU: 0, wantMem: 0,
		},
		{
			name:    "negative sizes from a bad row charge nothing",
			steps:   []step{{now: 15, rows: []Sandbox{running("n", "acme", -1, -5, 0)}}, {now: 30, rows: []Sandbox{running("n", "acme", -1, -5, 0)}}},
			wantCPU: 0, wantMem: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMeter("inc", t0)
			run(m, tc.steps)
			fams := m.Collect()
			cpu, ok := value(fams, MetricReservedCPU, "acme")
			if !ok {
				t.Fatalf("no %s series for acme", MetricReservedCPU)
			}
			mem, _ := value(fams, MetricReservedMemory, "acme")
			if !near(cpu, tc.wantCPU) || !near(mem, tc.wantMem) {
				t.Fatalf("reserved cpu, mem = %v, %v; want %v, %v", cpu, mem, tc.wantCPU, tc.wantMem)
			}
		})
	}
}

func TestMeterConsumed(t *testing.T) {
	read := func(cpu float64, memMiB uint64) *Consumed {
		return &Consumed{CPUSeconds: cpu, MemoryBytes: memMiB << 20}
	}
	with := func(sb Sandbox, c *Consumed) Sandbox { sb.Consumed = c; return sb }
	fresh := running("a", "acme", 1, 512, 5)
	old := running("old", "acme", 1, 512, -100)
	cases := []struct {
		name    string
		steps   []step
		wantCPU float64
		wantMem float64
	}{
		{
			name:    "a sandbox made during this process counts its first reading in full",
			steps:   []step{{now: 15, rows: []Sandbox{with(fresh, read(3, 100))}}},
			wantCPU: 3, wantMem: 100 * 10,
		},
		{
			name: "an older sandbox's first reading is only a baseline",
			steps: []step{{now: 15, rows: []Sandbox{with(old, read(500, 100))}},
				{now: 30, rows: []Sandbox{with(old, read(507, 200))}}},
			wantCPU: 7, wantMem: 100*15 + 200*15,
		},
		{
			name: "a count that goes down is a new cgroup and counts in full",
			steps: []step{{now: 15, rows: []Sandbox{with(old, read(500, 0))}},
				{now: 30, rows: []Sandbox{with(old, read(4, 0))}}},
			wantCPU: 4, wantMem: 0,
		},
		{
			name: "a failed reading leaves a gap the next reading covers",
			steps: []step{{now: 15, rows: []Sandbox{with(fresh, read(1, 100))}},
				{now: 30, rows: []Sandbox{fresh}},
				{now: 45, rows: []Sandbox{with(fresh, read(6, 100))}}},
			wantCPU: 6, wantMem: 100 * 40,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMeter("inc", t0)
			run(m, tc.steps)
			fams := m.Collect()
			cpu, _ := value(fams, MetricConsumedCPU, "acme")
			mem, _ := value(fams, MetricConsumedMemory, "acme")
			if !near(cpu, tc.wantCPU) || !near(mem, tc.wantMem) {
				t.Fatalf("consumed cpu, mem = %v, %v; want %v, %v", cpu, mem, tc.wantCPU, tc.wantMem)
			}
		})
	}
}

// Every counter only grows, through stops, removals, resizes, cgroup
// resets, a clock step back and owners coming and going.
func TestMeterCountersOnlyGrow(t *testing.T) {
	m := NewMeter("inc", t0)
	a := running("a", "acme", 2, 1024, 1)
	b := running("b", "beta", 1, 256, 3)
	reading := func(sb Sandbox, cpu float64) Sandbox {
		sb.Consumed = &Consumed{CPUSeconds: cpu, MemoryBytes: 64 << 20}
		return sb
	}
	steps := []step{
		{now: 10, rows: []Sandbox{reading(a, 5), reading(b, 1)}},
		{now: 20, rows: []Sandbox{reading(a, 9), stopped(b, 15)}},
		{now: 25, closeID: "a"},
		{now: 18, rows: []Sandbox{reading(a, 2)}},
		{now: 40, rows: []Sandbox{reading(b, 0.5)}},
		{now: 50, rows: []Sandbox{reading(b, 0.2)}},
		{now: 60},
		{now: 60 + int(OwnerRetention/time.Second) + 1},
		{now: 7300, rows: []Sandbox{reading(a, 1)}},
	}
	last := map[string]float64{}
	for i, s := range steps {
		run(m, []step{s})
		// A series that went away (an owner past its retention) and comes
		// back is a new series to Prometheus, so only series present in
		// both collections are compared.
		seen := map[string]float64{}
		for _, f := range m.Collect() {
			if f.Type != "counter" {
				continue
			}
			for _, smp := range f.Samples {
				key := f.Name
				for _, l := range smp.Labels {
					key += "|" + l.Value
				}
				if prev, ok := last[key]; ok && smp.Value < prev {
					t.Fatalf("step %d: %s went from %v to %v", i, key, prev, smp.Value)
				}
				seen[key] = smp.Value
			}
		}
		last = seen
	}
}

func TestMeterOwnerVisibility(t *testing.T) {
	a := running("a", "acme", 1, 128, 1)
	idle := stopped(running("z", "zeta", 1, 128, 1), 1)
	retention := int(OwnerRetention / time.Second)
	cases := []struct {
		name      string
		steps     []step
		wantOwner map[string]bool
	}{
		{
			name:      "an owner whose sandboxes never ran here is not exported",
			steps:     []step{{now: 10, rows: []Sandbox{a, idle}}},
			wantOwner: map[string]bool{"acme": true, "zeta": false},
		},
		{
			name:      "an owner keeps its final value after its last sandbox stops",
			steps:     []step{{now: 10, rows: []Sandbox{a}}, {now: 20, rows: []Sandbox{stopped(a, 15)}}, {now: 15 + retention - 1}},
			wantOwner: map[string]bool{"acme": true},
		},
		{
			name:      "an owner goes once the retention has passed",
			steps:     []step{{now: 10, rows: []Sandbox{a}}, {now: 20, rows: []Sandbox{stopped(a, 15)}}, {now: 15 + retention}},
			wantOwner: map[string]bool{"acme": false},
		},
		{
			name:      "an owner with a sandbox still running never goes",
			steps:     []step{{now: 10, rows: []Sandbox{a}}, {now: 10 + 2*retention, rows: []Sandbox{a}}},
			wantOwner: map[string]bool{"acme": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMeter("inc", t0)
			run(m, tc.steps)
			fams := m.Collect()
			for owner, want := range tc.wantOwner {
				for _, name := range []string{MetricReservedCPU, MetricReservedMemory, MetricConsumedCPU, MetricConsumedMemory} {
					if _, got := value(fams, name, owner); got != want {
						t.Fatalf("%s{owner=%q} exported = %v, want %v", name, owner, got, want)
					}
				}
			}
		})
	}
}

// A restart is a new process with a new incarnation: its series are new
// series, never the old ones going backwards.
func TestMeterIncarnationLabel(t *testing.T) {
	first, second := NewIncarnation(), NewIncarnation()
	if first == second || len(first) != 16 {
		t.Fatalf("NewIncarnation() = %q then %q; want two different 16-character values", first, second)
	}
	for _, inc := range []string{first, second} {
		m := NewMeter(inc, t0)
		if m.Incarnation() != inc {
			t.Fatalf("Incarnation() = %q, want %q", m.Incarnation(), inc)
		}
		m.Observe(at(10), []Sandbox{running("a", "acme", 1, 1, 0)}, 2)
		for _, f := range m.Collect() {
			for _, s := range f.Samples {
				var got string
				for _, l := range s.Labels {
					if l.Name == "incarnation" {
						got = l.Value
					}
				}
				if got != inc {
					t.Fatalf("%s has incarnation %q, want %q", f.Name, got, inc)
				}
			}
		}
	}
}

func TestMeterProcessSeries(t *testing.T) {
	m := NewMeter("inc", t0)
	if _, ok := value(m.Collect(), MetricLastSample, ""); ok {
		t.Fatalf("%s exported before the first sample", MetricLastSample)
	}
	if v, ok := value(m.Collect(), MetricReadFailures, ""); !ok || v != 0 {
		t.Fatalf("%s = %v, %v before any sample; want 0, true", MetricReadFailures, v, ok)
	}
	m.Observe(at(15), nil, 3)
	m.Observe(at(30), nil, 0)
	fams := m.Collect()
	if v, _ := value(fams, MetricLastSample, ""); !near(v, float64(at(30).Unix())) {
		t.Fatalf("%s = %v, want %v", MetricLastSample, v, at(30).Unix())
	}
	if v, _ := value(fams, MetricReadFailures, ""); v != 3 {
		t.Fatalf("%s = %v, want 3", MetricReadFailures, v)
	}
	if _, ok := value(fams, MetricReservedCPU, "acme"); ok {
		t.Fatalf("an owner series with no sandboxes")
	}
}

func TestNilMeterClose(t *testing.T) {
	var m *Meter
	m.Close("a", t0) // the exporter is off: nothing to do, and no panic
}
