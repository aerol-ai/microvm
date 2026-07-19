package scaleobs

import (
	"expvar"
	"testing"
	"time"
)

func TestDurationBuckets_ObserveHitsCorrectBucket(t *testing.T) {
	b := NewDurationBuckets("test_obs_bucket_"+t.Name(),
		10*time.Millisecond, 100*time.Millisecond, time.Second)

	b.Observe(5 * time.Millisecond) // <= 10ms bucket
	if b.Value("le_10ms") != 1 {
		t.Errorf("le_10ms = %d, want 1", b.Value("le_10ms"))
	}
	if b.Value("le_100ms") != 0 {
		t.Errorf("le_100ms = %d, want 0", b.Value("le_100ms"))
	}

	b.Observe(50 * time.Millisecond) // <= 100ms bucket
	if b.Value("le_100ms") != 1 {
		t.Errorf("le_100ms = %d, want 1", b.Value("le_100ms"))
	}

	b.Observe(500 * time.Millisecond) // <= 1s bucket
	if b.Value("le_1s") != 1 {
		t.Errorf("le_1s = %d, want 1", b.Value("le_1s"))
	}
}

func TestDurationBuckets_ObserveInfBucket(t *testing.T) {
	b := NewDurationBuckets("test_obs_inf_"+t.Name(), 10*time.Millisecond)
	b.Observe(time.Hour) // exceeds all bounds → le_inf
	if b.Value("le_inf") != 1 {
		t.Errorf("le_inf = %d, want 1", b.Value("le_inf"))
	}
	if b.Value("le_10ms") != 0 {
		t.Errorf("le_10ms = %d, want 0 (oversized observation)", b.Value("le_10ms"))
	}
}

func TestDurationBuckets_ObserveExactBoundary(t *testing.T) {
	b := NewDurationBuckets("test_obs_exact_"+t.Name(), 50*time.Millisecond, 100*time.Millisecond)
	b.Observe(50 * time.Millisecond) // exactly on boundary → goes into that bucket
	if b.Value("le_50ms") != 1 {
		t.Errorf("le_50ms = %d, want 1 (boundary inclusive)", b.Value("le_50ms"))
	}
}

func TestDurationBuckets_Count(t *testing.T) {
	b := NewDurationBuckets("test_count_"+t.Name(), 10*time.Millisecond, 100*time.Millisecond)
	if b.Count() != 0 {
		t.Errorf("Count() = %d, want 0 before any observations", b.Count())
	}
	b.Observe(5 * time.Millisecond)
	b.Observe(50 * time.Millisecond)
	b.Observe(time.Second) // goes to le_inf
	if b.Count() != 3 {
		t.Errorf("Count() = %d, want 3", b.Count())
	}
}

func TestDurationBuckets_NilReceiverIsNoop(t *testing.T) {
	var b *DurationBuckets
	b.Observe(time.Second) // must not panic
	if b.Count() != 0 {
		t.Errorf("nil Count() = %d, want 0", b.Count())
	}
	if b.Value("le_1s") != 0 {
		t.Errorf("nil Value = %d, want 0", b.Value("le_1s"))
	}
}

func TestDurationBuckets_DefaultBounds(t *testing.T) {
	b := NewDurationBuckets("test_default_bounds_" + t.Name()) // no explicit bounds
	// Observe a value that hits the le_25ms bucket (default bounds include 25ms).
	b.Observe(20 * time.Millisecond)
	if b.Value("le_25ms") != 1 {
		t.Errorf("le_25ms = %d, want 1 with default bounds", b.Value("le_25ms"))
	}
}

func TestAdd_NilMapIsNoop(t *testing.T) {
	Add(nil, "key", 1) // must not panic
}

func TestAdd_Valid(t *testing.T) {
	m := new(expvar.Map).Init()
	Add(m, "my key", 5)
	if IntValue(m.Get("my_key")) != 5 {
		t.Errorf("Add: got %d, want 5", IntValue(m.Get("my_key")))
	}
}

func TestSet_NilMapIsNoop(t *testing.T) {
	Set(nil, "key", 42) // must not panic
}

func TestSet_Valid(t *testing.T) {
	m := new(expvar.Map).Init()
	Set(m, "counter", 99)
	if IntValue(m.Get("counter")) != 99 {
		t.Errorf("Set: got %d, want 99", IntValue(m.Get("counter")))
	}
}

func TestIntValue_Nil(t *testing.T) {
	if IntValue(nil) != 0 {
		t.Errorf("IntValue(nil) = %d, want 0", IntValue(nil))
	}
}

func TestIntValue_Valid(t *testing.T) {
	v := new(expvar.Int)
	v.Set(42)
	if IntValue(v) != 42 {
		t.Errorf("IntValue = %d, want 42", IntValue(v))
	}
}

func TestKey_Normalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"foo bar", "foo_bar"},
		{"FOO BAR", "foo_bar"},
		{"  leading", "leading"},
		{"trailing  ", "trailing"},
		{"foo--bar", "foo_bar"},
		{"", "unknown"},
		{"   ", "unknown"},
		{"special!@#chars", "special_chars"},
		{"a1b2c3", "a1b2c3"},
		{"__only__underscores__", "only_underscores"},
	}
	for _, c := range cases {
		got := Key(c.in)
		if got != c.want {
			t.Errorf("Key(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDurationLabel(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Millisecond, "le_5ms"},
		{250 * time.Millisecond, "le_250ms"},
		{time.Second, "le_1s"},
		{5 * time.Second, "le_5s"},
		{500 * time.Nanosecond, "le_500ns"},
	}
	for _, c := range cases {
		got := durationLabel(c.d)
		if got != c.want {
			t.Errorf("durationLabel(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestNestedDurationBuckets_Observe(t *testing.T) {
	n := NewNestedDurationBuckets("test_nested_"+t.Name(),
		10*time.Millisecond, 100*time.Millisecond, time.Second)

	n.Observe("fc_verify", 5*time.Millisecond)
	if got := n.Value("fc_verify", "le_10ms"); got != 1 {
		t.Fatalf("fc_verify le_10ms = %d, want 1", got)
	}
	if got := n.Value("fc_verify", "le_100ms"); got != 0 {
		t.Fatalf("fc_verify le_100ms = %d, want 0", got)
	}

	n.Observe("fc_spawn", 50*time.Millisecond)
	if got := n.Value("fc_spawn", "le_100ms"); got != 1 {
		t.Fatalf("fc_spawn le_100ms = %d, want 1", got)
	}

	n.Observe("fc_warm", 2*time.Second)
	if got := n.Value("fc_warm", "le_inf"); got != 1 {
		t.Fatalf("fc_warm le_inf = %d, want 1", got)
	}
}

func TestNestedDurationBuckets_NilAndEmptyLabel(t *testing.T) {
	var n *NestedDurationBuckets
	n.Observe("fc_verify", time.Second)

	n = NewNestedDurationBuckets("test_nested_nil_" + t.Name())
	n.Observe("", time.Second)
	if got := n.Value("fc_verify", "le_1s"); got != 0 {
		t.Fatalf("empty label observe = %d, want 0", got)
	}
}
