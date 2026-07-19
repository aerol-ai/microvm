package scaleobs

import (
	"expvar"
	"strconv"
	"strings"
	"sync"
	"time"
)

var DefaultDurationBuckets = []time.Duration{
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	5 * time.Second,
}

type DurationBuckets struct {
	m      *expvar.Map
	bounds []time.Duration
	labels []string
}

func NewDurationBuckets(name string, bounds ...time.Duration) *DurationBuckets {
	if len(bounds) == 0 {
		bounds = DefaultDurationBuckets
	}
	labels := make([]string, 0, len(bounds)+1)
	cp := make([]time.Duration, len(bounds))
	copy(cp, bounds)
	m := expvar.NewMap(name)
	for _, bound := range cp {
		label := durationLabel(bound)
		labels = append(labels, label)
		m.Add(label, 0)
	}
	labels = append(labels, "le_inf")
	m.Add("le_inf", 0)
	return &DurationBuckets{m: m, bounds: cp, labels: labels}
}

func (b *DurationBuckets) Observe(elapsed time.Duration) {
	if b == nil || b.m == nil {
		return
	}
	for i, bound := range b.bounds {
		if elapsed <= bound {
			b.m.Add(b.labels[i], 1)
			return
		}
	}
	b.m.Add("le_inf", 1)
}

func (b *DurationBuckets) Value(label string) int64 {
	if b == nil || b.m == nil {
		return 0
	}
	return IntValue(b.m.Get(label))
}

func (b *DurationBuckets) Count() int64 {
	if b == nil {
		return 0
	}
	var total int64
	for _, label := range b.labels {
		total += b.Value(label)
	}
	return total
}

// NestedDurationBuckets is a two-level expvar histogram: the outer map key
// is a caller label (e.g. create stage name) and inner keys are le_* buckets.
// The observability scraper emits these as key/key2 Prometheus labels.
type NestedDurationBuckets struct {
	root   *expvar.Map
	bounds []time.Duration
	labels []string
	cache  sync.Map // normalized label -> *expvar.Map
}

func NewNestedDurationBuckets(name string, bounds ...time.Duration) *NestedDurationBuckets {
	if len(bounds) == 0 {
		bounds = DefaultDurationBuckets
	}
	cp := make([]time.Duration, len(bounds))
	copy(cp, bounds)
	labels := make([]string, 0, len(cp)+1)
	for _, bound := range cp {
		labels = append(labels, durationLabel(bound))
	}
	labels = append(labels, "le_inf")
	return &NestedDurationBuckets{
		root:   expvar.NewMap(name),
		bounds: cp,
		labels: labels,
	}
}

func (n *NestedDurationBuckets) Observe(label string, elapsed time.Duration) {
	if n == nil || n.root == nil || strings.TrimSpace(label) == "" {
		return
	}
	m := n.bucketsFor(Key(label))
	for i, bound := range n.bounds {
		if elapsed <= bound {
			m.Add(n.labels[i], 1)
			return
		}
	}
	m.Add("le_inf", 1)
}

func (n *NestedDurationBuckets) bucketsFor(key string) *expvar.Map {
	if v, ok := n.cache.Load(key); ok {
		return v.(*expvar.Map)
	}
	sub := new(expvar.Map).Init()
	for _, label := range n.labels {
		sub.Add(label, 0)
	}
	if actual, loaded := n.cache.LoadOrStore(key, sub); loaded {
		return actual.(*expvar.Map)
	}
	n.root.Set(key, sub)
	return sub
}

// Value returns the bucket count for a label pair (tests and diagnostics).
func (n *NestedDurationBuckets) Value(label, bucket string) int64 {
	if n == nil || n.root == nil {
		return 0
	}
	sub, ok := n.root.Get(Key(label)).(*expvar.Map)
	if !ok || sub == nil {
		return 0
	}
	return IntValue(sub.Get(bucket))
}

func Add(m *expvar.Map, key string, delta int64) {
	if m == nil {
		return
	}
	m.Add(Key(key), delta)
}

func Set(m *expvar.Map, key string, value int64) {
	if m == nil {
		return
	}
	v := new(expvar.Int)
	v.Set(value)
	m.Set(Key(key), v)
}

func IntValue(v expvar.Var) int64 {
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

func Key(in string) string {
	in = strings.TrimSpace(strings.ToLower(in))
	if in == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(in))
	lastUnderscore := false
	for _, r := range in {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}

func durationLabel(d time.Duration) string {
	switch {
	case d%time.Second == 0:
		return "le_" + strconv.FormatInt(int64(d/time.Second), 10) + "s"
	case d%time.Millisecond == 0:
		return "le_" + strconv.FormatInt(int64(d/time.Millisecond), 10) + "ms"
	default:
		return "le_" + strconv.FormatInt(d.Nanoseconds(), 10) + "ns"
	}
}
