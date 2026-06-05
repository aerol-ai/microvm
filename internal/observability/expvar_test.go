package observability

import (
	"expvar"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestCollectAerolVMExpvarsFiltersAndFlattens(t *testing.T) {
	suffix := time.Now().UnixNano()
	scalarName := fmt.Sprintf("aerolvm_observability_test_scalar_%d", suffix)
	expvar.NewInt(scalarName).Set(99)
	mapName := fmt.Sprintf("aerolvm_observability_test_map_%d", suffix)
	mapped := expvar.NewMap(mapName)
	mapped.Add("worker-a", 3)
	ignoredName := fmt.Sprintf("not_aerolvm_observability_test_%d", suffix)
	expvar.NewInt(ignoredName).Set(1)

	samples := CollectAerolVMExpvars()
	if !hasIntSample(samples, scalarName, "", "", 99) {
		t.Fatalf("missing scalar sample %q in %+v", scalarName, samples)
	}
	if !hasIntSample(samples, mapName, "key", "worker-a", 3) {
		t.Fatalf("missing map sample %q in %+v", mapName, samples)
	}
	for _, sample := range samples {
		if sample.Name == ignoredName {
			t.Fatalf("collector included non-aerolvm expvar %q", ignoredName)
		}
	}
}

func hasIntSample(samples []ExpvarSample, name, labelName, labelValue string, want int64) bool {
	for _, sample := range samples {
		if sample.Name != name || sample.Int64 == nil || *sample.Int64 != want {
			continue
		}
		if labelName == "" {
			return len(sample.Labels) == 0
		}
		for _, label := range sample.Labels {
			if label.Name == labelName && label.Value == labelValue {
				return true
			}
		}
	}
	return false
}

// rawVar is a minimal expvar.Var whose String() returns its value verbatim.
// expvar.String quotes its output (JSON), so we use this to exercise the
// default branch in sampleFromExpvar that parses bare numeric strings.
type rawVar string

func (r rawVar) String() string { return string(r) }

func TestSampleFromExpvar(t *testing.T) {
	t.Run("expvar_int", func(t *testing.T) {
		v := new(expvar.Int)
		v.Set(42)
		s, ok := sampleFromExpvar("m", nil, v)
		if !ok || s.Int64 == nil || *s.Int64 != 42 {
			t.Fatalf("expected Int64=42, got ok=%v sample=%+v", ok, s)
		}
		if s.Float != nil {
			t.Fatal("expected Float nil for Int var")
		}
	})

	t.Run("expvar_float_valid", func(t *testing.T) {
		v := new(expvar.Float)
		v.Set(3.14)
		s, ok := sampleFromExpvar("m", nil, v)
		if !ok || s.Float == nil {
			t.Fatalf("expected Float sample, got ok=%v sample=%+v", ok, s)
		}
		if math.Abs(*s.Float-3.14) > 1e-9 {
			t.Fatalf("Float = %v, want 3.14", *s.Float)
		}
	})

	t.Run("expvar_float_nan_filtered", func(t *testing.T) {
		v := new(expvar.Float)
		v.Set(math.NaN())
		_, ok := sampleFromExpvar("m", nil, v)
		if ok {
			t.Fatal("NaN float should be filtered (ok=false)")
		}
	})

	t.Run("expvar_float_inf_filtered", func(t *testing.T) {
		v := new(expvar.Float)
		v.Set(math.Inf(1))
		_, ok := sampleFromExpvar("m", nil, v)
		if ok {
			t.Fatal("+Inf float should be filtered (ok=false)")
		}
	})

	t.Run("string_backed_int", func(t *testing.T) {
		// A custom expvar.Var whose String() returns a bare integer (no JSON quotes).
		// This exercises the default branch that falls through to ParseInt.
		s, ok := sampleFromExpvar("m", nil, rawVar("99"))
		if !ok || s.Int64 == nil || *s.Int64 != 99 {
			t.Fatalf("expected Int64=99, got ok=%v sample=%+v", ok, s)
		}
	})

	t.Run("string_backed_float", func(t *testing.T) {
		s, ok := sampleFromExpvar("m", nil, rawVar("2.718"))
		if !ok || s.Float == nil {
			t.Fatalf("expected Float sample, got ok=%v sample=%+v", ok, s)
		}
		if math.Abs(*s.Float-2.718) > 1e-9 {
			t.Fatalf("Float = %v, want 2.718", *s.Float)
		}
	})

	t.Run("string_unparseable_filtered", func(t *testing.T) {
		_, ok := sampleFromExpvar("m", nil, rawVar("not-a-number"))
		if ok {
			t.Fatal("unparseable string should be filtered (ok=false)")
		}
	})

	t.Run("labels_copied", func(t *testing.T) {
		v := new(expvar.Int)
		v.Set(1)
		labels := []ExpvarLabel{{Name: "k", Value: "v"}}
		s, ok := sampleFromExpvar("m", labels, v)
		if !ok || len(s.Labels) != 1 || s.Labels[0].Name != "k" {
			t.Fatalf("labels not propagated: ok=%v sample=%+v", ok, s)
		}
		// mutating original labels must not affect the stored copy
		labels[0].Value = "changed"
		if s.Labels[0].Value != "v" {
			t.Fatal("labels were not deep-copied")
		}
	})

	t.Run("string_backed_float_with_spaces", func(t *testing.T) {
		s, ok := sampleFromExpvar("m", nil, rawVar(" 12.5 "))
		if !ok || s.Float == nil || math.Abs(*s.Float-12.5) > 1e-9 {
			t.Fatalf("expected Float=12.5, got ok=%v sample=%+v", ok, s)
		}
	})
}

func TestCollectExpvarSamplesNestedMap(t *testing.T) {
	root := new(expvar.Map).Init()
	child := new(expvar.Map).Init()
	leaf := new(expvar.Int)
	leaf.Set(7)
	child.Set("worker-a", leaf)
	root.Set("cluster-1", child)

	var samples []ExpvarSample
	collectExpvarSamples("aerolvm_nested", root, nil, &samples)
	if len(samples) != 1 {
		t.Fatalf("samples len = %d, want 1", len(samples))
	}
	if samples[0].Int64 == nil || *samples[0].Int64 != 7 {
		t.Fatalf("sample value = %+v, want int64 7", samples[0])
	}
	if len(samples[0].Labels) != 2 ||
		samples[0].Labels[0] != (ExpvarLabel{Name: "key", Value: "cluster-1"}) ||
		samples[0].Labels[1] != (ExpvarLabel{Name: "key2", Value: "worker-a"}) {
		t.Fatalf("nested labels = %+v", samples[0].Labels)
	}
}
