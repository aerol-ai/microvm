package observability

import (
	"expvar"
	"fmt"
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
