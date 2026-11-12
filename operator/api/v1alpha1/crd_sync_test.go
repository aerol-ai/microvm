package v1alpha1

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The chart's CRDs are the generated ones, byte for byte: Helm installs
// charts/aerolvm/crds, and a field the operator reads but the chart's CRD
// lacks is pruned by the API server on every write.
func TestChartCRDsMatch(t *testing.T) {
	gen, err := filepath.Glob("../../config/crd/*.yaml")
	if err != nil || len(gen) == 0 {
		t.Fatalf("no generated CRDs: %v", err)
	}
	chart, _ := filepath.Glob("../../../charts/aerolvm/crds/*.yaml")
	if len(chart) != len(gen) {
		t.Fatalf("chart has %d CRDs, generated %d (run go generate ./api/...)", len(chart), len(gen))
	}
	for _, g := range gen {
		want, err := os.ReadFile(g)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("../../../charts/aerolvm/crds", filepath.Base(g)))
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(g), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("charts/aerolvm/crds/%s differs from config/crd (run go generate ./api/...)", filepath.Base(g))
		}
	}
}
