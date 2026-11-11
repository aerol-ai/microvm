package service

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// C12 (plans/kubernetes-v2-architecture.md §12.3): new IDs carry the cell in
// their first two hex digits and keep the shape clients route by.
func TestNewSandboxIDCarriesTheCell(t *testing.T) {
	for _, tc := range []struct {
		cell   int
		prefix string
	}{
		{0, "sb-01"}, // a Config not built by config.Load: the default cell
		{1, "sb-01"},
		{7, "sb-07"},
		{255, "sb-ff"},
	} {
		s := &Service{cfg: config.Config{CellID: tc.cell}}
		seen := map[string]bool{}
		for i := 0; i < 50; i++ {
			id, err := s.NewSandboxID()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(id, tc.prefix) || !models.IsGeneratedSandboxID(id) {
				t.Fatalf("cell %d: id %q, want prefix %s and the sb-<16 hex> shape", tc.cell, id, tc.prefix)
			}
			if seen[id] {
				t.Fatalf("cell %d: id %q minted twice", tc.cell, id)
			}
			seen[id] = true
		}
	}
	for _, cell := range []int{-1, 256} {
		if id, err := newSandboxIDInCell(cell); err == nil {
			t.Fatalf("cell %d: minted %q, want an error", cell, id)
		}
	}
}
