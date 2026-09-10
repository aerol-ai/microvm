package daytona

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func TestFilterFacadeLocalToPage(t *testing.T) {
	type item struct{ ID string }
	local := []item{{ID: "sb-1"}, {ID: "sb-2"}, {ID: ""}}
	if got := filterFacadeLocalToPage(local, nil, "", func(it item) string { return it.ID }); len(got) != 3 {
		t.Fatalf("cold start = %d", len(got))
	}
	if got := filterFacadeLocalToPage(local, nil, "tok", func(it item) string { return it.ID }); got != nil {
		t.Fatalf("terminal nil placements = %+v", got)
	}
	got := filterFacadeLocalToPage(local, []cluster.Placement{{SandboxID: "sb-2"}}, "", func(it item) string { return it.ID })
	if len(got) != 1 || got[0].ID != "sb-2" {
		t.Fatalf("page filter = %+v", got)
	}
}
