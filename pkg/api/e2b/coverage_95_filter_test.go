package e2b

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func TestFilterE2BLocalToPage(t *testing.T) {
	local := []listedSandboxResponse{{SandboxID: "sb-1"}, {SandboxID: "sb-2"}}
	if got := filterE2BLocalToPage(local, nil, ""); len(got) != 2 {
		t.Fatalf("cold start = %d", len(got))
	}
	if got := filterE2BLocalToPage(local, nil, "tok"); got != nil {
		t.Fatalf("terminal = %+v", got)
	}
	got := filterE2BLocalToPage(local, []cluster.Placement{{SandboxID: "sb-2"}}, "")
	if len(got) != 1 || got[0].SandboxID != "sb-2" {
		t.Fatalf("page filter = %+v", got)
	}
}
