package clusterlist

import (
	"errors"
	"net/url"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWantsLocalPaging(t *testing.T) {
	for raw, want := range map[string]bool{
		"/v1/sandboxes":                  false,
		"/v1/sandboxes?tag.a=b":          false,
		"/v1/sandboxes?limit=20":         true,
		"/v1/sandboxes?page_token=l1.YQ": true,
		"/v1/sandboxes?pageToken=l1.YQ":  true,
		"/v1/sandboxes?limit=%20&name=x": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := WantsLocalPaging(u); got != want {
			t.Fatalf("WantsLocalPaging(%s) = %v, want %v", raw, got, want)
		}
	}
	if WantsLocalPaging(nil) {
		t.Fatal("nil URL must not page")
	}
}

func TestPageLocalWalksIDOrder(t *testing.T) {
	local := []*models.Sandbox{{ID: "sb-c"}, nil, {ID: "sb-a"}, {ID: "sb-e"}, {ID: "sb-b"}, {ID: "sb-d"}}
	var seen []string
	token := ""
	for pages := 0; pages < 10; pages++ {
		page, next, err := PageLocal(local, 2, token)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		for _, sb := range page {
			seen = append(seen, sb.ID)
		}
		if next == "" {
			break
		}
		token = next
	}
	want := []string{"sb-a", "sb-b", "sb-c", "sb-d", "sb-e"}
	if len(seen) != len(want) {
		t.Fatalf("seen %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen %v, want %v", seen, want)
		}
	}
	// An exact fit has no next page.
	if page, next, err := PageLocal(local, 5, ""); err != nil || len(page) != 5 || next != "" {
		t.Fatalf("exact fit = (%d, %q, %v)", len(page), next, err)
	}
	// Limits are clamped like the cluster path.
	if page, _, err := PageLocal(local, 0, ""); err != nil || len(page) != 5 {
		t.Fatalf("default limit = (%d, %v)", len(page), err)
	}
	many := make([]*models.Sandbox, MaxPageLimit+10)
	for i := range many {
		many[i] = &models.Sandbox{ID: string(rune('A'+i/26/26%26)) + string(rune('A'+i/26%26)) + string(rune('A'+i%26))}
	}
	if page, next, err := PageLocal(many, MaxPageLimit+100, ""); err != nil || len(page) != MaxPageLimit || next == "" {
		t.Fatalf("clamped page = (%d, %q, %v)", len(page), next, err)
	}
}

func TestPageLocalRejectsForeignTokens(t *testing.T) {
	for _, token := range []string{"cluster-token", "l1.", "l1.!!!"} {
		if _, _, err := PageLocal(nil, 2, token); !errors.Is(err, ErrInvalidPageToken) {
			t.Fatalf("PageLocal(token %q) error = %v, want ErrInvalidPageToken", token, err)
		}
	}
}
