package v1

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

// TestParseTagFilterExtractsTagDotPrefix pins the wire contract that
// plans/multi-tenancy-via-control-plane.md depends on: a control plane in
// front of AerolVM scopes its list calls with tag.<key>=<value> params, and
// AerolVM lifts each one into the in-memory filter passed to the service.
// Multiple tag.* params AND together at the service layer; non-tag params are
// ignored so other query knobs can be added later without breaking this.
func TestParseTagFilterExtractsTagDotPrefix(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/sandboxes?tag.user_id=alice&tag.project_id=p1&limit=50", nil)
	got := parseTagFilter(r)
	want := map[string]string{"user_id": "alice", "project_id": "p1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTagFilter = %v, want %v", got, want)
	}
}

// TestParseTagFilterNoTagsReturnsNil covers backward compat: a list call
// without any tag.* params must produce a nil filter so the service-layer
// short-circuit fires and the response shape is identical to pre-filter
// behavior. Without this, existing SDK clients would suddenly be running
// through the filter code path.
func TestParseTagFilterNoTagsReturnsNil(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/sandboxes?limit=10&offset=20", nil)
	if got := parseTagFilter(r); got != nil {
		t.Fatalf("expected nil filter for tag-less query, got %v", got)
	}
}

// TestParseTagFilterRejectsBareTagPrefix: tag. with no key (e.g. "tag.=x") is
// nonsense and must not insert an empty-key entry, which would otherwise
// match every sandbox whose Tags is missing the empty string (i.e. all of
// them) and silently break the control plane's scoping.
func TestParseTagFilterRejectsBareTagPrefix(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/sandboxes?tag.=alice", nil)
	if got := parseTagFilter(r); got != nil {
		t.Fatalf("expected nil filter for bare 'tag.' key, got %v", got)
	}
}
