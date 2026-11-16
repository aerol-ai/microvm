package daytona

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// listBody is either GET /sandbox shape, decoded far enough to tell them
// apart and to check the cursor page's required keys.
type listBody struct {
	array      []sandboxResponse
	cursor     bool
	items      []sandboxResponse
	nextCursor *string
	rawKeys    map[string]json.RawMessage
}

func getSandboxList(t *testing.T, handler http.Handler, rawQuery string, headers map[string]string) (int, listBody, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox?"+rawQuery, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	raw := rr.Body.String()
	if rr.Code != http.StatusOK {
		return rr.Code, listBody{}, raw
	}
	var body listBody
	switch trimmed := bytes.TrimSpace(rr.Body.Bytes()); {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &body.array); err != nil {
			t.Fatalf("decode array: %v (%s)", err, raw)
		}
	default:
		body.cursor = true
		if err := json.Unmarshal(trimmed, &body.rawKeys); err != nil {
			t.Fatalf("decode page: %v (%s)", err, raw)
		}
		var page cursorSandboxesResponse
		if err := json.Unmarshal(trimmed, &page); err != nil {
			t.Fatalf("decode page: %v (%s)", err, raw)
		}
		body.items, body.nextCursor = page.Items, page.NextCursor
	}
	return rr.Code, body, raw
}

func seedListSandboxes(t *testing.T, upsert func(context.Context, *models.Sandbox) error, sandboxes ...*models.Sandbox) {
	t.Helper()
	for _, sb := range sandboxes {
		if err := upsert(context.Background(), sb); err != nil {
			t.Fatalf("Upsert(%s): %v", sb.ID, err)
		}
	}
}

func listSandbox(id string, createdAt time.Time, tags map[string]string) *models.Sandbox {
	return &models.Sandbox{
		ID: id, Name: id, Status: models.SandboxStatusStarted, Tags: tags,
		CPU: 1, MemoryMB: 1024, DiskGB: 10, ToolboxEnabled: true,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

// Daytona SDKs from 0.180 (the Python SDK 0.231.1 Inspect uses, the
// TypeScript SDK 0.223.1) read GET /sandbox as {items, nextCursor}; older
// raw clients read a bare array. The route answers each in its own shape.
func TestListSandboxesShapeFollowsDaytonaSDKVersion(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedListSandboxes(t, st.Upsert,
		listSandbox("sb-old", now.Add(-time.Hour), map[string]string{"created_by": "inspect-ai"}),
		listSandbox("sb-new", now, map[string]string{"created_by": "inspect-ai"}),
		listSandbox("sb-other", now.Add(-time.Minute), map[string]string{"created_by": "someone"}),
	)
	firstPage := encodeListCursor(listCursorKey{createdAt: now.Add(time.Hour).Format(time.RFC3339), id: "sb-zzz"})

	for _, tc := range []struct {
		name     string
		query    string
		headers  map[string]string
		wantPage bool
		wantIDs  []string
	}{
		{name: "no_sdk_header", wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{name: "go_api_client_0_177", headers: map[string]string{daytonaSDKVersionHeader: "0.177.0"}, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{name: "unknown_sdk_version", headers: map[string]string{daytonaSDKVersionHeader: "unknown"}, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{name: "last_array_release_0_179_9", headers: map[string]string{daytonaSDKVersionHeader: "0.179.9"}, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{name: "first_cursor_release_0_180_0", headers: map[string]string{daytonaSDKVersionHeader: "0.180.0"}, wantPage: true, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{name: "typescript_sdk_0_223_1", headers: map[string]string{daytonaSDKVersionHeader: "0.223.1", "X-Daytona-Source": "sdk-typescript"}, wantPage: true, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{
			// What Inspect's Daytona provider sends for its cleanup list.
			name:     "python_sdk_0_231_1_labels",
			query:    "labels=" + url.QueryEscape(`{"created_by":"inspect-ai"}`),
			headers:  map[string]string{daytonaSDKVersionHeader: "0.231.1", "X-Daytona-Source": "sdk-python-async"},
			wantPage: true, wantIDs: []string{"sb-new", "sb-old"},
		},
		{name: "sdk_2_0_0", headers: map[string]string{daytonaSDKVersionHeader: "2.0.0"}, wantPage: true, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{name: "cursor_param_without_header", query: "cursor=" + firstPage, wantPage: true, wantIDs: []string{"sb-new", "sb-other", "sb-old"}},
		{
			// The ingress merge decodes a peer's bare array, whatever the
			// caller asked for.
			name:    "cluster_peer_hop",
			query:   "cursor=" + firstPage + "&limit=1",
			headers: map[string]string{daytonaSDKVersionHeader: "0.231.1", "X-Cluster-Forwarded": "1"},
			wantIDs: []string{"sb-new", "sb-other", "sb-old"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body, raw := getSandboxList(t, handler, tc.query, tc.headers)
			if code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", code, raw)
			}
			if body.cursor != tc.wantPage {
				t.Fatalf("cursor page = %t, want %t: %s", body.cursor, tc.wantPage, raw)
			}
			got := body.array
			if tc.wantPage {
				got = body.items
				if _, ok := body.rawKeys["nextCursor"]; !ok || body.nextCursor != nil {
					t.Fatalf("nextCursor must be present and null on the only page: %s", raw)
				}
			}
			var ids []string
			for _, it := range got {
				ids = append(ids, it.ID)
			}
			if strings.Join(ids, ",") != strings.Join(tc.wantIDs, ",") {
				t.Fatalf("ids = %v, want %v", ids, tc.wantIDs)
			}
		})
	}
}

// Walking nextCursor returns every sandbox exactly once, newest first, with
// sandboxes created in the same second kept in one order.
func TestListSandboxesCursorPagesWalkEverySandboxOnce(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC().Truncate(time.Second)
	seedListSandboxes(t, st.Upsert,
		listSandbox("sb-a", now, nil),
		listSandbox("sb-b", now, nil),
		listSandbox("sb-c", now, nil),
		listSandbox("sb-d", now.Add(-time.Minute), nil),
		listSandbox("sb-e", now.Add(-time.Hour), nil),
	)
	headers := map[string]string{daytonaSDKVersionHeader: "0.231.1"}

	var ids []string
	var sizes []int
	query := "limit=2"
	for range 10 {
		code, body, raw := getSandboxList(t, handler, query, headers)
		if code != http.StatusOK || !body.cursor {
			t.Fatalf("status = %d, cursor page = %t: %s", code, body.cursor, raw)
		}
		sizes = append(sizes, len(body.items))
		for _, it := range body.items {
			ids = append(ids, it.ID)
		}
		if body.nextCursor == nil {
			break
		}
		query = "limit=2&cursor=" + url.QueryEscape(*body.nextCursor)
	}
	if got, want := strings.Join(ids, ","), "sb-c,sb-b,sb-a,sb-d,sb-e"; got != want {
		t.Fatalf("walked ids = %s, want %s", got, want)
	}
	if len(sizes) != 3 || sizes[0] != 2 || sizes[1] != 2 || sizes[2] != 1 {
		t.Fatalf("page sizes = %v, want [2 2 1]", sizes)
	}
}

// In a cluster the list is gathered across every placement page first (B10),
// then cut into cursor pages; the cursor page's limit, which the placement
// walk also reads as its page size, must not drop sandboxes.
func TestListSandboxesCursorPagesInClusterMode(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	ctx := context.Background()
	var placements []cluster.Placement
	for range 3 {
		sb, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
		if err != nil {
			t.Fatalf("CreateSandbox: %v", err)
		}
		placements = append(placements, cluster.Placement{SandboxID: sb.ID, OwnerNodeID: "self"})
	}
	svc.AttachCluster(&facadeListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		members:       []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleMixed}},
		placements:    placements,
	})

	seen := map[string]bool{}
	query := "limit=2"
	pages := 0
	for ; pages < 5; pages++ {
		code, body, raw := getSandboxList(t, handler, query, map[string]string{daytonaSDKVersionHeader: "0.231.1"})
		if code != http.StatusOK || !body.cursor {
			t.Fatalf("status = %d, cursor page = %t: %s", code, body.cursor, raw)
		}
		for _, it := range body.items {
			if seen[it.ID] {
				t.Fatalf("%s listed twice", it.ID)
			}
			seen[it.ID] = true
		}
		if body.nextCursor == nil {
			break
		}
		query = "limit=2&cursor=" + url.QueryEscape(*body.nextCursor)
	}
	if len(seen) != 3 || pages != 1 {
		t.Fatalf("walked %d sandboxes over %d pages, want 3 over 2", len(seen), pages+1)
	}
}

func TestListSandboxesCursorRejectsBadPageParams(t *testing.T) {
	_, _, _, handler := newHandlerExtraTestEnv(t)
	noNewline := base64.RawURLEncoding.EncodeToString([]byte("sb-a"))
	noID := base64.RawURLEncoding.EncodeToString([]byte("2026-11-15T00:00:00Z\n"))
	for _, tc := range []struct {
		name    string
		query   string
		wantMsg string
	}{
		{name: "limit_zero", query: "limit=0", wantMsg: "limit must be a whole number from 1 to 200"},
		{name: "limit_over_200", query: "limit=201", wantMsg: "limit must be a whole number from 1 to 200"},
		{name: "limit_not_a_number", query: "limit=ten", wantMsg: "limit must be a whole number from 1 to 200"},
		{name: "cursor_not_base64", query: "cursor=%21%21%21", wantMsg: "cursor is not one this server returned"},
		{name: "cursor_without_separator", query: "cursor=" + noNewline, wantMsg: "cursor is not one this server returned"},
		{name: "cursor_without_id", query: "cursor=" + noID, wantMsg: "cursor is not one this server returned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, raw := getSandboxList(t, handler, tc.query, map[string]string{daytonaSDKVersionHeader: "0.231.1"})
			if code != http.StatusBadRequest || !strings.Contains(raw, tc.wantMsg) {
				t.Fatalf("status = %d, body = %s; want 400 %q", code, raw, tc.wantMsg)
			}
		})
	}
	// The bare-array answer never read limit or cursor, and still does not.
	if code, body, raw := getSandboxList(t, handler, "limit=0&labels=%7B%7D", nil); code != http.StatusOK || body.cursor {
		t.Fatalf("array list with limit=0: status = %d, body = %s", code, raw)
	}
}

// Daytona's SandboxListItem has whole-number cpu, gpu, memory and disk, which
// the Python SDK checks strictly. Half a CPU and 1.5 GB round up in both list
// shapes, the same as in GET /sandbox/{id} (wholeUnits).
func TestListSandboxesCursorItemsUseWholeResourceNumbers(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	sb := listSandbox("sb-small", time.Now().UTC(), nil)
	sb.CPU, sb.MemoryMB, sb.DiskGB = 0.5, 1536, 3
	seedListSandboxes(t, st.Upsert, sb)

	_, page, raw := getSandboxList(t, handler, "", map[string]string{daytonaSDKVersionHeader: "0.231.1"})
	if len(page.items) != 1 {
		t.Fatalf("page = %s", raw)
	}
	if it := page.items[0]; it.CPU != 1 || it.Memory != 2 || it.Disk != 3 || it.GPU != 0 {
		t.Fatalf("list item cpu/memory/disk/gpu = %v/%v/%v/%v, want 1/2/3/0", it.CPU, it.Memory, it.Disk, it.GPU)
	}
	if !strings.Contains(raw, `"cpu":1,`) || !strings.Contains(raw, `"memory":2,`) {
		t.Fatalf("list item numbers must encode as integers: %s", raw)
	}
	_, array, raw := getSandboxList(t, handler, "", nil)
	if len(array.array) != 1 || array.array[0].CPU != 1 || array.array[0].Memory != 2 {
		t.Fatalf("array list must round cpu and memory up like the cursor page: %s", raw)
	}
}

func TestListSandboxesWithoutServiceAnswersEitherShapeEmpty(t *testing.T) {
	h := newHandlers(Deps{})
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{name: "array", want: "[]"},
		{name: "cursor_page", headers: map[string]string{daytonaSDKVersionHeader: "0.231.1"}, want: `{"items":[],"nextCursor":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			h.listSandboxes(rr, req)
			if got := strings.TrimSpace(rr.Body.String()); rr.Code != http.StatusOK || got != tc.want {
				t.Fatalf("status = %d, body = %s; want %s", rr.Code, got, tc.want)
			}
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox?limit=0", nil)
	req.Header.Set(daytonaSDKVersionHeader, "0.231.1")
	rr := httptest.NewRecorder()
	h.listSandboxes(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad limit without a service: status = %d", rr.Code)
	}
}

// A cursor is a position, not an offset: a sandbox from an earlier page that
// is deleted before the next page is fetched shifts nothing.
func TestCursorSandboxPageKeysOnPositionNotOffset(t *testing.T) {
	at := func(s string) *string { return &s }
	items := []sandboxResponse{
		{ID: "sb-e", CreatedAt: at("2026-11-15T10:00:00Z")},
		{ID: "sb-a", CreatedAt: at("2026-11-15T12:00:00Z")},
		{ID: "sb-c", CreatedAt: at("2026-11-15T11:00:00Z")},
		{ID: "sb-b", CreatedAt: at("2026-11-15T12:00:00Z")},
		{ID: "sb-d", CreatedAt: at("2026-11-15T11:00:00Z")},
		{ID: "sb-nil"},
	}
	first := cursorSandboxPage(items, cursorListPage{limit: 2})
	if len(first.Items) != 2 || first.Items[0].ID != "sb-b" || first.Items[1].ID != "sb-a" || first.NextCursor == nil {
		t.Fatalf("first page = %+v", first)
	}
	key, err := decodeListCursor(*first.NextCursor)
	if err != nil {
		t.Fatalf("decode nextCursor: %v", err)
	}
	// sb-b and sb-a are gone before page two is asked for.
	remaining := []sandboxResponse{items[0], items[2], items[4], items[5]}
	second := cursorSandboxPage(remaining, cursorListPage{limit: 2, after: &key})
	if len(second.Items) != 2 || second.Items[0].ID != "sb-d" || second.Items[1].ID != "sb-c" || second.NextCursor == nil {
		t.Fatalf("second page = %+v", second)
	}
	key, _ = decodeListCursor(*second.NextCursor)
	last := cursorSandboxPage(items, cursorListPage{limit: 2, after: &key})
	if len(last.Items) != 2 || last.Items[0].ID != "sb-e" || last.Items[1].ID != "sb-nil" || last.NextCursor != nil {
		t.Fatalf("last page = %+v (a sandbox with no createdAt sorts last)", last)
	}
	if items[0].ID != "sb-e" {
		t.Fatal("cursorSandboxPage must not reorder the caller's slice")
	}
}

func TestSDKVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"0.180.0", true},
		{"0.179.9", false},
		{"0.177.0", false},
		{"0.231.1", true},
		{"v0.180.0", true},
		{" 0.223.1 ", true},
		{"0.180.0-alpha.1", true},
		{"2.0.0-rc.1", true},
		{"1.0.0", true},
		{"0.1000.0", true},
		{"0.180", false},
		{"0.180.0.1", false},
		{"0.x.0", false},
		{"0.-1.0", false},
		{"unknown", false},
		{"", false},
	} {
		if got := sdkVersionAtLeast(tc.raw, daytonaCursorListSDK); got != tc.want {
			t.Errorf("sdkVersionAtLeast(%q) = %t, want %t", tc.raw, got, tc.want)
		}
	}
}
