package daytona

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// GET /sandbox answers in one of two shapes, because Daytona changed it.
// Daytona SDKs from 0.180.0 (the TypeScript and Python SDKs both switched in
// that release) list through GET /sandbox and read a cursor page,
// {items, nextCursor}; a bare array fails them (the Python SDK raises a
// validation error, the TypeScript SDK iterates undefined). Releases before
// 0.180.0 list through GET /sandbox/paginated, and only their raw API
// clients call GET /sandbox, reading every sandbox as a bare array (the Go
// api-client 0.177 in contract_test.go does). Both still talk to this
// server, so the route picks the shape per request.
//
// Every Daytona SDK sends its release in X-Daytona-SDK-Version, so that
// header picks the cursor page; a cursor query parameter does too, as only
// the paged protocol sends one. Anything else (no header, an older release,
// "unknown") keeps the bare array.
const daytonaSDKVersionHeader = "X-Daytona-SDK-Version"

// daytonaCursorListSDK is the first Daytona SDK release that reads GET
// /sandbox as a cursor page.
var daytonaCursorListSDK = [3]int{0, 180, 0}

const (
	// defaultCursorListLimit and maxCursorListLimit are Daytona's page size
	// default and bound for GET /sandbox (the SDKs refuse a limit above 200).
	defaultCursorListLimit = 100
	maxCursorListLimit     = 200
)

// wantsCursorList reports whether the caller reads GET /sandbox as a cursor
// page rather than a bare array.
func wantsCursorList(r *http.Request) bool {
	// A cluster peer hop is the ingress node's own merge, which decodes the
	// bare array (clusterlist.MergeJSON) and pages the result itself. The
	// hop carries the caller's query, cursor included, so it is checked
	// first.
	if r.Header.Get(cluster.HeaderForwarded) == "1" {
		return false
	}
	if _, ok := r.URL.Query()["cursor"]; ok {
		return true
	}
	return sdkVersionAtLeast(r.Header.Get(daytonaSDKVersionHeader), daytonaCursorListSDK)
}

// sdkVersionAtLeast reports whether raw, a release such as "0.231.1",
// "v0.180.0" or "2.0.0-rc.1", is at least want. A pre-release counts as its
// release. Anything that is not three dot-separated numbers is false.
func sdkVersionAtLeast(raw string, want [3]int) bool {
	v := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != len(want) {
		return false
	}
	var got [3]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return false
		}
		got[i] = n
	}
	for i := range got {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}

// cursorListPage is one cursor-page request: how many items, after which.
type cursorListPage struct {
	limit int
	after *listCursorKey // nil: the first page
}

// listCursorKey places a sandbox in the cursor list's order. The cursor is
// the key of the last item a page returned, not an offset, so sandboxes
// created or deleted between two pages (a cleanup that deletes as it lists)
// neither repeat nor shift the next page.
type listCursorKey struct {
	createdAt string // RFC 3339 in UTC (timePtr), so string order is time order
	id        string
}

// before reports whether k sorts ahead of other: newest first, then by ID so
// sandboxes created in the same second keep one fixed order across pages.
func (k listCursorKey) before(other listCursorKey) bool {
	if k.createdAt != other.createdAt {
		return k.createdAt > other.createdAt
	}
	return k.id > other.id
}

func listCursorKeyOf(item sandboxResponse) listCursorKey {
	key := listCursorKey{id: item.ID}
	if item.CreatedAt != nil {
		key.createdAt = *item.CreatedAt
	}
	return key
}

func encodeListCursor(key listCursorKey) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key.createdAt + "\n" + key.id))
}

func decodeListCursor(raw string) (listCursorKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return listCursorKey{}, err
	}
	createdAt, id, ok := strings.Cut(string(decoded), "\n")
	if !ok || id == "" {
		return listCursorKey{}, errors.New("malformed cursor")
	}
	return listCursorKey{createdAt: createdAt, id: id}, nil
}

// parseCursorListPage reads limit and cursor the way Daytona's GET /sandbox
// does: limit is a whole number from 1 to 200, defaulting to 100.
func parseCursorListPage(r *http.Request) (cursorListPage, error) {
	page := cursorListPage{limit: defaultCursorListLimit}
	q := r.URL.Query()
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxCursorListLimit {
			return cursorListPage{}, errors.New("limit must be a whole number from 1 to 200")
		}
		page.limit = n
	}
	if raw := strings.TrimSpace(q.Get("cursor")); raw != "" {
		key, err := decodeListCursor(raw)
		if err != nil {
			return cursorListPage{}, errors.New("cursor is not one this server returned as nextCursor")
		}
		page.after = &key
	}
	return page, nil
}

// cursorSandboxPage cuts one page out of the caller's whole filtered list.
// Each page re-reads the list, as the bare-array answer does once; the
// cursor only says where the page starts.
func cursorSandboxPage(items []sandboxResponse, page cursorListPage) cursorSandboxesResponse {
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, func(a, b sandboxResponse) int {
		ka, kb := listCursorKeyOf(a), listCursorKeyOf(b)
		switch {
		case ka.before(kb):
			return -1
		case kb.before(ka):
			return 1
		}
		return 0
	})
	start := 0
	if page.after != nil {
		start = sort.Search(len(sorted), func(i int) bool {
			return page.after.before(listCursorKeyOf(sorted[i]))
		})
	}
	end := min(start+page.limit, len(sorted))
	// Items is never null. Daytona's SandboxListItem needs whole cpu, gpu,
	// memory and disk; toSandboxResponse already rounds them (wholeUnits).
	out := cursorSandboxesResponse{Items: append(make([]sandboxResponse, 0, end-start), sorted[start:end]...)}
	if end < len(sorted) {
		next := encodeListCursor(listCursorKeyOf(sorted[end-1]))
		out.NextCursor = &next
	}
	return out
}
