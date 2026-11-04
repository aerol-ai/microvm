package clusterlist

import (
	"encoding/base64"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// localPageTokenPrefix tags single-node page tokens so a cluster token (which
// pages the replicated placement index) is never mistaken for one.
const localPageTokenPrefix = "l1."

// ErrInvalidPageToken is returned for a page_token PageLocal didn't issue.
var ErrInvalidPageToken = errors.New("invalid page_token")

// WantsLocalPaging reports whether a single-node list request asked for
// pages. Only an explicit limit or page_token turns paging on: older SDKs
// that never send either keep getting the whole list in one response, as
// single-node always returned before.
func WantsLocalPaging(u *url.URL) bool {
	if u == nil {
		return false
	}
	q := u.Query()
	return strings.TrimSpace(q.Get("limit")) != "" || strings.TrimSpace(q.Get("page_token")) != "" || strings.TrimSpace(q.Get("pageToken")) != ""
}

// PageLocal pages a single-node list in sandbox-ID order, the same order the
// cluster placement index pages in, so a client that loops on the next-page
// header behaves identically in both modes. The token is opaque to clients
// and carries only the last ID returned; a sandbox created or destroyed
// between pages shifts nothing already returned.
func PageLocal(local []*models.Sandbox, limit int, pageToken string) ([]*models.Sandbox, string, error) {
	if limit <= 0 {
		limit = DefaultPageLimit
	}
	if limit > MaxPageLimit {
		limit = MaxPageLimit
	}
	after := ""
	if token := strings.TrimSpace(pageToken); token != "" {
		raw, ok := strings.CutPrefix(token, localPageTokenPrefix)
		if !ok {
			return nil, "", ErrInvalidPageToken
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(decoded) == 0 {
			return nil, "", ErrInvalidPageToken
		}
		after = string(decoded)
	}
	sorted := make([]*models.Sandbox, 0, len(local))
	for _, sb := range local {
		if sb != nil && sb.ID > after {
			sorted = append(sorted, sb)
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	if len(sorted) <= limit {
		return sorted, "", nil
	}
	page := sorted[:limit]
	next := localPageTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(page[len(page)-1].ID))
	return page, next, nil
}
