package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// Batch runs fn with every admin call of this client applied to an in-memory
// copy of Caddy's config, then applies the result with ONE POST /load
// (plans/ingress-proxy-routing.md §5: "flag on/off is one batched load").
//
// WHY: each admin write makes Caddy reload its whole config, and each reload
// drops about 2.6% of new connections. Switching routing mode touches every
// per-sandbox route. Done one write at a time, that is N reloads; done in a
// batch, it is one.
//
// The same typed helpers run inside fn (upsertRoute, EnsureStatic*,
// DeleteTCPServer, ...), so batch output is exactly what the individual
// writes would have produced. Any goroutine using this client during the
// window writes into the batch too: nothing reaches Caddy in the middle and
// is then overwritten by the load. Requests wait while the batch is opened
// and while it is committed. Batches don't nest; a second Batch waits for
// the first.
//
// fn's error aborts the batch and nothing is loaded. An unchanged config is
// not loaded either, so a batch that finds nothing to do costs no reload.
func (c *Client) Batch(ctx context.Context, fn func() error) error {
	if !c.enabled {
		return fn()
	}
	c.batchMu.Lock()
	defer c.batchMu.Unlock()

	// Opening under the admin lock means no writer is between the read and
	// the write of a read-modify-write when the base config is taken.
	var emu *configEmulator
	if err := c.withAdminLock(ctx, func(ctx context.Context) error {
		c.gate.Lock()
		defer c.gate.Unlock()
		base, err := c.fetchRawConfig(ctx)
		if err != nil {
			return err
		}
		emu = newConfigEmulator(base)
		c.batch = emu
		return nil
	}); err != nil {
		return err
	}

	fnErr := fn()

	// The /load is a config write like any other: it takes the admin lock.
	return c.withAdminLock(ctx, func(ctx context.Context) error {
		c.gate.Lock()
		defer c.gate.Unlock()
		c.batch = nil
		if fnErr != nil {
			return fnErr
		}
		if !emu.changed() {
			return nil
		}
		body, err := json.Marshal(emu.root)
		if err != nil {
			return fmt.Errorf("marshal batched caddy config: %w", err)
		}
		status, detail, err := c.sendDirect(ctx, http.MethodPost, c.baseURL+"/load", body)
		if err != nil {
			return err
		}
		if status >= 400 {
			return caddyErr("load batched caddy config", status, detail)
		}
		return nil
	})
}

// do is the one place admin requests leave the client: to the open batch if
// there is one, otherwise to Caddy. Config mutations are serialized here
// (admin_lock.go) unless the caller already holds the admin lock.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if mutatesConfig(req.Method) && !holdsAdminLock(req.Context()) {
		c.adminMu.Lock()
		defer c.adminMu.Unlock()
	}
	c.gate.RLock()
	defer c.gate.RUnlock()
	if c.batch != nil {
		return c.batch.RoundTrip(req)
	}
	return c.httpClient.Do(req)
}

// sendDirect bypasses the gate (the batch commit holds it).
func (c *Client) sendDirect(ctx context.Context, method, target string, body []byte) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: %w", method, target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, caddyErrDetailMax))
	return resp.StatusCode, strings.TrimSpace(string(raw)), nil
}

func (c *Client) fetchRawConfig(ctx context.Context) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get caddy config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("get caddy config failed: %d", resp.StatusCode)
	}
	var root any
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return nil, fmt.Errorf("decode caddy config: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	return root, nil
}

// configEmulator answers the admin API subset this client uses, against an
// in-memory config tree. It follows Caddy's semantics:
//   - GET returns the value.
//   - POST appends to an array, or sets a key.
//   - PUT inserts before an array index, or creates a key (409 if present).
//   - PATCH replaces an existing value.
//   - DELETE removes a value.
//
// /id/<id> addresses the object with that "@id". A missing path is 404,
// which is what this client's callers expect. A write that would duplicate
// an @id is refused as Caddy refuses it.
type configEmulator struct {
	mu   sync.Mutex
	root any
	orig any
}

// NewConfigEmulator returns the in-memory admin API that Batch uses. It is
// exported for tests elsewhere that need a Caddy whose whole config they can
// read back.
func NewConfigEmulator(root any) http.RoundTripper { return newConfigEmulator(root) }

func newConfigEmulator(root any) *configEmulator {
	return &configEmulator{root: root, orig: deepCopy(root)}
}

func (e *configEmulator) changed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !reflect.DeepEqual(e.root, e.orig)
}

func (e *configEmulator) RoundTrip(req *http.Request) (*http.Response, error) {
	var body any
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				return respond(req, http.StatusBadRequest, map[string]string{"error": "decode request body: " + err.Error()}), nil
			}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	status, out := e.apply(req.Method, req.URL.Path, body)
	return respond(req, status, out), nil
}

func respond(req *http.Request, status int, v any) *http.Response {
	raw, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(raw)),
		Request:    req,
	}
}

func errBody(format string, a ...any) map[string]string {
	return map[string]string{"error": fmt.Sprintf(format, a...)}
}

func (e *configEmulator) apply(method, urlPath string, body any) (int, any) {
	segs, ok := e.resolve(urlPath)
	if !ok {
		return http.StatusNotFound, errBody("unknown object ID or path %s", urlPath)
	}
	if method == http.MethodGet {
		v, found := lookup(e.root, segs)
		if !found {
			return http.StatusNotFound, errBody("path %s not found", urlPath)
		}
		return http.StatusOK, v
	}
	if len(segs) == 0 {
		if method == http.MethodDelete {
			e.root = map[string]any{}
		} else {
			e.root = body
		}
		return http.StatusOK, nil
	}
	before := deepCopy(e.root)
	parentSegs, last := segs[:len(segs)-1], segs[len(segs)-1]
	parent, found := lookup(e.root, parentSegs)
	if !found || parent == nil {
		if method == http.MethodDelete || method == http.MethodPatch {
			return http.StatusNotFound, errBody("path %s not found", urlPath)
		}
		// POST/PUT under a missing parent create it (Caddy does the same
		// for object keys).
		if err := setAt(&e.root, parentSegs, map[string]any{}); err != nil {
			return http.StatusBadRequest, errBody("%v", err)
		}
		parent, _ = lookup(e.root, parentSegs)
	}

	var next any
	switch p := parent.(type) {
	case map[string]any:
		cur, exists := p[last]
		switch method {
		case http.MethodPost:
			if arr, ok := cur.([]any); ok && exists {
				next = append(arr, body)
			} else {
				next = body
			}
			p[last] = next
		case http.MethodPut:
			if exists && cur != nil {
				return http.StatusConflict, errBody("key already exists: %s", last)
			}
			p[last] = body
		case http.MethodPatch:
			if !exists {
				return http.StatusNotFound, errBody("path %s not found", urlPath)
			}
			p[last] = body
		case http.MethodDelete:
			if !exists {
				return http.StatusNotFound, errBody("path %s not found", urlPath)
			}
			delete(p, last)
		default:
			return http.StatusMethodNotAllowed, errBody("method %s", method)
		}
	case []any:
		idx, err := strconv.Atoi(last)
		if err != nil || idx < 0 {
			return http.StatusBadRequest, errBody("invalid array index %q", last)
		}
		var arr []any
		switch method {
		case http.MethodPut:
			if idx > len(p) {
				return http.StatusBadRequest, errBody("array index %d out of range", idx)
			}
			arr = append(append(append([]any{}, p[:idx]...), body), p[idx:]...)
		case http.MethodPost, http.MethodPatch:
			if idx >= len(p) {
				return http.StatusNotFound, errBody("array index %d out of range", idx)
			}
			arr = append([]any{}, p...)
			arr[idx] = body
		case http.MethodDelete:
			if idx >= len(p) {
				return http.StatusNotFound, errBody("array index %d out of range", idx)
			}
			arr = append(append([]any{}, p[:idx]...), p[idx+1:]...)
		default:
			return http.StatusMethodNotAllowed, errBody("method %s", method)
		}
		if err := setAt(&e.root, parentSegs, arr); err != nil {
			return http.StatusBadRequest, errBody("%v", err)
		}
	default:
		return http.StatusBadRequest, errBody("invalid traversal path %s", urlPath)
	}
	if dup := duplicateID(e.root); dup != "" {
		e.root = before
		return http.StatusBadRequest, errBody("duplicate ID '%s' found", dup)
	}
	return http.StatusOK, nil
}

// resolve turns /config/a/b or /id/<id>/c into path segments.
func (e *configEmulator) resolve(urlPath string) ([]string, bool) {
	if rest, ok := strings.CutPrefix(urlPath, "/config"); ok {
		return splitPath(rest), true
	}
	if rest, ok := strings.CutPrefix(urlPath, "/id/"); ok {
		id, sub, _ := strings.Cut(rest, "/")
		base, found := findID(e.root, id, nil)
		if !found {
			return nil, false
		}
		return append(base, splitPath(sub)...), true
	}
	return nil, false
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func lookup(v any, segs []string) (any, bool) {
	for _, s := range segs {
		switch t := v.(type) {
		case map[string]any:
			next, ok := t[s]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(s)
			if err != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			v = t[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// setAt replaces the value at segs, creating missing object keys.
func setAt(root *any, segs []string, val any) error {
	if len(segs) == 0 {
		*root = val
		return nil
	}
	if *root == nil {
		*root = map[string]any{}
	}
	cur := *root
	for i, s := range segs {
		lastSeg := i == len(segs)-1
		switch t := cur.(type) {
		case map[string]any:
			if lastSeg {
				t[s] = val
				return nil
			}
			next, ok := t[s]
			if !ok || next == nil {
				next = map[string]any{}
				t[s] = next
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(s)
			if err != nil || idx < 0 || idx >= len(t) {
				return fmt.Errorf("invalid array index %q", s)
			}
			if lastSeg {
				t[idx] = val
				return nil
			}
			cur = t[idx]
		default:
			return fmt.Errorf("invalid traversal at %q", s)
		}
	}
	return nil
}

func findID(v any, id string, path []string) ([]string, bool) {
	switch t := v.(type) {
	case map[string]any:
		if got, _ := t["@id"].(string); got == id {
			return append([]string{}, path...), true
		}
		for k, child := range t {
			if p, ok := findID(child, id, append(path, k)); ok {
				return p, true
			}
		}
	case []any:
		for i, child := range t {
			if p, ok := findID(child, id, append(path, strconv.Itoa(i))); ok {
				return p, true
			}
		}
	}
	return nil, false
}

func duplicateID(root any) string {
	seen := map[string]bool{}
	var dup string
	var walk func(any)
	walk = func(v any) {
		if dup != "" {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if id, ok := t["@id"].(string); ok {
				if seen[id] {
					dup = id
					return
				}
				seen[id] = true
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(root)
	return dup
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = deepCopy(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = deepCopy(child)
		}
		return out
	default:
		return v
	}
}
