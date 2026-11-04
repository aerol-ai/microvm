package identity

import (
	"container/list"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The verified-token cache (§5.5, CEO review finding 7.4): an LRU keyed by
// SHA-256 of the JWT, held until the token expires, bounded at 10k entries
// AND 16 MB, so a stream of large tokens cannot grow it to 10k × 16 KB. It
// saves the ~50 µs signature check on every repeat call. It is per node and
// never shared (§5.0), and it stores the token's matched binding SET, never
// the team a request selected (eng review E7): team selection runs per
// request over that short list, so a 10k-binding file costs nothing on a
// cache hit (E8). A reload builds a new cache with the new bindings.
//
// MCP-only access tokens (§5.14) are cached too, with mcpOnly set. The cache
// never decides where a token may be used: the API edge's surface rule reads
// Access.MCPOnly on every request, hit or miss, so a token first seen on
// /mcp is still refused on /v1 from the cache. mcpOnly depends only on the
// token's aud, which the key (the token's own hash) already fixes.

// Cache bounds.
const (
	DefaultCacheEntries = 10_000
	DefaultCacheBytes   = 16 << 20
)

// verifiedToken is what one verified JWT resolved to. Immutable once
// cached.
type verifiedToken struct {
	principal controlplane.Principal
	// bindings is every binding the claims matched, in file order. Empty
	// means "verified, but no binding": the caller gets the D9/DR8 403.
	bindings []controlplane.TeamBinding
	// issuer, groups and overage feed the "no binding" 403; groups is kept
	// only when bindings is empty. claimNames is the issuer's, for
	// `whoami --explain`: the caller's claims are read back out of the
	// bearer on that rare call rather than held here for every token.
	issuer     string
	claimNames *controlplane.ClaimNames
	groups     []string
	overage    bool
	// mcpOnly: the token's aud named only an mcp_audiences audience, so it
	// is an OAuth access token for /mcp (§5.14), refused everywhere else.
	mcpOnly bool
	expires time.Time
	// keys and gen pin the key-set generation the signature verified
	// under: a later fetch that withdraws a key makes the entry stale.
	keys *keySet
	gen  uint64
}

// size estimates the entry's memory for the byte bound. A binding's Rule
// shares the loaded file's string, so only its slice element counts.
func (t *verifiedToken) size() int {
	n := 256 + len(t.principal.ID) + len(t.principal.Name) + len(t.issuer) + 64*len(t.bindings)
	for _, b := range t.bindings {
		n += len(b.Team)
	}
	for _, g := range t.groups {
		n += 16 + len(g)
	}
	return n
}

// stale reports whether the key set has withdrawn a key since t verified.
func (t *verifiedToken) stale() bool {
	return t.keys != nil && t.keys.gen.Load() != t.gen
}

type cacheEntry struct {
	key  [32]byte
	tok  *verifiedToken
	size int
}

type tokenCache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	bytes      int
	ll         *list.List
	items      map[[32]byte]*list.Element
}

func newTokenCache(maxEntries, maxBytes int) *tokenCache {
	return &tokenCache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		ll:         list.New(),
		items:      make(map[[32]byte]*list.Element),
	}
}

// get returns the cached token for key and marks it recently used.
func (c *tokenCache) get(key [32]byte) (*verifiedToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*cacheEntry).tok, true
}

// put caches tok under key, evicting least recently used entries until
// both bounds hold. A token alone over the byte bound is not cached.
func (c *tokenCache) put(key [32]byte, tok *verifiedToken) {
	size := tok.size()
	if size > c.maxBytes || c.maxEntries <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeElement(el)
	}
	c.items[key] = c.ll.PushFront(&cacheEntry{key: key, tok: tok, size: size})
	c.bytes += size
	for c.ll.Len() > c.maxEntries || c.bytes > c.maxBytes {
		c.removeElement(c.ll.Back())
	}
}

// remove drops key, if cached.
func (c *tokenCache) remove(key [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeElement(el)
	}
}

func (c *tokenCache) removeElement(el *list.Element) {
	e := c.ll.Remove(el).(*cacheEntry)
	delete(c.items, e.key)
	c.bytes -= e.size
}

// len and usage are for tests and the bound checks.
func (c *tokenCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *tokenCache) usage() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}
