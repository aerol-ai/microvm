package identity

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func cacheKey(i int) [32]byte { return sha256.Sum256([]byte(strconv.Itoa(i))) }

func smallToken(id string) *verifiedToken {
	return &verifiedToken{
		principal: controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:t:" + id},
		bindings:  []controlplane.TeamBinding{{Role: controlplane.RoleRunner, Team: "payments"}},
	}
}

// TestTokenCacheBounds is finding 7.4: the cache holds at most maxEntries
// AND maxBytes, evicting least recently used first, and never caches a
// token bigger than the whole byte bound.
func TestTokenCacheBounds(t *testing.T) {
	c := newTokenCache(3, 1<<20)
	for i := 0; i < 3; i++ {
		c.put(cacheKey(i), smallToken(strconv.Itoa(i)))
	}
	if _, ok := c.get(cacheKey(0)); !ok { // 0 becomes most recent
		t.Fatal("entry 0 missing")
	}
	c.put(cacheKey(3), smallToken("3"))
	if _, ok := c.get(cacheKey(1)); ok {
		t.Fatal("the least recently used entry (1) must be evicted")
	}
	for _, i := range []int{0, 2, 3} {
		if _, ok := c.get(cacheKey(i)); !ok {
			t.Fatalf("entry %d evicted", i)
		}
	}
	if c.len() != 3 {
		t.Fatalf("len = %d", c.len())
	}
	// Re-putting a key replaces it without growing.
	c.put(cacheKey(3), smallToken("3b"))
	if c.len() != 3 {
		t.Fatalf("len after replace = %d", c.len())
	}
	c.remove(cacheKey(3))
	c.remove(cacheKey(99))
	if c.len() != 2 {
		t.Fatalf("len after remove = %d", c.len())
	}

	// The byte bound: big tokens push older ones out even under the count.
	big := func(id string) *verifiedToken {
		tok := smallToken(id)
		tok.groups = []string{strings.Repeat("g", 4000)}
		return tok
	}
	b := newTokenCache(100, 10_000)
	for i := 0; i < 5; i++ {
		b.put(cacheKey(i), big(strconv.Itoa(i)))
	}
	if b.usage() > 10_000 || b.len() >= 5 {
		t.Fatalf("byte bound not held: %d bytes in %d entries", b.usage(), b.len())
	}
	huge := smallToken("huge")
	huge.groups = []string{strings.Repeat("g", 20_000)}
	before := b.len()
	b.put(cacheKey(50), huge)
	if _, ok := b.get(cacheKey(50)); ok || b.len() != before {
		t.Fatal("a token over the whole byte bound must not be cached")
	}
	off := newTokenCache(0, 100)
	off.put(cacheKey(1), smallToken("1"))
	if off.len() != 0 {
		t.Fatal("a zero-entry cache caches nothing")
	}
}

// TestTokenCacheDefaultsHoldTenThousand: at the default bounds a typical
// ID token's entry fits 10k times inside 16 MB, so the count is the bound
// that bites for ordinary tokens.
func TestTokenCacheDefaultsHoldTenThousand(t *testing.T) {
	c := newTokenCache(DefaultCacheEntries, DefaultCacheBytes)
	for i := 0; i < DefaultCacheEntries+10; i++ {
		tok := smallToken(strconv.Itoa(i))
		tok.principal.Name = "person" + strconv.Itoa(i) + "@acme.com"
		c.put(cacheKey(i), tok)
	}
	if c.len() != DefaultCacheEntries || c.usage() > DefaultCacheBytes {
		t.Fatalf("len %d usage %d", c.len(), c.usage())
	}
}

func TestVerifiedTokenStale(t *testing.T) {
	ks := &keySet{}
	tok := &verifiedToken{keys: ks, gen: ks.gen.Load()}
	if tok.stale() {
		t.Fatal("fresh entry is stale")
	}
	ks.gen.Add(1)
	if !tok.stale() {
		t.Fatal("a withdrawn key must make the entry stale")
	}
	if (&verifiedToken{}).stale() {
		t.Fatal("an entry with no key set is never stale")
	}
}
