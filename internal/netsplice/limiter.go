package netsplice

import "sync"

// Limiter caps concurrent connections per key (a sandbox ID) and globally.
// The hooks run under the limiter's lock, so state tied to a key's first
// acquire or last release (the wake proxy's activity generation) changes
// atomically with the count. The wake proxy relied on that when all of this
// lived under Service.l4LimitMu.
type Limiter struct {
	perKeyMax func() int
	globalMax func() int

	mu     sync.Mutex
	byKey  map[string]int
	global int
}

// NewLimiter returns a Limiter whose caps are read on every acquire, not
// captured here. The wake proxy builds its limiters once, lazily, from config
// it can still change afterwards; a fixed cap is func() int { return n }.
func NewLimiter(perKeyMax, globalMax func() int) *Limiter {
	return &Limiter{perKeyMax: perKeyMax, globalMax: globalMax, byKey: make(map[string]int)}
}

// TryAcquire reserves one slot for key, or returns ok=false at either cap.
// onAcquire(first) and the returned release's onRelease(last) run under the
// lock; either may be nil. The release func is idempotent, so a double
// release cannot drive counts negative or free another connection's slot.
func (l *Limiter) TryAcquire(key string, onAcquire func(first bool), onRelease func(last bool)) (release func(), ok bool) {
	perKeyMax, globalMax := l.perKeyMax(), l.globalMax()
	l.mu.Lock()
	if l.byKey[key] >= perKeyMax || l.global >= globalMax {
		l.mu.Unlock()
		return nil, false
	}
	first := l.byKey[key] == 0
	l.byKey[key]++
	l.global++
	if onAcquire != nil {
		onAcquire(first)
	}
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			last := l.byKey[key] <= 1
			if last {
				delete(l.byKey, key)
			} else {
				l.byKey[key]--
			}
			if l.global > 0 {
				l.global--
			}
			if onRelease != nil {
				onRelease(last)
			}
		})
	}, true
}

// WithLock runs fn with the limiter's lock held, passing the live count for
// key. Use it for state guarded by the hooks.
func (l *Limiter) WithLock(key string, fn func(count int)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn(l.byKey[key])
}
