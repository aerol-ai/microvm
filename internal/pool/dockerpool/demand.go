package dockerpool

import (
	"math"
	"time"
)

// Depth that follows demand (plans/agent-sandbox-feature-parity.md W2). An
// entry with MaxDepth > 0 sets this server's target from the creates it saw
// for the image: every demandWindow the count of hits and misses is folded
// into a moving average, and the target is that average rounded up, kept
// between MinDepth and MaxDepth. With no creates the average halves every
// window, so an idle image drops to MinDepth (zero, if that is the floor)
// within a few minutes, and the next burst brings it back within one window.
//
// Each server decides alone, from its own creates: placement spreads load
// unevenly, and a server that serves none of an image's creates should not
// hold its slots. The state is in memory; a restart starts at MinDepth.
const (
	// demandWindow is one sample. Three refill ticks at the 5 s default, so
	// the average sees a burst before refill could have replaced it.
	demandWindow = 15 * time.Second
	// demandWeight is how much the newest window counts. At 0.5 the
	// average forgets a burst in a handful of windows instead of holding
	// slots for it for many minutes.
	demandWeight = 0.5
	// demandZero is the average below which there is no demand: a halving
	// average never reaches zero on its own.
	demandZero = 0.1
)

// demandState is one demand-following entry's view of its creates.
type demandState struct {
	count  int       // creates since start
	avg    float64   // moving average of creates per window
	start  time.Time // start of the current window; zero until first sampled
	target int
}

func (p *Pool) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// countDemandLocked records one create (hit or miss) for a demand-following
// entry. Other keys are not counted, so the map holds only entries.
func (p *Pool) countDemandLocked(ks string) {
	c, ok := p.configured[ks]
	if !ok || !c.followsDemand() {
		return
	}
	p.demandStateLocked(ks, c).count++
}

func (p *Pool) demandStateLocked(ks string, c Configured) *demandState {
	if p.demand == nil {
		p.demand = make(map[string]*demandState)
	}
	st := p.demand[ks]
	if st == nil {
		st = &demandState{target: c.MinDepth}
		p.demand[ks] = st
	}
	return st
}

// reconcileDemandLocked drops the state of entries that no longer follow
// demand and re-clamps the rest to their (possibly changed) limits. The
// average is kept across a limit change: the demand did not change.
func (p *Pool) reconcileDemandLocked() {
	for ks := range p.demand {
		if c, ok := p.configured[ks]; !ok || !c.followsDemand() {
			delete(p.demand, ks)
		}
	}
	for ks, c := range p.configured {
		if c.followsDemand() {
			st := p.demandStateLocked(ks, c)
			st.target = demandTarget(st.avg, c)
		}
	}
}

// sampleDemand folds every finished window into each entry's average and
// sets its target. Windows that passed with no tick (a stalled refill
// loop) count as windows with no creates.
func (p *Pool) sampleDemand() {
	now := p.clock()
	p.mu.Lock()
	defer p.mu.Unlock()
	for ks, c := range p.configured {
		if !c.followsDemand() {
			continue
		}
		st := p.demandStateLocked(ks, c)
		if st.start.IsZero() {
			st.start = now
			continue
		}
		windows := int(now.Sub(st.start) / demandWindow)
		if windows < 1 {
			continue
		}
		creates := st.count
		st.avg = demandWeight*float64(st.count) + (1-demandWeight)*st.avg
		st.avg *= math.Pow(1-demandWeight, float64(windows-1))
		st.count = 0
		st.start = st.start.Add(time.Duration(windows) * demandWindow)
		if target := demandTarget(st.avg, c); target != st.target {
			// One line per change, so an operator (and a live test) can see
			// the depth follow demand without reading metrics.
			if p.logger != nil {
				p.logger.Info("warm pool depth follows demand", "image", c.Key.Image,
					"creates_in_window", creates, "average", st.avg, "from", st.target, "to", target)
			}
			st.target = target
		}
	}
}

// demandTarget is an average rounded up, with anything under demandZero as
// none, kept between the entry's limits.
func demandTarget(avg float64, c Configured) int {
	n := 0
	if avg >= demandZero {
		n = int(math.Ceil(avg))
	}
	return min(max(n, c.MinDepth), c.MaxDepth)
}
