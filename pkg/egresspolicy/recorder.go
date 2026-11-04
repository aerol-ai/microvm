package egresspolicy

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// DefaultLearnMax mirrors SB_EGRESS_LEARN_MAX's default (§9).
const DefaultLearnMax = 1024

// collapseThreshold is how many distinct names under one registrable domain
// turn into a "*.<registrable domain>" suggestion (P2-7).
const collapseThreshold = 3

// Recorder is learn mode's single recording implementation (eng re-review
// S7). The gateway, the WASM mediator and the isolate host only feed it
// observations, so identical traffic yields identical suggestions on every
// runtime. It is safe for concurrent use.
type Recorder struct {
	mu        sync.Mutex
	max       int
	now       func() time.Time
	truncated bool
	// version counts changes, so a saver rewrites only recordings that
	// moved since it last wrote them.
	version uint64
	hosts   map[string]*observation
	flows   map[netip.Addr]*observation // direct-IP flows with no DNS name
	ipName  map[netip.Addr]string       // last name a served DNS answer mapped to the IP
}

type observation struct {
	ports       map[uint16]struct{} // connection ports; empty = seen in DNS only
	first, last time.Time
	hits        uint64
}

// NewRecorder returns a recorder capped at max distinct destinations (names
// plus direct IPs); max <= 0 means DefaultLearnMax.
func NewRecorder(max int) *Recorder {
	if max <= 0 {
		max = DefaultLearnMax
	}
	return &Recorder{
		max:    max,
		now:    time.Now,
		hosts:  make(map[string]*observation),
		flows:  make(map[netip.Addr]*observation),
		ipName: make(map[netip.Addr]string),
	}
}

// RestoreRecorder rebuilds a recorder from a saved Snapshot, so a recording
// outlives a restart of whatever holds it. The IP-to-name correlation is not
// saved: flows after the restart correlate again once the sandbox resolves
// the names, and until then count as direct-IP flows.
func RestoreRecorder(max int, l Learned) *Recorder {
	r := NewRecorder(max)
	r.truncated = l.Truncated
	for _, e := range l.Entries {
		c := canonicalName(e.Host)
		if c == "" {
			continue
		}
		o := &observation{ports: make(map[uint16]struct{}, len(e.Ports)), first: e.FirstSeen, last: e.LastSeen, hits: e.Hits}
		for _, p := range e.Ports {
			o.ports[p] = struct{}{}
		}
		r.hosts[c] = o
	}
	for _, raw := range l.CIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.IsSingleIP() {
			continue
		}
		r.flows[p.Addr()] = &observation{ports: make(map[uint16]struct{})}
	}
	return r
}

// ObserveDNS records a name the sandbox resolved and the A/AAAA answers it
// was served, so later flows to those IPs correlate back to the name.
func (r *Recorder) ObserveDNS(name string, answers []netip.Addr) {
	c := canonicalName(name)
	if c == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record(r, r.hosts, c, 0)
	for _, ip := range answers {
		ip = ip.Unmap()
		if !ip.IsValid() {
			continue
		}
		// The correlation map is bounded too: without it, one sandbox
		// resolving many names could grow the gateway without limit.
		if _, ok := r.ipName[ip]; !ok && len(r.ipName) >= 4*r.max {
			r.truncated = true
			continue
		}
		r.ipName[ip] = c
	}
}

// ObserveHost records a connection to name:port, as seen by the proxy (SNI
// on 443, Host on 80), the WASM mediator or isolate's proxy. An IP-literal
// name is recorded as a flow.
func (r *Recorder) ObserveHost(name string, port uint16) {
	if ip, err := netip.ParseAddr(name); err == nil {
		r.ObserveFlow(ip, port)
		return
	}
	c := canonicalName(name)
	if c == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record(r, r.hosts, c, port)
}

// ObserveFlow records a forwarded flow to ip:port (the gateway's
// @learn_flows set). A flow to an IP a served DNS answer named becomes
// host:port; one with no name is suggested as a single-address CIDR.
func (r *Recorder) ObserveFlow(ip netip.Addr, port uint16) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if name, ok := r.ipName[ip]; ok {
		record(r, r.hosts, name, port)
		return
	}
	record(r, r.flows, ip, port)
}

// record adds or refreshes one destination; the caller holds r.mu. Past the
// cap a NEW destination is dropped and the recording reports truncated;
// existing ones keep counting, which costs no memory.
func record[K comparable](r *Recorder, m map[K]*observation, key K, port uint16) {
	o, ok := m[key]
	now := r.now()
	if !ok {
		if len(r.hosts)+len(r.flows) >= r.max {
			r.truncated = true
			return
		}
		o = &observation{ports: make(map[uint16]struct{}), first: now}
		m[key] = o
	}
	o.last = now
	o.hits++
	r.version++
	if port != 0 {
		o.ports[port] = struct{}{}
	}
}

// Version reports how many observations have changed the recording.
func (r *Recorder) Version() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.version
}

// LearnedEntry is one observed name (GET /network/learned "entries").
type LearnedEntry struct {
	Host      string    `json:"host"`
	Ports     []uint16  `json:"ports"` // connection ports; empty = DNS only
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Hits      uint64    `json:"hits"`
}

// SuggestedProfile is a profile body for a suggestion too big to inline.
type SuggestedProfile struct {
	AllowOut    []string `json:"allow_out"`
	Description string   `json:"description"`
}

// Learned is a recording plus its suggestion, in the GET /network/learned
// shape (the caller adds mode). Exactly one of SuggestedAllowOut and
// SuggestedProfile holds the list to apply: the inline list when it fits
// MaxInlineHostnames, the profile otherwise.
type Learned struct {
	Truncated         bool              `json:"truncated"`
	Entries           []LearnedEntry    `json:"entries"`
	CIDRs             []string          `json:"cidrs"`
	SuggestedAllowOut []string          `json:"suggested_allow_out"`
	SuggestedProfile  *SuggestedProfile `json:"suggested_profile"`
}

// Snapshot returns the recording and a suggested allow list, sorted so the
// output is deterministic. Suggestions collapse 3+ names under one
// registrable domain to "*.<registrable domain>" (never a public suffix;
// the apex, if seen, stays as an exact entry because the wildcard does not
// cover it), keep non-web ports as host:port (collapsed the same way per
// port, "*.<registrable domain>:22"), turn unnamed flows into single-address
// CIDRs, and always pass this package's validation and caps.
func (r *Recorder) Snapshot() Learned {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := Learned{Truncated: r.truncated, Entries: []LearnedEntry{}, CIDRs: []string{}}
	for host, o := range r.hosts {
		out.Entries = append(out.Entries, LearnedEntry{
			Host: host, Ports: sortedPorts(o.ports),
			FirstSeen: o.first, LastSeen: o.last, Hits: o.hits,
		})
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Host < out.Entries[j].Host })
	flowIPs := make([]netip.Addr, 0, len(r.flows))
	for ip := range r.flows {
		flowIPs = append(flowIPs, ip)
	}
	sort.Slice(flowIPs, func(i, j int) bool { return flowIPs[i].Less(flowIPs[j]) })
	for _, ip := range flowIPs {
		out.CIDRs = append(out.CIDRs, netip.PrefixFrom(ip, ip.BitLen()).String())
	}

	suggested, cut := suggest(out.Entries, out.CIDRs)
	if cut {
		out.Truncated = true
	}
	if CountHostnames(suggested) <= MaxInlineHostnames {
		out.SuggestedAllowOut = entryStrings(suggested)
		return out
	}
	out.SuggestedAllowOut = []string{}
	out.SuggestedProfile = &SuggestedProfile{
		AllowOut:    entryStrings(suggested),
		Description: fmt.Sprintf("suggested by learn mode from %d observed destinations", len(out.Entries)+len(out.CIDRs)),
	}
	return out
}

// suggest builds the suggested entries. cut reports that hostnames past
// MaxProfileHostnames were dropped.
func suggest(entries []LearnedEntry, cidrs []string) (out []Entry, cut bool) {
	seen := make(map[string]struct{})
	add := func(raw string) {
		e, reason := parseEntry(raw)
		if reason != "" {
			return // a name the grammar refuses cannot be suggested either
		}
		if _, dup := seen[e.String()]; dup {
			return
		}
		seen[e.String()] = struct{}{}
		out = append(out, e)
	}

	// Names per port; 0 stands for the web ports a bare entry covers.
	byPort := make(map[uint16][]string)
	for _, le := range entries {
		web := len(le.Ports) == 0 // DNS-only: the name must still resolve
		for _, p := range le.Ports {
			if p == 80 || p == 443 {
				web = true
			} else {
				byPort[p] = append(byPort[p], le.Host)
			}
		}
		if web {
			byPort[0] = append(byPort[0], le.Host)
		}
	}
	for port, hosts := range byPort {
		collapsed := collapseByRegistrableDomain(hosts)
		for _, h := range hosts {
			if w, ok := collapsed[h]; ok {
				h = w
			}
			if port != 0 {
				h = fmt.Sprintf("%s:%d", h, port)
			}
			add(h)
		}
	}
	for _, c := range cidrs {
		add(c)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	if CountHostnames(out) > MaxProfileHostnames {
		kept := out[:0]
		n := 0
		for _, e := range out {
			if e.IsHostname() {
				if n == MaxProfileHostnames {
					cut = true
					continue
				}
				n++
			}
			kept = append(kept, e)
		}
		out = kept
	}
	return out, cut
}

// collapseByRegistrableDomain maps each host to the "*.<registrable domain>"
// that replaces it when collapseThreshold or more of hosts share that
// domain. The apex itself is never mapped: a wildcard does not cover it.
func collapseByRegistrableDomain(hosts []string) map[string]string {
	byReg := make(map[string][]string)
	for _, h := range hosts {
		// EffectiveTLDPlusOne fails for a name that is itself a public
		// suffix, and by definition never returns one, so a collapse can
		// never produce "*.github.io"-style wildcards.
		if reg, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
			byReg[reg] = append(byReg[reg], h)
		}
	}
	collapsed := make(map[string]string)
	for reg, group := range byReg {
		if len(group) < collapseThreshold {
			continue
		}
		if _, reason := parseEntry("*." + reg); reason != "" {
			continue // defensive: never suggest a wildcard the grammar refuses
		}
		for _, h := range group {
			if h != reg {
				collapsed[h] = "*." + reg
			}
		}
	}
	return collapsed
}

func sortedPorts(m map[uint16]struct{}) []uint16 {
	ps := make([]uint16, 0, len(m))
	for p := range m {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i] < ps[j] })
	return ps
}

func entryStrings(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.String()
	}
	return out
}
