// Package routedns answers "where does this sandbox hostname go?" for a
// static Caddy config (plans/ingress-proxy-routing.md §3.2, task T3).
//
// Caddy's config stays static. Instead of one route per sandbox (each route
// write reloads Caddy's whole config and drops ~2.6% of new connections),
// Caddy asks a loopback DNS responder:
//
//	owner:   reverse_proxy dynamic A name={http.request.host}.  → OwnerTable
//	ingress: caddy-l4 dial "{l4.tls.server_name}.rt.internal"   → IngressIndex
//
// Bytes stay in Caddy. sandboxd only answers where, so a sandboxd restart
// never resets established connections. Both tables are keyed by the EXACT
// hostname Caddy's old per-sandbox matchers used. Nothing parses sandbox IDs
// out of hostnames on the answer path; IDs may contain dashes, so parsing
// would be ambiguous.
package routedns

import (
	"net"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// TargetState distinguishes an answerable upstream from a hostname that must
// fall back to the sandboxd router (Caddy's static fallback upstream), which
// owns wake-on-request and in-flux 503s.
type TargetState int

const (
	TargetReady  TargetState = iota // answer A with the target IP
	TargetWake                      // serverless and stopped: router wakes it
	TargetInFlux                    // failover or placement in flux: router answers 503
	// TargetRouter always takes the fallback: the route needs per-route
	// behaviour a static Caddy route cannot express, such as E2B
	// maskRequestHost (a per-route upstream Host rewrite). The router already
	// applies it.
	TargetRouter
)

// OwnerTarget is where one hostname goes on its owner node.
type OwnerTarget struct {
	IP    net.IP
	Port  int
	State TargetState
}

// OwnerTable is the owner node's route table: what Caddy's per-sandbox http
// routes used to hold. The service's route-intent seam (publicRouteWriter)
// maintains it, so it has exactly the semantics of the routes it replaces.
type OwnerTable struct {
	mu    sync.RWMutex
	hosts map[string]OwnerTarget
}

func NewOwnerTable() *OwnerTable { return &OwnerTable{hosts: map[string]OwnerTarget{}} }

func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".") }

// Set records a target. An empty host is ignored.
func (t *OwnerTable) Set(host string, target OwnerTarget) {
	host = normHost(host)
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hosts[host] = target
}

// SetState changes only the state of an existing or new entry (wake and
// in-flux routes carry no upstream).
func (t *OwnerTable) SetState(host string, state TargetState) {
	host = normHost(host)
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.hosts[host]
	cur.State = state
	t.hosts[host] = cur
}

func (t *OwnerTable) Delete(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.hosts, normHost(host))
}

// DeleteFunc removes every host match selects (e.g. all of a sandbox). It
// mirrors Caddy's DeleteSandboxRoute, which also dropped the sandbox's
// custom-hostname matchers that rode the root route.
func (t *OwnerTable) DeleteFunc(match func(host string) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for h := range t.hosts {
		if match(h) {
			delete(t.hosts, h)
		}
	}
}

func (t *OwnerTable) Lookup(host string) (OwnerTarget, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v, ok := t.hosts[normHost(host)]
	return v, ok
}

func (t *OwnerTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.hosts)
}

// IngressEntry is where one SNI hostname goes from an ingress node.
type IngressEntry struct {
	SandboxID   string
	OwnerNodeID string
	OwnerHost   string // data-plane host (IP or DNS name)
	// Routable: public, actively owned, not reserved or deleting. A known
	// but unroutable host is answered like an unknown one (the local router
	// gives 503/404), never spliced to a guessed owner.
	Routable bool
	Custom   bool // a tenant custom domain (not under the platform domain)
}

// IngressIndex maps every SNI hostname of every placement to its owner. It
// covers ALL placements (review T3): any ingress routes any sandbox, and
// routing does not depend on a shard-aware load balancer. It is rebuilt
// from the placement view (the delta feed keeps that current) and swapped
// in atomically.
type IngressIndex struct {
	mu    sync.RWMutex
	hosts map[string]IngressEntry
	// bySandbox lets one placement change replace exactly that sandbox's
	// hosts, so the index updates in O(changes), not O(fleet).
	bySandbox map[string][]string
}

func NewIngressIndex() *IngressIndex {
	return &IngressIndex{hosts: map[string]IngressEntry{}, bySandbox: map[string][]string{}}
}

// Replace rebuilds the index from placements. domain is the platform domain
// (hosts are {id}.{domain} and {id}-{port}.{domain}).
func (x *IngressIndex) Replace(placements []cluster.Placement, domain string) {
	next := make(map[string]IngressEntry, len(placements)*2)
	by := make(map[string][]string, len(placements))
	for _, p := range placements {
		one := map[string]IngressEntry{}
		addPlacementHosts(one, p, domain)
		for h, e := range one {
			next[h] = e
			by[p.SandboxID] = append(by[p.SandboxID], h)
		}
	}
	x.mu.Lock()
	x.hosts, x.bySandbox = next, by
	x.mu.Unlock()
}

// Upsert replaces one placement's hosts: new ones are added, and ones it no
// longer has (a removed custom domain or unexposed port) are dropped.
func (x *IngressIndex) Upsert(p cluster.Placement, domain string) {
	add := map[string]IngressEntry{}
	addPlacementHosts(add, p, domain)
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(p.SandboxID)
	hosts := make([]string, 0, len(add))
	for h, e := range add {
		x.hosts[h] = e
		hosts = append(hosts, h)
	}
	if len(hosts) > 0 {
		x.bySandbox[p.SandboxID] = hosts
	}
}

// Remove drops every host of a deleted placement.
func (x *IngressIndex) Remove(sandboxID string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(sandboxID)
}

func (x *IngressIndex) removeLocked(sandboxID string) {
	for _, h := range x.bySandbox[sandboxID] {
		// A host another sandbox now owns (a custom domain moved) stays.
		if e, ok := x.hosts[h]; ok && e.SandboxID == sandboxID {
			delete(x.hosts, h)
		}
	}
	delete(x.bySandbox, sandboxID)
}

func (x *IngressIndex) Lookup(host string) (IngressEntry, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	e, ok := x.hosts[normHost(host)]
	return e, ok
}

func (x *IngressIndex) Len() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.hosts)
}

func addPlacementHosts(into map[string]IngressEntry, p cluster.Placement, domain string) {
	domain = normHost(domain)
	if p.SandboxID == "" || domain == "" {
		return
	}
	base := IngressEntry{
		SandboxID:   p.SandboxID,
		OwnerNodeID: p.OwnerNodeID,
		OwnerHost:   p.OwnerDataPlaneHost,
		Routable:    p.PublicTraffic && !p.IsOrphaned() && !p.IsReserved() && !p.IsDeleting() && p.OwnerDataPlaneHost != "",
	}
	into[normHost(p.SandboxID+"."+domain)] = base
	ports := map[int]struct{}{}
	for port := range p.ExposedPorts {
		ports[port] = struct{}{}
	}
	for port, r := range p.ExposedPortRoutes {
		if strings.EqualFold(r.Protocol, "tcp") {
			continue // raw TCP rides host ports, not SNI
		}
		ports[port] = struct{}{}
	}
	for port := range ports {
		if proto, ok := p.ExposedPorts[port]; ok && strings.EqualFold(proto, "tcp") {
			continue
		}
		into[normHost(portHost(p.SandboxID, port, domain))] = base
	}
	for _, h := range p.CustomHostnames {
		e := base
		e.Custom = true
		into[normHost(h)] = e
	}
}

func portHost(id string, port int, domain string) string {
	return id + "-" + itoa(port) + "." + domain
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
