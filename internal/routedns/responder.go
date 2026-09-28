package routedns

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// IngressZone is the suffix caddy-l4 appends to the SNI before dialing
// ("{l4.tls.server_name}.rt.internal"). The node's resolver routes this
// domain (and only this domain) to the responder.
const IngressZone = "rt.internal"

// answerTTL is short on purpose: Caddy re-resolves every refresh interval
// (1s), so a moved sandbox takes effect within about a second, with no
// config reload.
const answerTTL = 1

// portFromHost is the SAME rule the static Caddy map uses to pick the dial
// port for a Host. An A answer is only given when the target's port equals
// what Caddy will derive; otherwise Caddy would dial the right IP on the
// wrong port. Mismatches (WASM/isolate loopback upstreams, custom domains on
// a bound port) answer NXDOMAIN and take the static fallback to the sandboxd
// router, which resolves them properly.
var portFromHost = regexp.MustCompile(`^[^.]+-([0-9]+)\.`)

// DerivedPort is the port Caddy's static map yields for host.
func DerivedPort(host string, toolboxPort int) int {
	if m := portFromHost.FindStringSubmatch(normHost(host) + "."); m != nil {
		if p, err := strconv.Atoi(m[1]); err == nil {
			return p
		}
	}
	return toolboxPort
}

// MissLookup resolves a placement the ingress index doesn't hold yet (a
// brand-new sandbox's first connection). It is the cluster's internal
// placement point read.
type MissLookup func(ctx context.Context, sandboxID string) (cluster.Placement, bool)

// Responder is the loopback DNS server Caddy consults.
type Responder struct {
	// Domain is the platform domain ({id}.{Domain}).
	Domain string
	// SelfNodeID identifies placements this node owns.
	SelfNodeID string
	// LocalIP is the node-local listener that terminates with the wildcard
	// cert and routes through the static route: used for owner == self, and
	// for unroutable platform hosts so the local router can answer 503/404
	// (review 1A, wildcard only per T5).
	LocalIP net.IP
	// ToolboxPort is the static map's default port (root host).
	ToolboxPort int

	Owner   *OwnerTable
	Ingress *IngressIndex
	Miss    MissLookup

	missGroup singleflight.Group
	negMu     sync.Mutex
	negative  map[string]time.Time
	// NegativeTTL bounds how long a failed on-miss lookup is remembered, so
	// a flood of connections for an unknown host costs one control-plane
	// read, not one per connection.
	NegativeTTL time.Duration
	now         func() time.Time
}

var errNoAnswer = errors.New("no answer")

func (r *Responder) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// ServeDNS implements dns.Handler. Every answer is authoritative and nothing
// recurses: a query about a sandbox hostname never leaves this node.
func (r *Responder) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = false
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := normHost(q.Name)
	rr, rcode := r.answer(name, q.Qtype)
	m.Rcode = rcode
	if rr != nil {
		m.Answer = append(m.Answer, rr)
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, r.soa(name))
	}
	_ = w.WriteMsg(m)
}

// answer returns one record, or nil plus NXDOMAIN (unknown / fall back) or
// NOERROR (name exists, no record of that type).
func (r *Responder) answer(name string, qtype uint16) (dns.RR, int) {
	var ip net.IP
	var cname string
	var err error
	if host, ok := strings.CutSuffix(name, "."+IngressZone); ok {
		ip, cname, err = r.ingressTarget(host)
	} else {
		ip, err = r.ownerTarget(name)
	}
	if err != nil {
		return nil, dns.RcodeNameError
	}
	hdr := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: answerTTL}
	if cname != "" {
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(cname)}, dns.RcodeSuccess
	}
	if qtype != dns.TypeA || ip.To4() == nil {
		return nil, dns.RcodeSuccess // NODATA: exists, but no record of this type
	}
	hdr.Rrtype = dns.TypeA
	return &dns.A{Hdr: hdr, A: ip.To4()}, dns.RcodeSuccess
}

// ownerTarget answers the owner's static reverse_proxy lookup.
func (r *Responder) ownerTarget(host string) (net.IP, error) {
	if r.Owner == nil {
		return nil, errNoAnswer
	}
	t, ok := r.Owner.Lookup(host)
	if !ok || t.State != TargetReady || t.IP == nil || t.IP.IsLoopback() {
		return nil, errNoAnswer
	}
	if DerivedPort(host, r.ToolboxPort) != t.Port {
		return nil, errNoAnswer
	}
	return t.IP, nil
}

// ingressTarget answers caddy-l4's per-connection dial for an SNI.
func (r *Responder) ingressTarget(host string) (net.IP, string, error) {
	e, ok := r.lookupIngress(host)
	platform := r.isPlatformHost(host)
	if !ok || !e.Routable {
		if platform && r.LocalIP != nil {
			return r.LocalIP, "", nil // local router answers 503/404
		}
		return nil, "", errNoAnswer // custom domain: close, never ACME on ingress
	}
	if e.OwnerNodeID == r.SelfNodeID && r.LocalIP != nil {
		return r.LocalIP, "", nil
	}
	if ip := net.ParseIP(e.OwnerHost); ip != nil {
		return ip, "", nil
	}
	return nil, e.OwnerHost, nil
}

func (r *Responder) isPlatformHost(host string) bool {
	d := normHost(r.Domain)
	return d != "" && strings.HasSuffix(normHost(host), "."+d)
}

// lookupIngress consults the index, then the on-miss read (single-flight,
// with a negative cache) for platform hosts. Candidate IDs come from the
// hostname only here, and only as a lookup key: the placement read decides.
func (r *Responder) lookupIngress(host string) (IngressEntry, bool) {
	if r.Ingress == nil {
		return IngressEntry{}, false
	}
	if e, ok := r.Ingress.Lookup(host); ok {
		return e, true
	}
	if r.Miss == nil || !r.isPlatformHost(host) {
		return IngressEntry{}, false
	}
	host = normHost(host)
	if r.negativeHit(host) {
		return IngressEntry{}, false
	}
	v, _, _ := r.missGroup.Do(host, func() (any, error) {
		label, _, _ := strings.Cut(host, ".")
		candidates := []string{label}
		if i := strings.LastIndexByte(label, '-'); i > 0 {
			if _, err := strconv.Atoi(label[i+1:]); err == nil {
				candidates = append(candidates, label[:i])
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, id := range candidates {
			if p, ok := r.Miss(ctx, id); ok {
				r.Ingress.Upsert(p, r.Domain)
				if e, ok := r.Ingress.Lookup(host); ok {
					return e, nil
				}
			}
		}
		r.rememberNegative(host)
		return nil, errNoAnswer
	})
	if e, ok := v.(IngressEntry); ok {
		return e, true
	}
	return IngressEntry{}, false
}

func (r *Responder) negativeHit(host string) bool {
	r.negMu.Lock()
	defer r.negMu.Unlock()
	until, ok := r.negative[host]
	if !ok {
		return false
	}
	if r.clock().After(until) {
		delete(r.negative, host)
		return false
	}
	return true
}

func (r *Responder) rememberNegative(host string) {
	ttl := r.NegativeTTL
	if ttl <= 0 {
		ttl = 2 * time.Second
	}
	r.negMu.Lock()
	defer r.negMu.Unlock()
	if r.negative == nil {
		r.negative = map[string]time.Time{}
	}
	if len(r.negative) > 100000 {
		r.negative = map[string]time.Time{} // bound memory under a flood
	}
	r.negative[host] = r.clock().Add(ttl)
}

// soa is the authority record on NXDOMAIN/NODATA. Its minimum (the negative
// TTL) matches answerTTL, so a miss is re-asked within a second, never
// cached for the 30 minutes a public zone would impose.
func (r *Responder) soa(name string) dns.RR {
	zone := IngressZone
	if !strings.HasSuffix(name, "."+IngressZone) && normHost(r.Domain) != "" {
		zone = normHost(r.Domain)
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: answerTTL},
		Ns:      "ns." + dns.Fqdn(zone),
		Mbox:    "hostmaster." + dns.Fqdn(zone),
		Serial:  1,
		Refresh: 60, Retry: 60, Expire: 60,
		Minttl: answerTTL,
	}
}

// ListenAndServe serves UDP and TCP on addr (loopback) until ctx ends.
func (r *Responder) ListenAndServe(ctx context.Context, addr string) error {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: r}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: r}
	errc := make(chan error, 2)
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errc:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return err
	}
}
