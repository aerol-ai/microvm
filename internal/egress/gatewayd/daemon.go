package gatewayd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/dnsfilter"
	"github.com/aerol-ai/microvm/internal/egress/proxy"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// probePrefix marks the self-test's synthetic sandbox (T41).
const probePrefix = "__probe__"

// Deps are the kernel and network seams (tests swap them).
type Deps struct {
	Backend     egress.Backend
	Conntrack   egress.ConntrackFlusher
	Listen      func(network, addr string) (net.Listener, net.PacketConn, error)
	OriginalDst func(net.Conn) (netip.AddrPort, error)
	Dialer      proxy.Dialer
	Peer        egress.PeerCheck
	Guard       egresspolicy.DialGuard
	// Upstream is the operator's proxy chain (§5.10 PC-4), or nil.
	Upstream *egresspolicy.Upstream
}

// Daemon is a running gateway.
type Daemon struct {
	cfg   Config
	log   *slog.Logger
	gw    *egress.Gateway
	hub   *egress.EventHub
	dns   *dnsfilter.Filter
	px    *proxy.Proxy
	lns   *bridgeListeners
	srv   *egress.Server
	deps  Deps
	dirty chan struct{}

	learnMu sync.Mutex
	learn   map[string]*egresspolicy.Recorder

	probeMu sync.Mutex
	probes  map[netip.Addr]*egress.ProbeResult

	started time.Time
	// floor is the operator's deny_cidrs, node-wide for every sandbox.
	floor        []netip.Prefix
	statsMu      sync.Mutex
	denied       map[string]uint64
	layoutLost   bool
	seenRejected map[egress.Elem]time.Time
}

// New builds a gateway from cfg and deps. It creates (or confirms) the nft
// layout and restores the snapshot, but binds nothing until Serve.
func New(cfg Config, deps Deps, log *slog.Logger) (*Daemon, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if deps.Listen == nil {
		deps.Listen = listenFreebind
	}
	d := &Daemon{
		cfg: cfg, log: log, deps: deps,
		hub:          egress.NewEventHub(cfg.AuditBuffer),
		dirty:        make(chan struct{}, 1),
		learn:        map[string]*egresspolicy.Recorder{},
		probes:       map[netip.Addr]*egress.ProbeResult{},
		denied:       map[string]uint64{},
		started:      time.Now().UTC(),
		seenRejected: map[egress.Elem]time.Time{},
	}
	d.floor = deps.Guard.DenyFloor
	d.gw = egress.New(egress.Options{
		Backend:    deps.Backend,
		Conntrack:  deps.Conntrack,
		Layout:     egress.LayoutConfig{DNSPort: cfg.DNSPort, ProxyPort: cfg.ProxyPort},
		LearnedMax: cfg.LearnedMax,
		Logger:     log,
	})
	// Creating the table is the kernel probe: a kernel without interval
	// concatenations (< 5.6) fails here and the gateway reports unavailable.
	if err := d.gw.Bootstrap(); err != nil {
		return nil, err
	}
	d.dns = dnsfilter.New(d.gw, d.gw, d.onDNS, dnsfilter.Config{
		Upstreams: cfg.DNSUpstreams, QPS: cfg.DNSQPS, Guard: deps.Guard, Logger: log, Upstream: deps.Upstream,
	})
	d.px = proxy.New(d.gw, d.onProxy, proxy.Config{
		MaxConns: cfg.ProxyMaxConns, MaxConnsPerSandbox: cfg.ProxyMaxPerSandbox,
		Guard: deps.Guard, OriginalDst: deps.OriginalDst, Dialer: deps.Dialer, Logger: log, Upstream: deps.Upstream,
	})
	d.lns = newBridgeListeners(cfg.DNSPort, cfg.ProxyPort, dns.HandlerFunc(d.serveDNS), d.serveProxy, deps.Listen, log)
	d.srv = egress.NewServer(d.gw, egress.ServerHooks{
		SetBridges:  d.setBridges,
		Probe:       d.probe,
		Listeners:   d.lns.Addrs,
		Learned:     d.learned,
		Changed:     d.markDirty,
		NodeControl: d.setNodeControl,
	}, deps.Peer, d.hub, log)
	if err := d.restore(); err != nil {
		log.Warn("egress: snapshot not restored; waiting for sandboxd sync", "error", err)
	}
	return d, nil
}

// Gateway exposes the core (tests, metrics).
func (d *Daemon) Gateway() *egress.Gateway { return d.gw }

// Events exposes the event hub.
func (d *Daemon) Events() *egress.EventHub { return d.hub }

func (d *Daemon) snapshotPath() string { return filepath.Join(d.cfg.StateDir, "snapshot.json") }

// restore loads the snapshot: specs come back restart-blocked in memory
// (kernel sets untouched until Sync, D13 + eng re-review D2) and listeners
// bind on the last bridge list before sandboxd reconnects (S5).
func (d *Daemon) restore() error {
	snap, ok, err := egress.LoadSnapshot(d.snapshotPath())
	if err != nil || !ok {
		return err
	}
	if err := d.gw.Restore(snap.Specs); err != nil {
		return err
	}
	if len(snap.Bridges) > 0 {
		if err := d.lns.Set(snap.Bridges); err != nil {
			d.log.Warn("egress: rebind snapshot bridges", "error", err)
		}
	}
	d.loadRecordings(snap.Specs)
	return nil
}

func (d *Daemon) setBridges(bridges []egress.Bridge) error {
	if err := d.lns.Set(bridges); err != nil {
		return err
	}
	nw := d.gw.NodeWideState()
	nw.Subnets = nil
	for _, b := range bridges {
		if b.Subnet.IsValid() {
			nw.Subnets = append(nw.Subnets, b.Subnet)
		}
	}
	nw.Floor = d.floor
	return d.gw.SetNodeWide(nw)
}

// setNodeControl replaces the control endpoints the node-wide guard drops
// (sandboxd sends them from cluster membership, §5.10 PC-2).
func (d *Daemon) setNodeControl(eps []netip.AddrPort) error {
	nw := d.gw.NodeWideState()
	nw.Control, nw.ControlKnown = eps, true
	nw.Floor = d.floor
	return d.gw.SetNodeWide(nw)
}

func (d *Daemon) markDirty() {
	select {
	case d.dirty <- struct{}{}:
	default:
	}
}

// Serve runs the gateway until ctx ends: the UDS server on ln, plus the
// heartbeat, flow reader and snapshot writer.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	loops := []func(context.Context){d.heartbeatLoop, d.flowLoop, d.snapshotLoop}
	for _, loop := range loops {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(loop)
	}
	errc := make(chan error, 1)
	go func() { errc <- d.srv.Serve(ln) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	_ = ln.Close()
	d.srv.Close()
	d.lns.Close()
	wg.Wait()
	d.saveNow()
	return err
}

// serveDNS notes probe traffic, then filters.
func (d *Daemon) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	if a, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		d.noteProbe(a.IP, true)
	} else if a, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		d.noteProbe(a.IP, true)
	}
	d.dns.ServeDNS(w, r)
}

// serveProxy wraps the proxy listener so probe connections are noted.
func (d *Daemon) serveProxy(ln net.Listener) {
	_ = d.px.Serve(&probeListener{Listener: ln, d: d})
}

type probeListener struct {
	net.Listener
	d *Daemon
}

func (l *probeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			l.d.noteProbe(a.IP, false)
		}
	}
	return c, err
}

func (d *Daemon) noteProbe(ip net.IP, isDNS bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}
	d.probeMu.Lock()
	defer d.probeMu.Unlock()
	if r := d.probes[addr.Unmap()]; r != nil {
		if isDNS {
			r.DNSSeen = true
		} else {
			r.ProxySeen = true
		}
	}
}

// probe runs the self-test window (T41): sandboxd sends DNS and HTTPS from a
// link-local /32 in a test netns; the gateway attaches that source as a
// gateway-mode sandbox for the window and reports what reached the
// listeners. A host whose INPUT policy drops redirected traffic fails here.
func (d *Daemon) probe(p egress.ProbeRequest) (egress.ProbeResult, error) {
	if !p.Source.Is4() {
		return egress.ProbeResult{}, fmt.Errorf("probe source %q is not IPv4", p.Source)
	}
	id := probePrefix + p.Source.String()
	if p.Begin {
		d.probeMu.Lock()
		d.probes[p.Source] = &egress.ProbeResult{}
		d.probeMu.Unlock()
		return egress.ProbeResult{}, d.gw.Attach(egress.Spec{ID: id, IP: p.Source, AllowOut: []string{"aerolvm-probe.invalid"}})
	}
	deadline := time.Now().Add(p.Wait)
	for {
		d.probeMu.Lock()
		r := d.probes[p.Source]
		var got egress.ProbeResult
		if r != nil {
			got = *r
		}
		d.probeMu.Unlock()
		if (got.DNSSeen && got.ProxySeen) || time.Now().After(deadline) {
			d.probeMu.Lock()
			delete(d.probes, p.Source)
			d.probeMu.Unlock()
			return got, d.gw.Detach(id, p.Source)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---- observers: audit events and learn recording ----

// logDecision writes one gateway decision with the fields log pipelines key
// on (P1-15). Debug level: the audit stream is the durable record, and at
// node scale an Info line per connection would drown everything else.
func (d *Daemon) logDecision(path, sandboxID string, allowed bool, dest, reason, rule string, mode egress.Mode) {
	if !d.log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	d.log.Debug("egress decision", "path", path, "sandbox_id", sandboxID, "allowed", allowed,
		"destination", dest, "reason", reason, "rule", rule, "mode", string(mode))
}

func (d *Daemon) countDenied(reason string) {
	d.statsMu.Lock()
	d.denied[reason]++
	d.statsMu.Unlock()
}

func (d *Daemon) onDNS(dec dnsfilter.Decision) {
	if strings.HasPrefix(dec.SandboxID, probePrefix) {
		return
	}
	if dec.Mode == egress.ModeLearn && dec.Allowed && dec.Name != "" {
		d.recorder(dec.SandboxID).ObserveDNS(dec.Name, dec.Answers)
		d.markDirty()
	}
	if dec.Allowed || dec.Reason == "" {
		return
	}
	d.logDecision("dns", dec.SandboxID, false, dec.Name, dec.Reason, dec.Rule, dec.Mode)
	d.countDenied(dec.Reason)
	d.hub.Publish(egress.Event{Kind: "audit", SandboxID: dec.SandboxID, Result: "denied", Reason: dec.Reason,
		Destination: dec.Name, Rule: dec.Rule, Mode: string(dec.Mode), Time: time.Now().UTC()})
}

func (d *Daemon) onProxy(dec proxy.Decision) {
	if strings.HasPrefix(dec.SandboxID, probePrefix) {
		return
	}
	dest := dec.Host
	if dec.Port != 0 && dest != "" {
		dest = net.JoinHostPort(dec.Host, fmt.Sprint(dec.Port))
	}
	ev := egress.Event{Kind: "audit", SandboxID: dec.SandboxID, Destination: dest, Rule: dec.Rule,
		Reason: dec.Reason, Mode: string(dec.Mode), Time: time.Now().UTC()}
	d.logDecision("proxy", dec.SandboxID, dec.Allowed, dest, dec.Reason, dec.Rule, dec.Mode)
	if dec.Allowed {
		ev.Result = "allowed"
		if dec.Mode == egress.ModeLearn {
			d.recorder(dec.SandboxID).ObserveHost(dec.Host, dec.Port)
			d.markDirty()
		}
	} else {
		ev.Result = "denied"
		d.countDenied(dec.Reason)
	}
	if dec.SandboxID != "" {
		d.hub.Publish(ev)
	}
}

func (d *Daemon) recorder(id string) *egresspolicy.Recorder {
	d.learnMu.Lock()
	defer d.learnMu.Unlock()
	r := d.learn[id]
	if r == nil {
		r = egresspolicy.NewRecorder(d.cfg.LearnMax)
		d.learn[id] = r
	}
	return r
}

func (d *Daemon) learned(id string) (json.RawMessage, error) {
	d.learnMu.Lock()
	r := d.learn[id]
	d.learnMu.Unlock()
	if r == nil {
		return json.Marshal(egresspolicy.NewRecorder(d.cfg.LearnMax).Snapshot())
	}
	return json.Marshal(r.Snapshot())
}

// ---- background loops ----

func (d *Daemon) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(d.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.heartbeat()
		}
	}
}

// heartbeat checks the table (CEO D17). On loss it rebuilds the layout in one
// batch and re-applies its in-memory state at once, so the window without
// filtering is one interval; the heartbeat then tells sandboxd, which holds
// every gateway-mode sandbox and re-syncs to confirm.
func (d *Daemon) heartbeat() {
	lost := false
	if err := d.gw.CheckLayout(); err != nil {
		lost = true
		d.log.Error("egress: nft layout lost; rebuilding", "error", err)
		if err := d.gw.Bootstrap(); err != nil {
			d.log.Error("egress: layout rebuild failed", "error", err)
		} else if err := d.gw.Sync(d.gw.Specs()); err != nil {
			d.log.Error("egress: re-apply after rebuild failed", "error", err)
		}
	}
	d.statsMu.Lock()
	if lost {
		d.layoutLost = true
	}
	lostSeen := d.layoutLost
	d.statsMu.Unlock()
	specs := d.gw.Specs()
	n := 0
	for _, s := range specs {
		if !strings.HasPrefix(s.ID, probePrefix) {
			n++
		}
	}
	d.hub.Publish(egress.Event{Kind: "heartbeat", LayoutOK: !lost, LayoutLostSeen: lostSeen,
		AuditDropped: d.hub.Dropped(), FQDNSandboxes: n, ProxyConns: d.px.Active(), ProxyConnCap: d.cfg.ProxyMaxConns,
		Denied: d.DeniedCounts(), DNSQueries: d.dns.Queries(), GatewayStart: d.started, Time: time.Now().UTC()})
}

// AckLayoutLost clears the latched table-loss flag once sandboxd re-synced.
func (d *Daemon) AckLayoutLost() {
	d.statsMu.Lock()
	d.layoutLost = false
	d.statsMu.Unlock()
}

// DeniedCounts returns denials by reason (aerolvm_egress_denied_total).
func (d *Daemon) DeniedCounts() map[string]uint64 {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	out := make(map[string]uint64, len(d.denied))
	for k, v := range d.denied {
		out[k] = v
	}
	return out
}

func (d *Daemon) flowLoop(ctx context.Context) {
	t := time.NewTicker(d.cfg.FlowReadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.readFlows()
		}
	}
}

// readFlows turns new @rejected_flows elements into firewall_reject audit
// events (C9) and feeds @learn_flows into learn-mode recordings (F3).
func (d *Daemon) readFlows() {
	now := time.Now()
	if rejected, err := d.deps.Backend.List(egress.SetRejectedFlows); err == nil {
		for _, e := range rejected {
			k := egress.Elem{Src: e.Src, Dst: e.Dst, Port: e.Port}
			d.statsMu.Lock()
			_, seen := d.seenRejected[k]
			d.seenRejected[k] = now
			d.statsMu.Unlock()
			if seen {
				continue
			}
			src, ok := d.gw.Source(e.Src)
			if !ok || strings.HasPrefix(src.Spec.ID, probePrefix) {
				continue
			}
			d.countDenied("firewall_reject")
			d.hub.Publish(egress.Event{Kind: "audit", SandboxID: src.Spec.ID, Result: "denied", Reason: "firewall_reject",
				Destination: netip.AddrPortFrom(e.Dst, e.Port).String(), Mode: string(src.Mode), Time: now.UTC()})
		}
		d.statsMu.Lock()
		for k, at := range d.seenRejected {
			if now.Sub(at) > 5*time.Minute {
				delete(d.seenRejected, k)
			}
		}
		d.statsMu.Unlock()
	}
	if flows, err := d.deps.Backend.List(egress.SetLearnFlows); err == nil {
		for _, e := range flows {
			src, ok := d.gw.Source(e.Src)
			if !ok || src.Mode != egress.ModeLearn {
				continue
			}
			d.recorder(src.Spec.ID).ObserveFlow(e.Dst, e.Port)
		}
	}
}

func (d *Daemon) snapshotLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.dirty:
			select {
			case <-ctx.Done():
				return
			case <-time.After(d.cfg.SnapshotDebounce):
			}
			d.saveNow()
		}
	}
}

// saveNow writes the snapshot and the learn recordings. Recordings go in
// their own per-sandbox files so one change never rewrites every recording
// on the node (eng re-review S9).
func (d *Daemon) saveNow() {
	var specs []egress.Spec
	for _, s := range d.gw.Specs() {
		if !strings.HasPrefix(s.ID, probePrefix) {
			specs = append(specs, s)
		}
	}
	if err := egress.SaveSnapshot(d.snapshotPath(), egress.Snapshot{Specs: specs, Bridges: d.lns.Bridges()}); err != nil {
		d.log.Warn("egress: save snapshot", "error", err)
	}
	d.learnMu.Lock()
	recs := make(map[string]*egresspolicy.Recorder, len(d.learn))
	for id, r := range d.learn {
		recs[id] = r
	}
	d.learnMu.Unlock()
	dir := filepath.Join(d.cfg.StateDir, "learn")
	for id, r := range recs {
		b, err := json.Marshal(r.Snapshot())
		if err != nil {
			continue
		}
		if err := writeFileAtomic(filepath.Join(dir, safeName(id)+".json"), b); err != nil {
			d.log.Warn("egress: save learn recording", "sandbox_id", id, "error", err)
		}
	}
}

// loadRecordings reports which learn recordings exist on disk. Recordings are
// rebuilt from live traffic; the files are what GET /learned serves until the
// first new observation (best effort across a gateway restart).
func (d *Daemon) loadRecordings(specs []egress.Spec) {
	for _, s := range specs {
		if !s.Learn {
			continue
		}
		if _, err := os.Stat(filepath.Join(d.cfg.StateDir, "learn", safeName(s.ID)+".json")); err == nil {
			d.recorder(s.ID)
		}
	}
}

func safeName(id string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || r == '.' {
			return '_'
		}
		return r
	}, id)
}

func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// errNoSocket is returned when neither socket activation nor a path is set.
var errNoSocket = errors.New("egress gateway: no socket configured")
