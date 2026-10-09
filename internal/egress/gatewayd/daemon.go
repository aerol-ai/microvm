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
	"github.com/aerol-ai/microvm/internal/egress/inspect"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/egress/procid"
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
	// savedLearn is the recorder version last written to disk, per sandbox;
	// saveMu serializes saveNow (the save loop, Close and tests), which
	// alone touches it, so two saves never both see a version as unsaved.
	saveMu     sync.Mutex
	savedLearn map[string]uint64

	probeMu sync.Mutex
	probes  map[netip.Addr]*egress.ProbeResult

	started time.Time
	// floor is the operator's deny_cidrs, node-wide for every sandbox;
	// upstream and opHash are the rest of the operator file in force. opMu
	// guards the three: a reload replaces them while the server runs.
	opMu       sync.Mutex
	floor      []netip.Prefix
	upstream   *egresspolicy.Upstream
	opHash     string
	statsMu    sync.Mutex
	denied     map[string]uint64
	layoutLost bool
	// lossGen counts detected table losses; a sandboxd Sync that started
	// after the latest one acknowledges it (layoutSynced).
	lossGen      uint64
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
		savedLearn:   map[string]uint64{},
		probes:       map[netip.Addr]*egress.ProbeResult{},
		denied:       map[string]uint64{},
		started:      time.Now().UTC(),
		seenRejected: map[egress.Elem]time.Time{},
	}
	d.floor, d.upstream = deps.Guard.DenyFloor, deps.Upstream
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
		InspectMaxBody: cfg.InspectMaxBody,
		Identify:       identifier(cfg.ProcidSocket),
	})
	d.lns = newBridgeListeners(cfg.DNSPort, cfg.ProxyPort, dns.HandlerFunc(d.serveDNS), d.serveProxy, deps.Listen, log)
	d.srv = egress.NewServer(d.gw, egress.ServerHooks{
		SetBridges:    d.setBridges,
		Probe:         d.probe,
		Listeners:     d.lns.Addrs,
		Learned:       d.learned,
		ForgetLearned: d.forgetLearned,
		RetainLearned: d.retainLearned,
		Changed:       d.markDirty,
		NodeControl:   d.setNodeControl,
		LossGen:       d.layoutLossGen,
		Synced:        d.layoutSynced,
		InspectCA:     d.setInspectCA,
	}, deps.Peer, d.hub, log)
	if err := d.restore(); err != nil {
		log.Warn("egress: snapshot not restored; waiting for sandboxd sync", "error", err)
	}
	return d, nil
}

// setInspectCA installs the node's inspection CA (P3-1). It lives in memory
// only: the key never reaches the snapshot, and sandboxd sends it again
// after every gateway start, before its Sync.
func (d *Daemon) setInspectCA(ca egress.InspectCA) error {
	a, err := inspect.New(ca.CertPEM, ca.KeyPEM, nil)
	if err != nil {
		return err
	}
	d.px.SetInspector(a)
	return nil
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
	nw.Floor = d.denyFloor()
	return d.gw.SetNodeWide(nw)
}

func (d *Daemon) denyFloor() []netip.Prefix {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	return d.floor
}

// SetOperator applies a reloaded operator file (review finding 7): the DNS
// filter and the proxy get the new dial guard and upstream chain, the
// node-wide deny floor is rewritten, and proxied connections the new guard
// refuses are closed. An upstream chain that can't be built (unreadable
// credentials) keeps the previous one, as sandboxd does for isolate.
func (d *Daemon) SetOperator(op *operator.Operator) {
	guard := op.Guard()
	d.opMu.Lock()
	up, err := op.UpstreamDialer()
	if err != nil {
		d.log.Error("egress operator file: upstream proxy not updated", "error", err)
		up = d.upstream
	}
	d.floor, d.upstream, d.opHash = guard.DenyFloor, up, op.Hash()
	d.opMu.Unlock()
	d.dns.SetOperator(guard, up)
	d.px.SetOperator(guard, up)
	nw := d.gw.NodeWideState()
	nw.Floor = guard.DenyFloor
	if err := d.gw.SetNodeWide(nw); err != nil {
		d.log.Error("egress operator file: deny floor not rewritten", "error", err)
	}
	closed := d.gw.RevalidateConns(func(pol *egresspolicy.Policy, host string, dst netip.AddrPort) bool {
		return dst.IsValid() && guard.Check(pol, egresspolicy.DialTarget{Name: host, NameAllowed: true, Addr: dst}) != nil
	})
	d.log.Info("egress operator file applied", "hash", op.Hash(), "connections_closed", closed)
}

// OperatorHash is the operator file in force ("" without one).
func (d *Daemon) OperatorHash() string {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	return d.opHash
}

// setNodeControl replaces the control endpoints the node-wide guard drops
// (sandboxd sends them from cluster membership, §5.10 PC-2).
func (d *Daemon) setNodeControl(eps []netip.AddrPort) error {
	nw := d.gw.NodeWideState()
	nw.Control, nw.ControlKnown = eps, true
	nw.Floor = d.denyFloor()
	return d.gw.SetNodeWide(nw)
}

func (d *Daemon) markDirty() {
	select {
	case d.dirty <- struct{}{}:
	default:
	}
}

// Serve runs the gateway until ctx ends or the UDS server on ln fails: the
// server, plus the heartbeat, flow reader and snapshot writer.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	// The loops end with Serve, not only with ctx. On a server failure they
	// would otherwise keep Serve waiting forever: a process that serves
	// nothing, never exits, and so is never restarted.
	loopCtx, stopLoops := context.WithCancel(ctx)
	defer stopLoops()
	var wg sync.WaitGroup
	loops := []func(context.Context){d.heartbeatLoop, d.flowLoop, d.snapshotLoop}
	for _, loop := range loops {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(loopCtx) }(loop)
	}
	errc := make(chan error, 1)
	go func() { errc <- d.srv.Serve(ln) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	stopLoops()
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
		// A recording saved on disk (a stopped sandbox's, one from before
		// a restart) is picked up, so new traffic adds to it rather than a
		// fresh recorder overwriting it (review finding 14).
		if r = d.loadRecordingLocked(id); r == nil {
			r = egresspolicy.NewRecorder(d.cfg.LearnMax)
		}
		d.learn[id] = r
	}
	return r
}

func (d *Daemon) learned(id string) (json.RawMessage, error) {
	d.learnMu.Lock()
	r := d.learn[id]
	if r == nil {
		// Readable until the sandbox is destroyed, attached or not: a stopped
		// sandbox's recording is on disk only after a restart.
		if r = d.loadRecordingLocked(id); r != nil {
			d.learn[id] = r
		}
	}
	d.learnMu.Unlock()
	if r == nil {
		return json.Marshal(egresspolicy.NewRecorder(d.cfg.LearnMax).Snapshot())
	}
	return json.Marshal(r.Snapshot())
}

// loadRecordingLocked reads a sandbox's saved recording, or nil if it has
// none (or it can't be read). Callers hold learnMu.
func (d *Daemon) loadRecordingLocked(id string) *egresspolicy.Recorder {
	b, err := os.ReadFile(d.recordingPath(id))
	if err != nil {
		return nil
	}
	var l egresspolicy.Learned
	if err := json.Unmarshal(b, &l); err != nil {
		d.log.Warn("egress: learn recording unreadable; starting it over", "sandbox_id", id, "error", err)
		return nil
	}
	return egresspolicy.RestoreRecorder(d.cfg.LearnMax, l)
}

// retainLearned drops every recording, in memory and on disk, of a sandbox
// not in ids: sandboxd's inventory of every sandbox this node still holds,
// started or stopped, plus attaches it hasn't written yet. A destroy whose
// forget_learned never reached the gateway (it was down), and the delete
// paths that don't send one, are collected here (review finding 13).
// Membership in the inventory, not attachment, decides, so a stopped
// sandbox keeps its recording until it is destroyed.
func (d *Daemon) retainLearned(ids []string) error {
	keep := make(map[string]bool, len(ids))
	keepFiles := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[id] = true
		keepFiles[safeName(id)+".json"] = true
	}
	d.learnMu.Lock()
	for id := range d.learn {
		if !keep[id] {
			delete(d.learn, id)
		}
	}
	d.learnMu.Unlock()
	dir := filepath.Join(d.cfg.StateDir, "learn")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || keepFiles[name] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// forgetLearned drops a destroyed sandbox's recording, in memory and on disk.
func (d *Daemon) forgetLearned(id string) error {
	d.learnMu.Lock()
	delete(d.learn, id)
	d.learnMu.Unlock()
	err := os.Remove(d.recordingPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (d *Daemon) recordingPath(id string) string {
	return filepath.Join(d.cfg.StateDir, "learn", safeName(id)+".json")
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

// resyncSelf re-applies the gateway's own state after a layout rebuild, as
// one operation against every attach, detach and block write
// (Gateway.Reapply).
func (d *Daemon) resyncSelf() error {
	return d.gw.Reapply()
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
		} else if err := d.resyncSelf(); err != nil {
			d.log.Error("egress: re-apply after rebuild failed", "error", err)
		}
	}
	d.statsMu.Lock()
	if lost {
		d.layoutLost = true
		d.lossGen++
	}
	lostSeen := d.layoutLost
	d.statsMu.Unlock()
	// Kernel writes that failed (a block, a learned or conntrack cleanup)
	// are re-driven here rather than waiting for sandboxd.
	if err := d.gw.RetryDirty(); err != nil {
		d.log.Warn("egress: retrying failed kernel writes", "error", err)
	}
	specs := d.gw.Specs()
	n := 0
	for _, s := range specs {
		if !strings.HasPrefix(s.ID, probePrefix) {
			n++
		}
	}
	d.hub.Publish(egress.Event{Kind: "heartbeat", LayoutOK: !lost, LayoutLostSeen: lostSeen,
		AuditDropped: d.hub.Dropped(), FQDNSandboxes: n, ProxyConns: d.px.Active(), ProxyConnCap: d.cfg.ProxyMaxConns,
		Denied: d.DeniedCounts(), DNSQueries: d.dns.Queries(), GatewayStart: d.started, OperatorHash: d.OperatorHash(), Time: time.Now().UTC()})
}

// layoutLossGen is the table-loss generation an incoming Sync starts from.
func (d *Daemon) layoutLossGen() uint64 {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	return d.lossGen
}

// layoutSynced clears the latched table loss once sandboxd's Sync, begun
// after the latest loss, succeeded: sandboxd has held, re-synced and is
// re-attaching, so reporting the loss again would only repeat that. A loss
// detected while the Sync ran stays reported.
func (d *Daemon) layoutSynced(gen uint64) {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	if d.lossGen == gen {
		d.layoutLost = false
	}
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
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
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
	// A forgotten or collected recording's version entry goes with it.
	for id := range d.savedLearn {
		if _, ok := recs[id]; !ok {
			delete(d.savedLearn, id)
		}
	}
	// Only recordings that changed are rewritten (S9): at density a full
	// rewrite would be ~100 MB every few seconds.
	for id, r := range recs {
		v := r.Version()
		if d.savedLearn[id] == v {
			continue
		}
		b, err := json.Marshal(r.Snapshot())
		if err != nil {
			continue
		}
		if err := writeFileAtomic(d.recordingPath(id), b); err != nil {
			d.log.Warn("egress: save learn recording", "sandbox_id", id, "error", err)
			continue
		}
		d.savedLearn[id] = v
		// A forget that ran while this was being written must win.
		d.learnMu.Lock()
		_, live := d.learn[id]
		d.learnMu.Unlock()
		if !live {
			_ = os.Remove(d.recordingPath(id))
			delete(d.savedLearn, id)
		}
	}
}

// loadRecordings restores the learn recordings saved on disk, so GET
// /learned answers the same across a gateway restart and new traffic adds to
// what was recorded. A recording is restored for any sandbox the snapshot
// knows, learning or not: one switched to enforce stays readable until its
// sandbox is destroyed.
func (d *Daemon) loadRecordings(specs []egress.Spec) {
	d.learnMu.Lock()
	defer d.learnMu.Unlock()
	for _, s := range specs {
		if r := d.loadRecordingLocked(s.ID); r != nil {
			d.learn[s.ID] = r
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

// createTemp is os.CreateTemp. Tests substitute a file whose write or sync
// fails, which a fresh temp file never does, and a forget that lands while a
// recording is being written: neither may leave a recording in place.
var createTemp = os.CreateTemp

func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := createTemp(filepath.Dir(path), ".tmp-*")
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

// identifier asks sandboxd which executable holds a traced connection: the
// gateway runs unprivileged and can't read a sandbox's /proc itself (review
// finding 16). sandboxd resolves the sandbox's process from its own record,
// so the pid the gateway holds isn't sent. No socket refuses per-binary
// flows (binary_unknown), never admits them.
func identifier(socket string) proxy.Identifier {
	if socket == "" {
		return nil
	}
	c := procid.Client{Path: socket}
	return func(sandboxID string, _ int, local, remote netip.AddrPort, paths []string) (func(string) bool, error) {
		return c.Match(sandboxID, local, remote, paths)
	}
}
