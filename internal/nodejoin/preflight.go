package nodejoin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Preflight (§4.3, CEO D7): checks the machine and the network before
// init or join changes anything, and says how to fix each failure. Each
// check is its own function over Host and Paths, so a test drives one
// check with a fake network or file system.

// CheckStatus is one check's verdict. A warning never stops init or join.
type CheckStatus string

const (
	StatusOK   CheckStatus = "ok"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

// Check is one line of the report.
type Check struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// Report is every check, in order.
type Report struct {
	Checks []Check `json:"checks"`
}

// OK reports whether no check failed.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

func (r *Report) add(c ...Check) { r.Checks = append(r.Checks, c...) }

// Print writes the report as a table, then one "fix:" line per failure or
// warning that has one.
func (r Report) Print(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tDETAIL")
	for _, c := range r.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.Status, c.Detail)
	}
	_ = tw.Flush()
	for _, c := range r.Checks {
		if c.Status != StatusOK && c.Fix != "" {
			fmt.Fprintf(w, "%s %s: %s\n", fixPrefix(c.Status), c.Name, c.Fix)
		}
	}
}

func fixPrefix(s CheckStatus) string {
	if s == StatusFail {
		return "fix"
	}
	return "note"
}

// PrintJSON writes the report as one JSON object.
func (r Report) PrintJSON(w io.Writer) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(struct {
		OK     bool    `json:"ok"`
		Checks []Check `json:"checks"`
	}{r.OK(), r.Checks})
}

// Limits of the checks.
const (
	// maxClockSkew is how far this clock may be from the join server's.
	maxClockSkew = 30 * time.Second
	// DefaultMinFreeBytes is the free space the state folder needs.
	DefaultMinFreeBytes = 2 << 30
)

// checkCgroup never fails: cgroup v1 only loses Firecracker VMs across a
// sandboxd restart (the VM cgroup move needs v2), and today's daemon only
// warns about it too.
func checkCgroup(p Paths, firecracker bool) Check {
	c := Check{Name: "cgroup v2", Status: StatusOK, Detail: "unified hierarchy at " + p.CgroupRoot}
	if _, err := os.Stat(filepath.Join(p.CgroupRoot, "cgroup.controllers")); err == nil {
		return c
	}
	c.Status, c.Detail = StatusWarn, "the unified cgroup hierarchy (v2) is not mounted"
	c.Fix = "boot with systemd.unified_cgroup_hierarchy=1"
	if firecracker {
		c.Detail += "; Firecracker VMs won't survive a sandboxd restart"
	}
	return c
}

// checkKVM fails only on a Firecracker node with no /dev/kvm.
func checkKVM(p Paths, firecracker bool) Check {
	c := Check{Name: "kvm", Status: StatusOK, Detail: "Firecracker is off on this node"}
	if !firecracker {
		return c
	}
	if _, err := os.Stat(p.KVMDevice); err != nil {
		c.Status, c.Detail = StatusFail, p.KVMDevice+" is missing and this node runs Firecracker"
		c.Fix = "use a metal or nested-virt machine, or turn Firecracker off (SB_ENABLE_FIRECRACKER=false)"
		return c
	}
	c.Detail = p.KVMDevice + " is present"
	return c
}

// checkDisk fails when the state folder has less than min bytes free.
func checkDisk(h Host, p Paths, minFree uint64) Check {
	c := Check{Name: "disk", Status: StatusOK}
	free, err := h.FreeBytes(p.StateDir)
	if err != nil {
		c.Status, c.Detail, c.Fix = StatusWarn, "could not read free space: "+err.Error(), "check that "+p.StateDir+" is on a mounted disk"
		return c
	}
	c.Detail = fmt.Sprintf("%s free under %s", humanBytes(free), p.StateDir)
	if free < minFree {
		c.Status = StatusFail
		c.Detail += fmt.Sprintf(" (need %s)", humanBytes(minFree))
		c.Fix = "free space under the state folder " + p.StateDir
	}
	return c
}

func humanBytes(n uint64) string {
	const gib = 1 << 30
	if n >= gib {
		return fmt.Sprintf("%.1f GiB", float64(n)/gib)
	}
	return fmt.Sprintf("%d MiB", n>>20)
}

// portSpec is one TCP port a role needs.
type portSpec struct {
	name string
	port int
}

// rolePorts are the TCP ports a join role listens on (agent.go: workers
// and ingress nodes run no Raft listener). withJoin adds the join port,
// which servers open.
func rolePorts(joinRole string, withJoin bool) []portSpec {
	var out []portSpec
	if joinRole == cluster.JoinRoleServer {
		out = append(out, portSpec{"raft", cluster.DefaultRaftPort})
	}
	out = append(out, portSpec{"gossip", cluster.DefaultGossipPort}, portSpec{"internal", cluster.DefaultInternalPort})
	if withJoin && joinRole == cluster.JoinRoleServer {
		out = append(out, portSpec{"join", cluster.DefaultJoinPort})
	}
	return out
}

// checkLocalPorts fails when a port this node must listen on is held by
// another program. clustered says sandboxd itself already runs in cluster
// mode here (a re-run), so a held port is most likely its own.
func checkLocalPorts(h Host, ports []portSpec, clustered bool) Check {
	c := Check{Name: "local ports", Status: StatusOK}
	var free, held []string
	for _, ps := range ports {
		ln, err := h.Listen(net.JoinHostPort("0.0.0.0", strconv.Itoa(ps.port)))
		if err == nil {
			_ = ln.Close()
			free = append(free, strconv.Itoa(ps.port))
			continue
		}
		held = append(held, fmt.Sprintf("%d (%s)", ps.port, ps.name))
	}
	switch {
	case len(held) == 0:
		c.Detail = "TCP " + strings.Join(free, ", ") + " free"
	case clustered:
		c.Detail = "TCP " + strings.Join(held, ", ") + " in use, by this node's sandboxd in cluster mode"
	default:
		c.Status, c.Detail = StatusFail, "TCP "+strings.Join(held, ", ")+" already in use on this machine"
		c.Fix = "stop the program that holds those ports (sudo ss -ltnp)"
	}
	return c
}

// localChecks are the checks that need nothing but this machine.
func localChecks(h Host, p Paths, env nodeEnv, ports []portSpec, minFree uint64) []Check {
	return []Check{
		checkCgroup(p, env.firecracker()),
		checkKVM(p, env.firecracker()),
		checkDisk(h, p, minFree),
		checkLocalPorts(h, ports, env.clusterMode()),
	}
}

// dialBackListeners opens a listener on each port so the join server can
// dial it back, accepting and closing every connection. A port already
// held (sandboxd itself, on a re-run) is left to its holder: the server's
// TCP dial reaches that just as well.
func dialBackListeners(h Host, ports []portSpec) (func(), error) {
	var lns []net.Listener
	closeAll := func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}
	for _, ps := range ports {
		ln, err := h.Listen(net.JoinHostPort("0.0.0.0", strconv.Itoa(ps.port)))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("listen on TCP %d for the dial-back: %w", ps.port, err)
		}
		lns = append(lns, ln)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}
	return closeAll, nil
}

// dialBackCheck turns the server's dial-back results into one check.
func dialBackCheck(results []cluster.DialBackResult) Check {
	c := Check{Name: "dial-back", Status: StatusOK}
	var ok, bad []string
	for _, r := range results {
		if r.OK {
			ok = append(ok, fmt.Sprintf("%d", r.Port))
		} else {
			bad = append(bad, fmt.Sprintf("%d (%s)", r.Port, r.Name))
		}
	}
	if len(bad) > 0 {
		c.Status, c.Detail, c.Fix = StatusFail, "the join server could not reach this node on TCP "+strings.Join(bad, ", "), portFix
		return c
	}
	c.Detail = "the join server reached this node on TCP " + strings.Join(ok, ", ")
	return c
}

// clockCheck compares this clock with the join server's.
func clockCheck(server, local time.Time) Check {
	c := Check{Name: "clock", Status: StatusOK}
	if server.IsZero() {
		c.Status, c.Detail = StatusWarn, "the join server sent no time to compare with"
		return c
	}
	skew := local.Sub(server)
	if skew < 0 {
		skew = -skew
	}
	c.Detail = fmt.Sprintf("%s off the join server", skew.Round(time.Second))
	if skew > maxClockSkew {
		c.Status, c.Fix = StatusFail, "start time sync (chrony or systemd-timesyncd)"
	}
	return c
}

// remoteInput is what the join-server checks need.
type remoteInput struct {
	joinURL, token, pin, role, nodeID, keyHash, version string
	client                                              *http.Client
}

// remoteResult is what the join-server checks learned.
type remoteResult struct {
	// disc is the checked cluster-info, nil when discovery failed.
	disc *discovery
	// role is the token's role, from the preflight answer ("" if none).
	role   string
	checks []Check
}

// remoteChecks runs discovery, the dial-back, the clock and the node ID
// check against the join server.
func remoteChecks(ctx context.Context, h Host, in remoteInput) remoteResult {
	d, role, checks := remoteChecksInner(ctx, h, in)
	return remoteResult{disc: d, role: role, checks: checks}
}

func remoteChecksInner(ctx context.Context, h Host, in remoteInput) (*discovery, string, []Check) {
	reach := Check{Name: "join server", Status: StatusOK}
	client := in.client
	if client == nil {
		client = insecureClient()
	}
	d, err := discover(ctx, client, in.joinURL, in.token, in.pin)
	if err != nil {
		reach.Status, reach.Detail = StatusFail, err.Error()
		var unreachable *unreachableError
		var refusal *JoinRefusal
		switch {
		case errors.As(err, &unreachable):
			reach.Fix = "open TCP 7003 to the servers, and check the join URL"
		case errors.As(err, &refusal):
			reach.Fix = refusal.FixFor(in.role)
		case errors.Is(err, cluster.ErrJoinTokenFormat):
			reach.Fix = "copy the whole token: 6 characters, a dot, 32 characters"
		default:
			reach.Fix = "check the token and --ca-cert-hash: they must come from this cluster"
		}
		return nil, "", []Check{reach}
	}
	reach.Detail = fmt.Sprintf("%s, cluster %s, installs %s", in.joinURL, shortHash(d.info.ClusterID), d.info.Version)
	out := []Check{reach}
	if in.version != "" && d.info.Version != "" && in.version != d.info.Version {
		out = append(out, Check{Name: "version", Status: StatusWarn,
			Detail: fmt.Sprintf("this sandboxd is %s; the cluster installs %s", in.version, d.info.Version),
			Fix:    "the join server refuses a build no member runs; install " + d.info.Version + " (the installer does)"})
	}

	ports := rolePorts(cluster.JoinRoleServer, false)
	closeListeners, err := dialBackListeners(h, ports)
	if err != nil {
		return d, "", append(out, Check{Name: "dial-back", Status: StatusFail, Detail: err.Error(), Fix: "stop the program that holds the port"})
	}
	var resp cluster.PreflightResponse
	err = postJoin(ctx, pinnedClient(d.pool), in.joinURL, cluster.JoinPreflightPath, cluster.PreflightRequest{
		Token: in.token, Role: in.role, NodeID: in.nodeID, KeyHash: in.keyHash,
	}, &resp)
	closeListeners()
	if err != nil {
		c := Check{Name: "dial-back", Status: StatusFail, Detail: err.Error()}
		var refusal *JoinRefusal
		if errors.As(err, &refusal) {
			c.Fix = refusal.FixFor(in.role)
		}
		return d, "", append(out, c)
	}
	out = append(out, dialBackCheck(resp.DialBack),
		Check{Name: "gossip udp", Status: StatusWarn, Detail: "UDP 7001 can't be tested before this node has the gossip key",
			Fix: "make sure UDP 7001 is open between nodes"})
	serverTime := resp.ServerTime
	if serverTime.IsZero() {
		serverTime = d.serverTime
	}
	out = append(out, clockCheck(serverTime, h.Now()))
	if in.nodeID != "" {
		c := Check{Name: "node id", Status: StatusOK, Detail: in.nodeID + " is free"}
		if resp.NodeIDInUse {
			c.Status, c.Detail = StatusFail, in.nodeID+" belongs to another node"
			c.Fix = "pick another --node-id, or delete the old node first (aerolvm delete node " + in.nodeID + ")"
		}
		out = append(out, c)
	}
	return d, resp.Role, out
}

// shortHash keeps a CA hash readable in a table.
func shortHash(h string) string {
	if len(h) > 19 {
		return h[:19] + "…"
	}
	return h
}

// PreflightOptions is `sandboxd preflight`.
type PreflightOptions struct {
	JoinURL    string
	Token      string
	CACertHash string
	// Role is the join role this machine is for (server, worker, ingress),
	// which picks the ports. Empty means the token's role, or server
	// without --join.
	Role         string
	NodeID       string
	MinFreeBytes uint64
}

// Preflighter runs the checks.
type Preflighter struct {
	Paths   Paths
	Host    Host
	Version string
	// Client reaches the join port before the CA is known; nil is the
	// real one.
	Client *http.Client
}

// Run runs every check that applies and returns the report.
func (pf *Preflighter) Run(ctx context.Context, o PreflightOptions) (Report, error) {
	env, err := loadNodeEnv(pf.Paths)
	if err != nil {
		return Report{}, err
	}
	role := strings.ToLower(strings.TrimSpace(o.Role))
	if role != "" && !cluster.ValidJoinRole(role) {
		return Report{}, fmt.Errorf("--role must be server, worker or ingress, got %q", o.Role)
	}
	portsRole := role
	if portsRole == "" {
		portsRole = cluster.JoinRoleServer
	}
	minFree := o.MinFreeBytes
	if minFree == 0 {
		minFree = DefaultMinFreeBytes
	}
	var r Report
	if o.JoinURL == "" {
		r.add(localChecks(pf.Host, pf.Paths, env, rolePorts(portsRole, true), minFree)...)
		return r, nil
	}
	joinURL, err := normalizeJoinURL(o.JoinURL)
	if err != nil {
		return Report{}, err
	}
	keyH := ""
	if key, ok, _ := loadNodeKey(env.tlsDir(pf.Paths)); ok {
		keyH = keyHash(key)
	}
	// The remote checks first: they learn the token's role, which picks the
	// ports the local check needs free.
	remote := remoteChecks(ctx, pf.Host, remoteInput{
		joinURL: joinURL, token: o.Token, pin: o.CACertHash, role: role, nodeID: strings.TrimSpace(o.NodeID),
		keyHash: keyH, version: pf.Version, client: pf.Client,
	})
	if remote.role != "" {
		portsRole = remote.role
	}
	r.add(localChecks(pf.Host, pf.Paths, env, rolePorts(portsRole, false), minFree)...)
	r.add(remote.checks...)
	return r, nil
}
