package daemon

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// workerFenceTick paces the fence's re-plan and check (the reassert itself
// is every workerfence.ReassertInterval); a failed install is also retried
// by the next worker start.
const workerFenceTick = 10 * time.Second

// Seams for wireWasmWorkerFence; tests replace them.
var (
	newWorkerFenceBackend = workerfence.NewBackend
	workerFenceGOOS       = goruntime.GOOS
	resolvConfPath        = "/etc/resolv.conf"
	nodeInterfaceAddrs    = net.InterfaceAddrs
)

// wireWasmWorkerFence installs the WASM worker fence (internal/network/
// workerfence) when workers drop, before any worker starts, and makes it
// the gate every dropped worker start asks (worker.SetConfineGate). It
// returns the loopback address the driver binds guest listeners on, ""
// when there is no fence.
//
// Fail closed: a worker that drops is not started while the fence is not
// in the kernel. The drop is worth what the worker uid cannot reach; a
// dropped worker that can still drive Caddy's admin API or read the
// instance role's credentials is not safe, and running it as root instead
// would be worse. So the create fails with the fence's error, the fence
// logs it loudly once, and the next worker start (and the fence's own
// tick) tries the install again. Workers kept root for a legacy mount are
// not asked: the fence is about the worker uid.
//
// A node with the host firewall off (SB_ENABLE_NETWORK_RULES=false, local
// mode, not enterprise) gets no fence, as it gets no IPv6 fence and no IPv4
// floor: the operator turned the host firewall off, and refusing creates
// there would only break local development. That is said loudly at boot.
func wireWasmWorkerFence(ctx context.Context, cfg config.Config, c worker.Confinement, logger *slog.Logger) string {
	if !c.Enabled() || workerFenceGOOS != "linux" {
		worker.SetConfineGate(nil)
		return ""
	}
	if !cfg.EnableNetworkRules && !cfg.EnterpriseMode {
		logger.Warn("host firewall off (SB_ENABLE_NETWORK_RULES=false): no WASM worker fence; workers still drop their privileges, but the worker uid can reach the node's loopback services (Caddy's admin API) and the cloud metadata endpoints",
			"uid", c.UID)
		worker.SetConfineGate(nil)
		return ""
	}
	fence := workerfence.New(newWorkerFenceBackend(), func() (workerfence.Spec, error) {
		return workerFenceSpec(cfg, c), nil
	}, logger)
	_ = fence.Ensure() // logs a failure itself; workers are refused until it is in
	worker.SetConfineGate(fence.Ensure)
	go fence.Run(ctx, workerFenceTick)
	return workerfence.GuestListenHost
}

// workerFenceSpec is what the worker uid may still reach, and what else it
// may not, read again on every sync:
//
//   - the audit ingest (SB_AUDIT_INGEST_PORT on 127.0.0.1), where workers
//     post egress records;
//   - a name server resolv.conf lists, on port 53: workers resolve the
//     names guests dial;
//   - the operator's upstream proxy, when the operator file names it by an
//     address or "localhost".
//
// Guest listeners need no exception: only sandboxd opens connections to
// them, and the fence lets the worker uid answer on those (workerfence's
// reply rule). The deny floor is the one every dial guard holds (the
// operator file's deny_cidrs, the metadata endpoints, SB_EGRESS_DENY_FLOOR_
// CIDRS and the floor file), and the node ports are the ones guests may
// still reach on the node's own addresses.
func workerFenceSpec(cfg config.Config, c worker.Confinement) workerfence.Spec {
	spec := workerfence.Spec{UID: c.UID, NodePorts: egresspolicy.NodeAllowedPorts()}
	if port, err := strconv.ParseUint(strings.TrimSpace(os.Getenv("SB_AUDIT_INGEST_PORT")), 10, 16); err == nil && port > 0 {
		spec.Allow = append(spec.Allow, workerfence.Allow{Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: uint16(port), PortHi: uint16(port), Why: "audit ingest"})
	}
	if raw, err := os.ReadFile(resolvConfPath); err == nil {
		for _, ns := range workerfence.Nameservers(raw) {
			for _, proto := range []string{"udp", "tcp"} {
				spec.Allow = append(spec.Allow, workerfence.Allow{Proto: proto, Prefix: netip.PrefixFrom(ns, ns.BitLen()), PortLo: 53, PortHi: 53, Why: "name server"})
			}
		}
	}
	var op *operator.Operator
	if path := strings.TrimSpace(cfg.EgressOperatorFile); path != "" {
		if loaded, err := operator.Load(path); err == nil {
			op = loaded
			spec.Allow = append(spec.Allow, upstreamAllows(op.Upstream())...)
		}
	}
	// A nil operator's floor is the metadata endpoints and the node's
	// extra floor; the floor file's ranges are this process's current copy
	// (wireEgressFloorFile keeps it).
	spec.Floor = append(op.DenyFloor(), egresspolicy.FileFloor()...)
	spec.Local = localAddrs()
	return spec
}

// localAddrs are the node's own addresses, which the fence lists itself on
// a kernel without nft fib. A failed read lists none: the fib rules, where
// the kernel has them, need no list.
func localAddrs() []netip.Addr {
	addrs, err := nodeInterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// upstreamAllows lets the worker uid reach the operator's upstream proxy.
func upstreamAllows(up *operator.UpstreamProxy) []workerfence.Allow {
	if up == nil || up.URL == nil {
		return nil
	}
	port, err := strconv.ParseUint(up.URL.Port(), 10, 16)
	if err != nil || port == 0 {
		port = 80
		if strings.EqualFold(up.URL.Scheme, "https") {
			port = 443
		}
	}
	var out []workerfence.Allow
	for _, a := range workerfence.HostAddrs(up.URL.Hostname()) {
		out = append(out, workerfence.Allow{Proto: "tcp", Prefix: netip.PrefixFrom(a, a.BitLen()), PortLo: uint16(port), PortHi: uint16(port), Why: "upstream proxy"})
	}
	return out
}
