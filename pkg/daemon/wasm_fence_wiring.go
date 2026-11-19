package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/network/workerfence"
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
	localPortRangePath    = "/proc/sys/net/ipv4/ip_local_port_range"
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

// workerFenceSpec is what the worker uid may still reach inside the fenced
// ranges, read again on every sync:
//
//   - its guests' listeners, on GuestListenHost and the ephemeral ports a
//     listener bound to port 0 gets: a worker proxies an exposed port's
//     requests to its own guest's listener;
//   - the audit ingest (SB_AUDIT_INGEST_PORT on 127.0.0.1), where workers
//     post egress records;
//   - a name server resolv.conf lists on loopback or link-local
//     (systemd-resolved's 127.0.0.53, Amazon's 169.254.169.253), on port
//     53: workers resolve the names guests dial;
//   - the operator's upstream proxy, when the operator file names it by a
//     loopback or link-local address or "localhost".
//
// Plan drops every exception outside the fenced ranges, so a name server
// or proxy elsewhere adds nothing.
func workerFenceSpec(cfg config.Config, c worker.Confinement) workerfence.Spec {
	spec := workerfence.Spec{UID: c.UID}
	lo, hi := uint16(1024), uint16(65535)
	if raw, err := os.ReadFile(localPortRangePath); err == nil {
		if l, h, err := workerfence.PortRange(raw); err == nil {
			lo, hi = l, h
		}
	}
	listen := netip.MustParseAddr(workerfence.GuestListenHost)
	spec.Allow = append(spec.Allow, workerfence.Allow{Proto: "tcp", Prefix: netip.PrefixFrom(listen, 32), PortLo: lo, PortHi: hi, Why: "guest listeners"})
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
	if path := strings.TrimSpace(cfg.EgressOperatorFile); path != "" {
		if op, err := operator.Load(path); err == nil {
			spec.Allow = append(spec.Allow, upstreamAllows(op.Upstream())...)
		}
	}
	return spec
}

// upstreamAllows lets the worker uid reach the operator's upstream proxy
// when it sits inside the fenced ranges.
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
