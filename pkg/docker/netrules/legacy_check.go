package netrules

import (
	"log/slog"
	"os/exec"
	"strings"
)

// iptablesVersion is a test seam over `iptables -V`.
var iptablesVersion = func() (string, error) {
	out, err := exec.Command("iptables", "-V").CombinedOutput()
	return string(out), err
}

// iptablesReportsLegacy parses `iptables -V` output, which names the active
// variant in parentheses: "iptables v1.8.7 (legacy)" vs "(nf_tables)".
func iptablesReportsLegacy(version string) bool {
	return strings.Contains(strings.ToLower(version), "legacy")
}

// WarnIfLegacyIptables logs a boot-time warning when the netlink backend is
// selected on a host whose iptables binary runs in legacy (xtables) mode.
// The netlink backend writes to the nft tables, which legacy iptables cannot
// see — the kernel evaluates BOTH rule sets, so flipping SB_NETRULES_BACKEND
// with live sandboxes strands the previous backend's ACCEPT/DROP rules on
// recycled container IPs (TODOS.md "netrules backend switch on
// iptables-legacy hosts"). Best-effort: a missing binary or exec failure
// stays silent — no signal is not a legacy host.
func WarnIfLegacyIptables(backend string, logger *slog.Logger) {
	if logger == nil || !strings.EqualFold(strings.TrimSpace(backend), BackendNetlink) {
		return
	}
	v, err := iptablesVersion()
	if err != nil || !iptablesReportsLegacy(v) {
		return
	}
	logger.Warn("netrules: netlink backend selected but host iptables runs in legacy mode; "+
		"rules written via exec previously are invisible to netlink — drain sandboxes before switching backends",
		"iptables_version", strings.TrimSpace(v))
}
