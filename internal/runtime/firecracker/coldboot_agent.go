package firecracker

import (
	_ "embed"
	"fmt"
	"net"
	"runtime"
	"strings"
)

// toolboxdInitScript is the PID-1 shim baked into every cold-boot rootfs.
// See assets/toolboxd-init.sh for the rationale; embedding keeps it in the
// binary so there's no runtime asset path to misconfigure.
//
//go:embed assets/toolboxd-init.sh
var toolboxdInitScript []byte

const (
	// guestToolboxPath / guestInitPath / guestEnvPath are where the
	// cold-boot injector places the agent, its init shim, and the
	// per-sandbox env file inside the guest rootfs. guestInitPath must
	// match the init= in coldBootArgs.
	guestToolboxPath = "/usr/local/bin/toolboxd"
	guestInitPath    = "/usr/local/bin/toolboxd-init"
	guestEnvPath     = "/etc/toolboxd.env"

	// guestToolboxPort is the in-guest HTTP port toolboxd listens on
	// (toolboxd's SB_TOOLBOX_PORT default, cmd/toolboxd/main.go). The host
	// reaches exec/files/sessions at GuestIP:guestToolboxPort over the TAP.
	guestToolboxPort = 2280
)

// coldBootInjectFiles returns the files to bake into a cold-boot rootfs so
// the guest comes up running the agent. Returns nil when no toolbox binary
// is configured — the caller then cold-boots an agent-less guest (Create's
// vsock handshake will time out, which is the honest failure for a
// misconfigured daemon rather than a silently broken sandbox).
//
// The token is per-sandbox, so these files are regenerated on every
// cold-boot Create (cold-boot already builds a fresh rootfs per sandbox).
func coldBootInjectFiles(toolboxBinaryPath, toolboxToken string) []InjectFile {
	if toolboxBinaryPath == "" {
		return nil
	}
	// Shell-quote the token defensively even though tokens are
	// host-generated hex today — keeps a future token format from
	// breaking the `.`-sourced env file.
	env := fmt.Sprintf("SB_TOOLBOX_TOKEN=%s\nSB_TOOLBOX_PORT='%d'\n", shellSingleQuote(toolboxToken), guestToolboxPort)
	return []InjectFile{
		{HostPath: toolboxBinaryPath, GuestPath: guestToolboxPath, Mode: 0o755},
		{Content: toolboxdInitScript, GuestPath: guestInitPath, Mode: 0o755},
		{Content: []byte(env), GuestPath: guestEnvPath, Mode: 0o600},
	}
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// coldBootArgs builds the kernel command line for a cold-boot guest that
// runs the injected agent. It extends the base args with:
//
//   - ip=<guest>::<gw>:<mask>::eth0:off — kernel IP autoconfig (CONFIG_IP_PNP)
//     so eth0 is up before userspace; the agent's HTTP server is then
//     reachable at GuestIP:2280 over the TAP without an in-guest DHCP client.
//   - init=/usr/local/bin/toolboxd-init — run our injected shim as PID 1
//     instead of the stock image's (absent or unrelated) init.
//
// When slot is nil or carries no usable IP, the ip= clause is omitted (the
// guest still boots; only host→guest networking is unconfigured). When
// toolboxInjected is false the init= clause is omitted so an agent-less
// cold-boot falls back to the image's own init.
func coldBootArgs(slot *TapSlot, toolboxInjected bool) string {
	args := baseBootArgsFor(runtime.GOARCH)
	if ipClause := kernelIPArg(slot); ipClause != "" {
		args += " " + ipClause
	}
	if toolboxInjected {
		args += " init=" + guestInitPath
	}
	return args
}

// kernelIPArg renders the Linux `ip=` kernel-autoconfig clause from a TAP
// slot, or "" if the slot lacks the data. Form:
//
//	ip=<client-ip>::<gateway-ip>:<netmask>::<device>:off
//
// gateway is the host side of the /30 (slot.HostIP); netmask is derived
// from slot.CIDR. "off" disables any autoconfig protocol (we supply
// everything statically).
func kernelIPArg(slot *TapSlot) string {
	if slot == nil || slot.GuestIP == "" || slot.HostIP == "" || slot.CIDR == "" {
		return ""
	}
	mask := netmaskFromCIDR(slot.CIDR)
	if mask == "" {
		return ""
	}
	return fmt.Sprintf("ip=%s::%s:%s::%s:off", slot.GuestIP, slot.HostIP, mask, primaryIfaceID)
}

// netmaskFromCIDR turns "172.16.0.2/30" into dotted "255.255.255.252".
// Returns "" on a malformed or non-IPv4 CIDR — the caller then drops the
// ip= clause rather than booting with a bogus mask.
func netmaskFromCIDR(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet == nil {
		return ""
	}
	m := ipnet.Mask
	if len(m) != net.IPv4len {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}
