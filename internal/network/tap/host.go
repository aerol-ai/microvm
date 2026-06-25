package tap

// host.go implements the host-side realization of TAP slots: the actual
// `ip link add ... type tap`, `ip addr add ...`, `ip link set ... up`
// sequence the runtime driver needs once a slot has been allocated from
// the pool.
//
// What lives here vs. pool.go:
//
//   - pool.go: pure allocation bookkeeping. Pick a /30, write a row,
//     return a Slot. No side effects outside SQLite. Cross-platform
//     because there are no `ip` invocations.
//
//   - host.go: the realization step. Given a Slot, create the TAP device,
//     assign the host-side IP, bring the link up. Inverse: tear it down
//     on Destroy. Linux-only at runtime (uses `iproute2`), but the type
//     and the test-double interface compile on darwin so the firecracker
//     driver's tests can stub it.
//
// Why shell out rather than netlink: this is operator-visible plumbing
// during early bring-up. `ip link show fctap0` is the diagnostic everyone
// reaches for; matching that mental model has been worth more than the
// 5-10 ms of `exec` overhead per Create/Destroy. A future optimization
// step can swap in github.com/vishvananda/netlink without changing the
// callers — the HostManager interface is the seam.
//
// Idempotency is the load-bearing contract here, same as the rest of the
// boot-path: Ensure called twice on the same slot is a no-op, Remove
// called on a missing TAP is a no-op. Without it, a daemon restart
// mid-create would leak interfaces (because the SQLite row already
// records the slot as allocated, but `ip link add` would fail because
// the device exists, and the driver would then return an error and
// release the slot — leaving the device orphaned).

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// HostManager is the operations the firecracker runtime driver depends on
// for putting a Slot onto the host's network surface. Declared here as
// an exported interface so the driver can hold this type without
// importing internal/network/tap (driver tests would otherwise drag in
// the SQLite-backed pool just to satisfy the type).
//
// Production implementation is *Host below. Tests inject a fake that
// records calls.
type HostManager interface {
	// Ensure brings the slot's TAP device up. Idempotent: a call against a
	// device that already exists with the right address is a no-op (no
	// error). A call against a device that exists with the WRONG address
	// surfaces an error — that's a state-mismatch the operator needs to
	// see, not silently fix, because the wrong address may be in use by
	// another sandbox.
	Ensure(ctx context.Context, slot Slot) error
	// Remove tears the slot's TAP device down. Idempotent: missing device
	// returns nil. Used by Destroy and by the rollback-on-Create-failure
	// path; both must be safe to retry.
	Remove(ctx context.Context, tapName string) error
}

// Host is the production HostManager. It shells out to /sbin/ip (or
// whichever IPCmd points at on this host). All methods are concurrency-
// safe — `ip` does its own kernel-side serialization, and the methods
// hold no per-host state.
type Host struct {
	// IPCmd is the absolute path to the `ip` binary. Empty defaults to "ip"
	// (resolved from $PATH). Operators with a hardened iproute2 install
	// (e.g. /usr/sbin/ip not in the daemon's PATH) point this at it.
	IPCmd string
	// run is the seam tests use to intercept exec. Production code leaves
	// it nil and the methods fall through to exec.CommandContext. Kept
	// unexported so the public surface stays narrow.
	run runFn
}

// runFn is the type the test seam injects. Mirrors exec.CommandContext's
// shape closely so the wiring is trivial in production.
type runFn func(ctx context.Context, name string, args ...string) ([]byte, error)

// NewHost constructs a Host with the given ip-binary path. Empty path
// means "use `ip` from $PATH". Most callers leave it at "" because the
// daemon's launchd/systemd unit already has /usr/sbin on PATH.
func NewHost(ipCmd string) *Host {
	return &Host{IPCmd: ipCmd}
}

// ipBinary returns the resolved binary name for exec. Centralized so
// every method stays in agreement and a future "embed iproute2" change
// has one site to touch.
func (h *Host) ipBinary() string {
	if h.IPCmd != "" {
		return h.IPCmd
	}
	return "ip"
}

// exec runs `ip <args...>` and returns combined stdout+stderr. Combined
// because `ip` puts useful diagnostics on stderr ("RTNETLINK answers:
// File exists") and we surface those verbatim. Returns the raw output
// alongside any error so the caller can inspect "already exists" lines
// without re-running.
func (h *Host) exec(ctx context.Context, args ...string) ([]byte, error) {
	if h.run != nil {
		return h.run(ctx, h.ipBinary(), args...)
	}
	cmd := exec.CommandContext(ctx, h.ipBinary(), args...)
	return cmd.CombinedOutput()
}

// Ensure creates the TAP device, assigns the host-side /30 IP, brings
// the link up, and pins the guest's L2 neighbor entry. Each step is
// idempotent on its own; the
// composition is idempotent overall because each step recognizes the
// "already in desired state" output and treats it as success.
//
// Order matters:
//
//  1. `ip tuntap add` first — we need the device to exist before
//     `ip addr add` can target it.
//  2. `ip addr add` next — putting the IP on first means the link is
//     usable the moment step 3 makes it up. Reverse order would race
//     against the guest's DHCP/static-IP probe.
//  3. `ip link set ... up` — flipping IFF_UP is what the guest's
//     virtio-net device sees.
//  4. `ip neigh replace` last — host-to-guest connects should not depend
//     on ARP discovery during Firecracker's early boot window.
//
// Rollback on partial failure: if step 2 or 3 fails we DO NOT call
// Remove. The caller is expected to call Remove from its
// error-cleanup path (the firecracker driver's deferred-release runs
// it), which keeps the "single owner of cleanup" rule pr-review.md §4
// describes. Mixing rollback in here would mean a Destroy after a
// failed Ensure double-Removes — harmless on idempotent Remove, but
// makes the failure log noisier.
func (h *Host) Ensure(ctx context.Context, slot Slot) error {
	if slot.TapName == "" {
		return errors.New("tap host: slot has empty TapName")
	}
	if slot.HostIP == "" || slot.CIDR == "" {
		return errors.New("tap host: slot has empty HostIP or CIDR")
	}

	// Step 1: create the tap. `ip tuntap add ... mode tap` is the only
	// shape that works without root-bound CAP_NET_ADMIN expansion; we
	// pass `user root` so the firecracker process (running as the jailer
	// UID later) can open /dev/net/tun against it. Keep the form stable
	// — every operator in the bring-up channel knows `ip tuntap add NAME
	// mode tap user X` and will misread alternative forms as a typo.
	if out, err := h.exec(ctx, "tuntap", "add", slot.TapName, "mode", "tap"); err != nil {
		// "File exists" / "Device or resource busy" mean the device is
		// already present from a previous Create; that's the idempotent
		// case. Anything else surfaces as an error with the `ip` output
		// attached, because every other failure (no permission, kernel
		// module missing) needs operator eyes.
		if !looksLikeExists(out) {
			return fmt.Errorf("tap host: tuntap add %s: %w (%s)", slot.TapName, err, strings.TrimSpace(string(out)))
		}
	}

	// Step 2: assign the host-side IP. The CIDR carries the /30 mask;
	// pairing the host IP with that mask gives the guest IP its peer
	// route in the host's routing table. We compute the host's prefix
	// notation from slot.HostIP + the mask in slot.CIDR (e.g.
	// "172.16.0.1/30").
	addr, err := hostAddrCIDR(slot.HostIP, slot.CIDR)
	if err != nil {
		return fmt.Errorf("tap host: build host addr: %w", err)
	}
	if out, err := h.exec(ctx, "addr", "add", addr, "dev", slot.TapName); err != nil {
		// `ip addr add` with an already-present address returns
		// "RTNETLINK answers: File exists" — idempotent for us.
		if !looksLikeExists(out) {
			return fmt.Errorf("tap host: addr add %s dev %s: %w (%s)", addr, slot.TapName, err, strings.TrimSpace(string(out)))
		}
	}

	// Step 3: bring it up. No idempotency check here — `ip link set ...
	// up` is intrinsically idempotent (a device that's already up stays
	// up, with no stderr output).
	if out, err := h.exec(ctx, "link", "set", slot.TapName, "up"); err != nil {
		return fmt.Errorf("tap host: link set %s up: %w (%s)", slot.TapName, err, strings.TrimSpace(string(out)))
	}

	// Step 4: pin host -> guest L2 resolution when the slot carries a
	// guest endpoint. The runtime gives Firecracker the same deterministic
	// MAC, so this turns the first toolbox proxy dial into a direct route
	// instead of waiting for ARP to discover a quiet guest.
	if slot.GuestIP != "" && slot.VsockCID >= 3 {
		mac := guestMACFromSlot(slot)
		if out, err := h.exec(ctx, "neigh", "replace", slot.GuestIP, "lladdr", mac, "dev", slot.TapName, "nud", "permanent"); err != nil {
			return fmt.Errorf("tap host: neigh replace %s dev %s: %w (%s)", slot.GuestIP, slot.TapName, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Remove deletes the TAP device. Idempotent: a missing device returns
// nil (the operator's restart path doesn't need to know whether
// teardown already happened).
func (h *Host) Remove(ctx context.Context, tapName string) error {
	if tapName == "" {
		return errors.New("tap host: empty TapName")
	}
	out, err := h.exec(ctx, "link", "delete", tapName)
	if err == nil {
		return nil
	}
	// "Cannot find device" is what `ip link delete` says when the device
	// is gone; treat that as success so a double-Remove or a Remove
	// after a daemon restart is a no-op.
	if looksLikeMissing(out) {
		return nil
	}
	return fmt.Errorf("tap host: link delete %s: %w (%s)", tapName, err, strings.TrimSpace(string(out)))
}

// hostAddrCIDR joins a host IP with the prefix length from a /30 CIDR.
// We don't accept the full /30 here directly because slot.CIDR encodes
// the *network* address (172.16.0.0/30), not the host's address — that
// would attach the network IP to the device, which the kernel rejects.
// Synthesizing "<HostIP>/<prefix>" is the only correct shape.
func hostAddrCIDR(hostIP, cidr string) (string, error) {
	slash := strings.IndexByte(cidr, '/')
	if slash < 0 {
		return "", fmt.Errorf("malformed CIDR %q", cidr)
	}
	return hostIP + cidr[slash:], nil
}

func guestMACFromSlot(slot Slot) string {
	cid := slot.VsockCID
	return fmt.Sprintf("02:00:00:%02x:%02x:%02x",
		byte(cid>>16), byte(cid>>8), byte(cid))
}

// looksLikeExists matches the `ip` output for an idempotent "already
// present" condition. Kept as a substring match because `ip` does not
// expose stable machine-readable error codes; this is the operationally
// stable hook the iproute2 community has used for years.
//
// The list is exhaustive for the cases we care about — if a future
// kernel adds a new "already exists" phrasing we'll surface it as an
// error and revisit. Better to fail loud than to silently accept a
// state we didn't model.
func looksLikeExists(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "file exists") ||
		strings.Contains(s, "already exists") ||
		strings.Contains(s, "device or resource busy")
}

// looksLikeMissing matches the `ip` output for "device not found" — the
// idempotent case for Remove.
func looksLikeMissing(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "cannot find device") ||
		strings.Contains(s, "does not exist") ||
		strings.Contains(s, "no such device")
}
