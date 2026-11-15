package wasm

import "sort"

// WASIListenPortDisabled means no wasip1 TCP listener is pre-opened (default).
const WASIListenPortDisabled = -1

// Capabilities configures WASI preopens, env, args, and resource limits for an instance.
type Capabilities struct {
	Env           map[string]string `json:"env,omitempty"`
	Preopens      []Preopen         `json:"preopens,omitempty"`
	Args          []string          `json:"args,omitempty"`
	MemoryMB      int               `json:"memory_mb,omitempty"`
	WallTimeoutNs int64             `json:"wall_timeout_ns,omitempty"`
	// WASIListenPort enables wasip1 pre-open TCP listeners when >= 0 (0 = ephemeral).
	// When unset, use -1 to disable.
	WASIListenPort int    `json:"wasi_listen_port,omitempty"`
	WASIListenHost string `json:"wasi_listen_host,omitempty"`
	// WASIListeners pre-opens one listener per exposed port (#177) and,
	// when set, replaces the single WASIListenPort listener. See Listeners.
	WASIListeners []WASIListener `json:"wasi_listeners,omitempty"`
	// AuditCapability is host control metadata, never exposed in guest Env.
	// It binds worker egress reports to exactly one sandbox incarnation.
	AuditCapability  string `json:"audit_capability,omitempty"`
	AuditIncarnation string `json:"audit_incarnation,omitempty"`
	// NetworkBlockIngress / NetworkBlockEgress carry network_block_all and
	// quota blocks into every instantiation, so the worker's mediator refuses
	// the guest's first dial instead of waiting for a later block message
	// (egress plan P0-1). Host control metadata like the audit fields. The
	// worker only ever ADDS blocks from caps; lifting one takes an explicit
	// set_network_blocks message, so a re-instantiation can't unblock.
	NetworkBlockIngress bool `json:"network_block_ingress,omitempty"`
	NetworkBlockEgress  bool `json:"network_block_egress,omitempty"`
	// EgressAllowOut / EgressDenyOut are the sandbox's egress policy in the
	// shared grammar, enforced by the worker's mediator from the first dial
	// (plans/egress-domain-filtering.md P1-6). EgressPolicySet marks caps
	// that carry the policy at all: caps without it leave the mediator's
	// policy unchanged, so a re-instantiation can never drop a policy.
	EgressAllowOut  []string `json:"egress_allow_out,omitempty"`
	EgressDenyOut   []string `json:"egress_deny_out,omitempty"`
	EgressPolicySet bool     `json:"egress_policy_set,omitempty"`
	// EgressLearn selects learn mode: open egress, recorded by the
	// mediator for GET /network/learned (P2-7).
	EgressLearn bool `json:"egress_learn,omitempty"`
}

// ListenEnabled reports whether wasip1 pre-open TCP listeners are active.
func (c Capabilities) ListenEnabled() bool {
	return c.WASIListenPort >= 0 || len(c.WASIListeners) > 0
}

// WASIListener is one pre-opened wasip1 TCP listener. GuestPort is the
// exposed port it serves: a name the guest and the worker route by, never
// bound itself (WASI has no getsockname, so the guest learns it from
// ListenFDsEnv). HostPort is the loopback port bound for it, 0 for an
// ephemeral one; the worker fills it in once bound.
type WASIListener struct {
	GuestPort int `json:"guest_port"`
	HostPort  int `json:"host_port,omitempty"`
}

// Listeners is the listener set an instance gets, in fd order: the
// WASIListeners ascending by guest port, else the one WASIListenPort
// listener (guest port 0: it serves whichever port it is asked for), else
// none. The first is the primary listener, the one ListenFDEnv names.
func (c Capabilities) Listeners() []WASIListener {
	if len(c.WASIListeners) > 0 {
		out := append([]WASIListener(nil), c.WASIListeners...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].GuestPort < out[j].GuestPort })
		return out
	}
	if c.WASIListenPort >= 0 {
		return []WASIListener{{HostPort: c.WASIListenPort}}
	}
	return nil
}

// Preopen maps a host directory into the guest filesystem.
type Preopen struct {
	GuestPath string `json:"guest_path"`
	HostPath  string `json:"host_path"`
	// ReadOnly lets the guest read the directory but not change it, as a
	// read-only bind does for a container.
	ReadOnly bool `json:"read_only,omitempty"`
}

// UsageStats captures per-invocation metering for billing (UC-42a on wazero).
type UsageStats struct {
	WallDurationMs int64 `json:"wall_duration_ms"`
	// Instructions is populated only on the wasmtime engine seam (UC-42b).
	Instructions int64 `json:"instructions,omitempty"`
}

// RunResult captures a single invocation's outcome.
type RunResult struct {
	ExitCode int        `json:"exit_code"`
	Stdout   string     `json:"stdout,omitempty"`
	Stderr   string     `json:"stderr,omitempty"`
	Usage    UsageStats `json:"usage,omitempty"`
}
