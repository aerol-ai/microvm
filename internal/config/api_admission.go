package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Load shedding for cluster-wide sandbox lists (pkg/api/apihttp Gate). Each
// such list fans out: a placement-page read and one request per owner node.
// Past the node's limit a list waits at most the queue wait for a slot and is
// otherwise answered 503 + Retry-After at once, instead of queueing until it
// takes 30 s and the node falls over (bank flagship ramp, 2026-11-01).
const (
	// DefaultAPIListMaxInflight matches the cluster transport's 16 pooled
	// connections per peer (internal/cluster newInternalTransport), so list
	// fan-out reuses mTLS connections instead of handshaking new ones. A
	// healthy list holds its slot for milliseconds, so 16 slots serve
	// thousands of lists a second; they fill only when lists slow down.
	DefaultAPIListMaxInflight = 16
	// DefaultAPIListQueueWait absorbs a burst without making anyone wait
	// long: well inside the SDKs' own retry backoff.
	DefaultAPIListQueueWait = 500 * time.Millisecond
)

// DefaultAPIListMaxInflightPerTenant is one tenant's share of a node's list
// slots when SB_API_LIST_MAX_INFLIGHT_PER_TENANT is unset: a quarter of
// them, at least one. A quarter lets one tenant's burst run four lists at
// once on the default 16 slots while three more tenants could do the same,
// and keeps three quarters of the node for everyone else whatever one tenant
// does. 0 when the gate itself is off.
func DefaultAPIListMaxInflightPerTenant(total int) int {
	if total <= 0 {
		return 0
	}
	return max(1, total/4)
}

// loadAPIAdmissionConfig reads SB_API_LIST_MAX_INFLIGHT (0 = no limit),
// SB_API_LIST_MAX_INFLIGHT_PER_TENANT and SB_API_LIST_QUEUE_WAIT. All are
// parsed strictly: a typo that fell back to a default would hide that the
// operator's limit is not in force.
func (cfg *Config) loadAPIAdmissionConfig() error {
	cfg.APIListMaxInflight = DefaultAPIListMaxInflight
	if raw := strings.TrimSpace(os.Getenv("SB_API_LIST_MAX_INFLIGHT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return fmt.Errorf("SB_API_LIST_MAX_INFLIGHT must be a whole number (0 = no limit), got %q", raw)
		}
		cfg.APIListMaxInflight = n
	}
	cfg.APIListMaxInflightPerTenant = DefaultAPIListMaxInflightPerTenant(cfg.APIListMaxInflight)
	if raw := strings.TrimSpace(os.Getenv("SB_API_LIST_MAX_INFLIGHT_PER_TENANT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return fmt.Errorf("SB_API_LIST_MAX_INFLIGHT_PER_TENANT must be a whole number (0 = no per-tenant share), got %q", raw)
		}
		switch total := cfg.APIListMaxInflight; {
		case total == 0:
			// No gate, so no share; a value left over from before the gate
			// was turned off must not refuse the boot that turns it off.
		case n > total:
			return fmt.Errorf("SB_API_LIST_MAX_INFLIGHT_PER_TENANT (%d) is more than SB_API_LIST_MAX_INFLIGHT (%d): a tenant's share cannot exceed the node's slots", n, total)
		case n == 0:
			cfg.APIListMaxInflightPerTenant = total
		default:
			cfg.APIListMaxInflightPerTenant = n
		}
	}
	cfg.APIListQueueWait = DefaultAPIListQueueWait
	if raw := strings.TrimSpace(os.Getenv("SB_API_LIST_QUEUE_WAIT")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < 0 {
			return fmt.Errorf("SB_API_LIST_QUEUE_WAIT must be a duration such as 500ms (0 = refuse at once), got %q", raw)
		}
		cfg.APIListQueueWait = d
	}
	return nil
}
