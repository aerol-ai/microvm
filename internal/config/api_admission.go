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

// loadAPIAdmissionConfig reads SB_API_LIST_MAX_INFLIGHT (0 = no limit) and
// SB_API_LIST_QUEUE_WAIT. Both are parsed strictly: a typo that fell back to
// a default would hide that the operator's limit is not in force.
func (cfg *Config) loadAPIAdmissionConfig() error {
	cfg.APIListMaxInflight = DefaultAPIListMaxInflight
	if raw := strings.TrimSpace(os.Getenv("SB_API_LIST_MAX_INFLIGHT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return fmt.Errorf("SB_API_LIST_MAX_INFLIGHT must be a whole number (0 = no limit), got %q", raw)
		}
		cfg.APIListMaxInflight = n
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
