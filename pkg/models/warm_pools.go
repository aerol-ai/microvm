package models

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Warm pools as an API object (plans/agent-sandbox-feature-parity.md W1).
// An entry names an image and how many warm slots every server with a warm
// pool keeps parked for it. The SB_DOCKER_POOL_* / SB_CONTAINERD_POOL_*
// settings stay the default for every other image; an entry overrides them
// for its own image. Entries are fleet-wide operator config, not owner
// scoped: a parked slot serves whichever caller creates from that image.

const (
	// MaxWarmPools bounds the entries a deployment may hold. Each entry's
	// status rides every warm-pool server's capacity heartbeat (about 60
	// bytes), so the bound is what keeps that payload small at fleet scale.
	MaxWarmPools = 32
	// MaxWarmPoolDepth bounds one entry's depth. The capacity gate still
	// decides how many slots a server can actually park; this only stops a
	// typo from asking every server for thousands.
	MaxWarmPoolDepth = 128
	// maxWarmPoolImageLen bounds the image reference (Docker's own limit on
	// a repository name is 255; a registry host and a digest add to it).
	maxWarmPoolImageLen = 512
)

// ErrWarmPoolInvalid is a warm-pool PUT the server refuses as malformed
// (400).
var ErrWarmPoolInvalid = errors.New("invalid warm pool")

// WarmPool is one image's warm-pool entry. Generation goes up by one on
// every change, so the same PUT twice leaves it alone. Status is filled on
// reads; a PUT answers without it.
type WarmPool struct {
	Image      string          `json:"image"`
	Depth      int             `json:"depth"`
	Generation int64           `json:"generation"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Status     *WarmPoolStatus `json:"status,omitempty"`
}

// WarmPoolRequest is the body of PUT /v1/warm-pools/{image}, a full
// replace: the same body twice is a no-op.
type WarmPoolRequest struct {
	Depth int `json:"depth"`
}

// WarmPoolStatus is how full an entry's pools are: the total over every
// server that runs a warm pool, and each server on its own.
type WarmPoolStatus struct {
	Ready   int                    `json:"ready"`
	Target  int                    `json:"target"`
	Servers []WarmPoolServerStatus `json:"servers"`
}

// WarmPoolServerStatus is one server's pool for an image. Stale marks a
// server whose last capacity report is too old to trust; its numbers are
// the last ones it sent.
type WarmPoolServerStatus struct {
	NodeID string `json:"node_id"`
	Ready  int    `json:"ready"`
	Target int    `json:"target"`
	Stale  bool   `json:"stale,omitempty"`
}

// WarmPoolList is GET /v1/warm-pools: every entry, by image.
type WarmPoolList struct {
	Pools []WarmPool `json:"pools"`
}

// ValidateWarmPoolImage checks an entry's image reference. The pool matches
// creates by the exact string they send, so it is checked for shape only:
// no scheme, no whitespace or control characters, and a sane length.
func ValidateWarmPoolImage(image string) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("%w: image is required", ErrWarmPoolInvalid)
	}
	if image != strings.TrimSpace(image) {
		return fmt.Errorf("%w: image %q has leading or trailing spaces", ErrWarmPoolInvalid, image)
	}
	if len(image) > maxWarmPoolImageLen {
		return fmt.Errorf("%w: image is %d bytes; the limit is %d", ErrWarmPoolInvalid, len(image), maxWarmPoolImageLen)
	}
	if strings.Contains(image, "://") {
		return fmt.Errorf("%w: image %q must be a reference like python:3.12, not a URL", ErrWarmPoolInvalid, image)
	}
	for _, r := range image {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: image %q contains whitespace or a control character", ErrWarmPoolInvalid, image)
		}
	}
	if strings.HasPrefix(image, "/") || strings.HasSuffix(image, "/") || strings.Contains(image, "//") {
		return fmt.Errorf("%w: image %q has an empty path segment", ErrWarmPoolInvalid, image)
	}
	return nil
}

// Validate checks a PUT body.
func (r WarmPoolRequest) Validate() error {
	if r.Depth < 0 || r.Depth > MaxWarmPoolDepth {
		return fmt.Errorf("%w: depth must be between 0 and %d, got %d", ErrWarmPoolInvalid, MaxWarmPoolDepth, r.Depth)
	}
	return nil
}
