package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultLivenessSocket is where sandboxd answers "is this process
// responsive?" for the install.sh watchdog (sandboxd-healthcheck). It sits
// in /run/sandboxd, which the unit's ExecStartPre makes root 0700: only root
// (the watchdog) needs to reach it.
const DefaultLivenessSocket = "/run/sandboxd/live.sock"

// LivenessSocketOff turns the liveness socket off. The watchdog then falls
// back to probing /health on the API port, as releases before it did.
const LivenessSocketOff = "off"

// loadLivenessConfig reads SB_LIVENESS_SOCKET. A relative path is refused:
// the watchdog and the daemon must agree on one absolute path, and a
// relative one would resolve against whatever directory the daemon started
// in.
func (cfg *Config) loadLivenessConfig() error {
	raw := strings.TrimSpace(getEnv("SB_LIVENESS_SOCKET", DefaultLivenessSocket))
	if strings.EqualFold(raw, LivenessSocketOff) || raw == "" {
		cfg.LivenessSocket = ""
		return nil
	}
	if !filepath.IsAbs(raw) {
		return fmt.Errorf("SB_LIVENESS_SOCKET must be an absolute path or %q, got %q", LivenessSocketOff, raw)
	}
	cfg.LivenessSocket = raw
	return nil
}
