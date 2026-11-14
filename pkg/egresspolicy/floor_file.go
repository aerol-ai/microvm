package egresspolicy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// The floor file (review R4). DenyFloorEnv is read once, at start, so on
// Kubernetes a worker made before the API server's addresses changed would
// never refuse the new ones: its pod's environment cannot change. The
// operator keeps the API server's current addresses in a ConfigMap instead,
// mounted into each worker pod; the kubelet refreshes the file in place, and
// every process that guards sandbox traffic (sandboxd, its WASM workers and
// the egress gateway) watches it and adds what it holds to the extra floor.
// The dial guards read the extra floor at each dial (CheckFloor); a
// process's kernel copies of the floor are rewritten by its onChange.

// FloorFileEnv names the floor file. Its addresses are written as in
// DenyFloorEnv, separated by commas or new lines.
const FloorFileEnv = "SB_EGRESS_DENY_FLOOR_FILE"

// fileFloor is the floor file's part of the extra floor.
var fileFloor atomic.Pointer[[]netip.Prefix]

// ReadFloorFile reads and checks the floor file at path, as ParseRanges
// checks DenyFloorEnv.
func ReadFloorFile(path string) ([]netip.Prefix, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FloorFileEnv, err)
	}
	return ParseRanges(FloorFileEnv+" "+path, strings.ReplaceAll(string(raw), "\n", ","))
}

// SetFileFloor installs the floor file's addresses.
func SetFileFloor(ps []netip.Prefix) {
	f := slices.Clone(ps)
	fileFloor.Store(&f)
}

// FileFloor returns the floor file's addresses in force.
func FileFloor() []netip.Prefix { return loadPrefixes(&fileFloor) }

// WatchFloorFile reads path every interval until ctx ends and installs
// what it holds when it changed, then calls onChange (nil: nothing more to
// do). A file that cannot be read, or holds an address that does not
// parse, keeps the addresses in force: an operator that could not read the
// API server's addresses leaves its last good ones in place too, so
// nothing is ever taken off the floor by a failure. log may be nil.
func WatchFloorFile(ctx context.Context, path string, interval time.Duration, log *slog.Logger, onChange func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	lastErr := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		got, err := ReadFloorFile(path)
		if err != nil {
			if msg := err.Error(); msg != lastErr && log != nil {
				log.Warn("egress deny-floor file unreadable; keeping the addresses in force", "path", path, "error", msg)
			}
			lastErr = err.Error()
			continue
		}
		lastErr = ""
		if slices.Equal(got, FileFloor()) {
			continue
		}
		SetFileFloor(got)
		if log != nil {
			log.Info("egress deny floor changed", "path", path, "addresses", FormatRanges(got))
		}
		if onChange != nil {
			onChange()
		}
	}
}
