//go:build linux

package firecracker

// rss_sampler_linux.go is the platform-specific half of the warm-VMM
// RSS sampler. Holds the /proc/<pid>/statm reader so the cross-platform
// rss_sampler.go can stay free of build tags.
//
// Format of /proc/<pid>/statm (from proc(5)):
//
//   size  resident  shared  text  lib  data  dt
//
// All seven fields are page counts. We only care about the second
// (resident) — that's the kernel's accounting of pages currently in
// physical memory for the process, which is exactly the "real RSS" the
// admission watermark in PR 5-B needs.
//
// Why statm and not status: status is ~50 lines of human-readable text
// and parsing it costs ~30x more CPU per sample. The plan
// (plans/snapshot-clone-fast-boot.md §Phase 5) calls statm out
// explicitly — "cheap; /proc/<pid>/statm is fine at ~1Hz" — so we
// match. At 1Hz × ~100 VMMs per host the sampler is a rounding error
// next to firecracker spawn cost.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readRSSPagesForPID opens /proc/<pid>/statm and returns the resident
// pages count. Returns an error when the process is gone (ENOENT) or
// the file is malformed — the sampler tolerates both by recording 0
// for that pid; one dead VMM doesn't poison the aggregate.
func readRSSPagesForPID(pid int) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}
	return parseStatm(b)
}

// parseStatm extracts the resident pages field (second whitespace-
// separated token) from a statm line. Pulled out so tests can feed
// canned input without touching /proc.
func parseStatm(b []byte) (int64, error) {
	line := strings.TrimSpace(string(b))
	if line == "" {
		return 0, errors.New("statm: empty")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("statm: need >=2 fields, got %d (%q)", len(fields), line)
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("statm: parse resident field: %w", err)
	}
	if pages < 0 {
		return 0, fmt.Errorf("statm: negative resident pages (%d)", pages)
	}
	return pages, nil
}
