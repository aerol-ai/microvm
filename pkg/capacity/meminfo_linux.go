//go:build linux

package capacity

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procMeminfoProbe reads /proc/meminfo MemAvailable. Result is cached briefly
// so a burst of admission checks doesn't open and parse the file repeatedly.
type procMeminfoProbe struct {
	ttl time.Duration

	mu     sync.Mutex
	cached int
	at     time.Time
}

// NewProcMeminfoProbe returns a MemProbe backed by /proc/meminfo with a 500ms
// cache. The cache window is small enough that decisions remain responsive
// to actual host memory pressure but large enough to absorb a burst of
// concurrent CreateSandbox calls without 50 file reads.
func NewProcMeminfoProbe() MemProbe {
	return &procMeminfoProbe{ttl: 500 * time.Millisecond}
}

func (p *procMeminfoProbe) FreeMB() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.at.IsZero() && time.Since(p.at) < p.ttl {
		return p.cached, nil
	}
	free, err := readMemAvailableMB()
	if err != nil {
		return 0, err
	}
	p.cached = free
	p.at = time.Now()
	return free, nil
}

func readMemAvailableMB() (int, error) {
	return readMeminfoField("MemAvailable")
}

// totalMemoryMB is consumed by DetectHost in capacity.go.
func totalMemoryMB() (int, error) {
	return readMeminfoField("MemTotal")
}

func readMeminfoField(field string) (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prefix := field + ":"
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed meminfo line: %q", line)
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("parse meminfo value: %w", err)
		}
		return kb / 1024, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s not found in /proc/meminfo", field)
}
