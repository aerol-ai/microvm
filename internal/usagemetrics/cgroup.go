package usagemetrics

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultCgroupRoot is where cgroup v2 is mounted on a worker. Tests pass
// a temporary folder with fake files instead.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// ReadCgroup reads a sandbox's measured use from its cgroup v2 group, a
// path below root such as "/aerolvm/<id>".
//
// Why cgroup files: they work the same for every runtime that gives each
// sandbox its own group. runc puts the sandbox's processes there, and
// gVisor puts its sandbox kernel there, so one reader covers both. The
// Docker stats API, which the older live sampler uses, knows only Docker.
//
// CPU is usage_usec from cpu.stat. Memory is memory.current less the
// inactive file cache from memory.stat: the working set, as docker stats
// and the kubelet report it, so cache the kernel can drop is not counted.
func ReadCgroup(root, group string) (Consumed, error) {
	dir := filepath.Join(root, filepath.FromSlash(path.Clean("/"+group)))
	usec, err := readKey(filepath.Join(dir, "cpu.stat"), "usage_usec")
	if err != nil {
		return Consumed{}, err
	}
	current, err := readUint(filepath.Join(dir, "memory.current"))
	if err != nil {
		return Consumed{}, err
	}
	inactive, err := readKey(filepath.Join(dir, "memory.stat"), "inactive_file")
	if err != nil && !errors.Is(err, errNoKey) && !errors.Is(err, fs.ErrNotExist) {
		return Consumed{}, err
	}
	mem := current
	if inactive <= mem {
		mem -= inactive
	}
	return Consumed{CPUSeconds: float64(usec) / 1e6, MemoryBytes: mem}, nil
}

var errNoKey = errors.New("key not found")

// readKey reads the value of key from a flat-keyed cgroup file ("key
// value" per line).
func readKey(file, key string) (uint64, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if !ok || k != key {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: bad %s %q", file, key, v)
		}
		return n, nil
	}
	return 0, fmt.Errorf("%s: %s: %w", file, key, errNoKey)
}

func readUint(file string) (uint64, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: bad value %q", file, s)
	}
	return n, nil
}
