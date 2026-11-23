// Package ownerlease is the ownership lease as a file, so it can be enforced
// where the sandboxes live (plans/kubernetes-v2-architecture.md C7, T3).
//
// In cluster mode a worker keeps a lease on the sandboxes it owns
// (internal/service/ownership_lease.go): without an authoritative read from
// the leader for a lease, it freezes every failover.policy=recreate sandbox,
// because the leader may hand them to another node. Only sandboxd enforced
// that. In a pod, sandboxd runs in the agent container and the sandboxes in
// the runtime container; with the agent down (a crash loop, an upgrade that
// cannot pull its image), its sandboxes kept running while the cluster
// recreated them elsewhere: two executors of one sandbox.
//
// So sandboxd writes the lease to a file on a folder both containers share,
// after every successful read, and the runtime supervisor freezes the
// listed sandboxes when the lease in that file runs out. The supervisor
// thaws one only when a later read proves this node still owns it; one that
// moved stays frozen until sandboxd removes it, as sandboxd's own fence
// leaves it.
package ownerlease

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Lease is the file's content.
type Lease struct {
	// ConfirmedUnixMs is when the last authoritative read that succeeded was
	// sent, in Unix milliseconds on sandboxd's clock. The lease runs from
	// then, as sandboxd's own does.
	ConfirmedUnixMs int64 `json:"confirmed_unix_ms"`
	// WrittenUnixMs is when the file was written, on the same clock, so a
	// reader turns the end into a duration (Remaining) and never compares
	// two clocks, or a clock that was stepped.
	WrittenUnixMs int64 `json:"written_unix_ms"`
	// LeaseMs is the lease's length (cluster.OwnershipLease).
	LeaseMs int64 `json:"lease_ms"`
	// Fence names the runtime instance of every local recreate-policy
	// sandbox: what is frozen when the lease runs out.
	Fence []string `json:"fence"`
	// Owned names the instances the read at ConfirmedUnixMs proved this node
	// still owns: the only ones a reader may thaw after a freeze.
	Owned []string `json:"owned"`
}

// Remaining is how much of the lease was left when the file was written.
func (l Lease) Remaining() time.Duration {
	return time.Duration(l.ConfirmedUnixMs+l.LeaseMs-l.WrittenUnixMs) * time.Millisecond
}

// ValidRef reports whether ref can name a sandbox's group under the
// sandboxes' cgroup parent: one path element (a container's group), or one
// element under a host-process runtime's group (a Firecracker VM's,
// "aerolvm-vmm/<sandbox>"), so a file that names "../supervisor" can never
// make the reader freeze anything else. A name ReservedGroup keeps for
// the machinery is never a sandbox's: "_runtime" would freeze containerd,
// every shim and the root helper.
func ValidRef(ref string) bool {
	group, child, nested := strings.Cut(ref, "/")
	if nested {
		return HostGroups[group] && sandboxElem(child)
	}
	// A host group itself holds every VM: naming it would freeze them all.
	return sandboxElem(ref) && !HostGroups[ref]
}

// HostGroups are the groups, directly under the sandboxes' cgroup parent,
// a host-process runtime keeps each sandbox's own group in. Firecracker
// starts each VM in aerolvm-vmm/<sandbox> (internal/runtime/firecracker).
var HostGroups = map[string]bool{"aerolvm-vmm": true}

// ReservedGroup reports whether name, one group directly under the
// sandboxes' cgroup parent, is one AerolVM keeps for its own processes
// rather than one sandbox's:
//
//   - a name starting with "_": the worker pod's supervisor puts
//     containerd, and so every shim and the root helper, in "_runtime"
//     (internal/supervisor);
//   - a name starting with "aerolvm-": the host-process runtimes' groups,
//     each holding many sandboxes or their helpers ("aerolvm-vmm",
//     "aerolvm-wasm", "aerolvm-isolate", "aerolvm-mounts").
//
// No sandbox, warm-pool slot or parked container takes either form
// ("sb-", "aerol-netns-", "park-"), so refusing them costs no real name,
// and a name that would put a sandbox, a freeze or an out-of-memory
// setting on the machinery is never taken for a sandbox's.
func ReservedGroup(name string) bool {
	return strings.HasPrefix(name, "_") || strings.HasPrefix(name, "aerolvm-")
}

func validElem(e string) bool {
	return e != "" && e != "." && e != ".." && !strings.ContainsAny(e, "/\x00")
}

// sandboxElem is one sandbox's group name: a single element that no
// machinery group takes.
func sandboxElem(e string) bool { return validElem(e) && !ReservedGroup(e) }

// Write replaces the file at path with l in one rename, so a reader sees
// the old lease or the new one, never part of one.
func Write(path string, l Lease) error {
	// Integers and strings: Marshal cannot fail.
	body, _ := json.Marshal(l)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(body)
	if err := errors.Join(werr, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// maxLeaseBytes bounds one read. A lease lists the sandboxes it fences and
// owns: a few hundred thousand IDs fit.
const maxLeaseBytes = 16 << 20

// Read returns the lease at path. A missing file is an error that
// errors.Is(err, os.ErrNotExist): no lease has been written.
//
// The reader is the runtime container's supervisor, root, and the file is
// sandboxd's, in a folder sandboxd can write. So Read follows no link at
// the file's name, takes only a regular file (a pipe would block it, a
// device would never end), and reads at most maxLeaseBytes.
func Read(path string) (Lease, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return Lease{}, err
	}
	defer f.Close()
	var body []byte
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("ownership lease %s: not a regular file (%s)", path, st.Mode().Type())
	}
	if err == nil {
		body, err = io.ReadAll(io.LimitReader(f, maxLeaseBytes+1))
	}
	if err == nil && len(body) > maxLeaseBytes {
		err = fmt.Errorf("ownership lease %s: over %d bytes", path, maxLeaseBytes)
	}
	if err != nil {
		return Lease{}, err
	}
	var l Lease
	if err := json.Unmarshal(body, &l); err != nil {
		return Lease{}, fmt.Errorf("ownership lease %s: %w", path, err)
	}
	if l.LeaseMs <= 0 || l.ConfirmedUnixMs <= 0 || l.WrittenUnixMs <= 0 {
		return Lease{}, errors.New("ownership lease " + path + ": missing times")
	}
	return l, nil
}
