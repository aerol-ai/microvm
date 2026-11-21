package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeKernel is a cgroup's files as the kernel serves them: cgroup.kill
// and a SIGKILL through a pidfd end a process at once, unless it is stuck.
type fakeKernel struct {
	procs        []int
	stuck        map[int]bool // a SIGKILL does not end it
	noKill       bool         // no cgroup.kill (Linux before 5.14)
	freeze       string       // cgroup.freeze; "" for a kernel with no freezer
	neverFreezes bool         // a freeze never takes hold
	events       string       // cgroup.events as read, when set
	errs         map[string]error
	mkdirErr     error
	rmdirErr     error
	onOpen       func(k *fakeKernel, pid int) // as a process is held
	onKill       func(k *fakeKernel, pid int) // as a process gets SIGKILL

	writes         []string
	killed         []int
	opened, closed int
}

func (k *fakeKernel) group() *helperCgroup {
	return &helperCgroup{
		dir: "/fake/_runtime/aerolvm-rootd", wait: 50 * time.Millisecond, poll: time.Millisecond, freezeWait: 5 * time.Millisecond,
		read: k.read, write: k.write, openPid: k.openPid,
		mkdir: func() error { return k.mkdirErr },
		rmdir: func() error { return k.rmdirErr },
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func enoent(name string) error {
	return &fs.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
}

func (k *fakeKernel) read(name string) ([]byte, error) {
	if err := k.errs["read "+name]; err != nil {
		return nil, err
	}
	switch name {
	case "cgroup.events":
		if k.events != "" {
			return []byte(k.events), nil
		}
		frozen := k.freeze == "1" && !k.neverFreezes
		return fmt.Appendf(nil, "populated %d\nfrozen %d\n", b2i(len(k.procs) > 0), b2i(frozen)), nil
	case "cgroup.procs":
		var b strings.Builder
		for _, p := range k.procs {
			fmt.Fprintf(&b, "%d\n", p)
		}
		return []byte(b.String()), nil
	case "cgroup.freeze":
		if k.freeze == "" {
			return nil, enoent(name)
		}
		return []byte(k.freeze + "\n"), nil
	}
	return nil, enoent(name)
}

func (k *fakeKernel) write(name, v string) error {
	k.writes = append(k.writes, name+"="+v)
	if err := k.errs["write "+name+"="+v]; err != nil {
		return err
	}
	switch name {
	case "cgroup.kill":
		if k.noKill {
			return enoent(name)
		}
		for _, p := range slices.Clone(k.procs) {
			k.end(p)
		}
	case "cgroup.freeze":
		k.freeze = v
	default:
		return enoent(name)
	}
	return nil
}

// end is a SIGKILL reaching pid.
func (k *fakeKernel) end(pid int) {
	if !k.stuck[pid] {
		k.procs = slices.DeleteFunc(k.procs, func(p int) bool { return p == pid })
	}
}

type fakePid struct {
	k   *fakeKernel
	pid int
}

func (p fakePid) Kill() error {
	p.k.killed = append(p.k.killed, p.pid)
	p.k.end(p.pid)
	if p.k.onKill != nil {
		p.k.onKill(p.k, p.pid)
	}
	return nil
}

func (p fakePid) Close() error { p.k.closed++; return nil }

func (k *fakeKernel) openPid(pid int) (pidHandle, error) {
	if err := k.errs["open "+strconv.Itoa(pid)]; err != nil {
		return nil, err
	}
	k.opened++
	if k.onOpen != nil {
		k.onOpen(k, pid)
	}
	return fakePid{k, pid}, nil
}

// TestHelperGroupEmpty: a group is empty once the kernel says so. On a
// kernel with cgroup.kill one write kills all; before 5.14 the group is
// frozen, each process held by pidfd and killed if still listed, and
// thawed, pass after pass. A group that will not empty, or a file that
// fails, is an error, and a group is never left frozen.
func TestHelperGroupEmpty(t *testing.T) {
	eacces := &fs.PathError{Op: "write", Path: "x", Err: syscall.EACCES}
	kill1, freeze1, freeze0 := "cgroup.kill=1", "cgroup.freeze=1", "cgroup.freeze=0"
	for _, tc := range []struct {
		name       string
		k          *fakeKernel
		want       string // in the error; "" for none
		wantWrites []string
		wantKilled []int
	}{
		{name: "already empty", k: &fakeKernel{freeze: "0"}},
		{name: "a kernel with no freezer", k: &fakeKernel{}},
		{name: "the group is there already", k: &fakeKernel{freeze: "0", mkdirErr: &fs.PathError{Op: "mkdir", Err: syscall.EEXIST}}},
		{name: "left frozen: thawed before anything starts in it", k: &fakeKernel{freeze: "1"}, wantWrites: []string{freeze0}},
		{name: "cgroup.kill", k: &fakeKernel{freeze: "0", procs: []int{10, 11}}, wantWrites: []string{kill1}},
		{
			name:       "no cgroup.kill: freeze, kill each, thaw",
			k:          &fakeKernel{freeze: "0", procs: []int{10, 11}, noKill: true},
			wantWrites: []string{kill1, freeze1, freeze0}, wantKilled: []int{10, 11},
		},
		{
			// 11 exited and was reaped while it was being held: its pid
			// may be anyone's now, so it gets no signal.
			name: "a pid that left the list as it was held gets no signal",
			k: &fakeKernel{freeze: "0", procs: []int{10, 11}, noKill: true, onOpen: func(k *fakeKernel, pid int) {
				if pid == 11 {
					k.procs = slices.DeleteFunc(k.procs, func(p int) bool { return p == 11 })
				}
			}},
			wantWrites: []string{kill1, freeze1, freeze0}, wantKilled: []int{10},
		},
		{
			name: "a pid that cannot be held is passed over",
			k: &fakeKernel{freeze: "0", procs: []int{10, 11}, noKill: true, errs: map[string]error{"open 11": syscall.ESRCH}, onKill: func(k *fakeKernel, _ int) {
				k.procs = slices.DeleteFunc(k.procs, func(p int) bool { return p == 11 }) // it had exited
			}},
			wantWrites: []string{kill1, freeze1, freeze0}, wantKilled: []int{10},
		},
		{
			name: "a fork before the freeze took hold dies on the next pass",
			k: &fakeKernel{freeze: "0", procs: []int{10}, noKill: true, onKill: func(k *fakeKernel, pid int) {
				if pid == 10 {
					k.procs = append(k.procs, 20)
				}
			}},
			wantWrites: []string{kill1, freeze1, freeze0, freeze1, freeze0}, wantKilled: []int{10, 20},
		},
		{
			name:       "a freeze that never takes hold: killed anyway",
			k:          &fakeKernel{freeze: "0", procs: []int{10}, noKill: true, neverFreezes: true},
			wantWrites: []string{kill1, freeze1, freeze0}, wantKilled: []int{10},
		},
		{name: "a process that will not die", k: &fakeKernel{freeze: "0", procs: []int{10, 12}, stuck: map[int]bool{12: true}}, want: "still holds processes [12] after 50ms"},
		{name: "one that will not die, killed by hand", k: &fakeKernel{freeze: "0", procs: []int{12}, stuck: map[int]bool{12: true}, noKill: true}, want: "still holds processes [12]"},
		{name: "the group cannot be made", k: &fakeKernel{mkdirErr: eacces}, want: "make the root helper's cgroup"},
		{name: "cgroup.freeze cannot be read", k: &fakeKernel{freeze: "0", errs: map[string]error{"read cgroup.freeze": syscall.EIO}}, want: "read the root helper's cgroup"},
		{name: "a frozen group cannot be thawed", k: &fakeKernel{freeze: "1", errs: map[string]error{"write " + freeze0: eacces}}, want: "thaw the root helper's cgroup"},
		{name: "cgroup.events cannot be read", k: &fakeKernel{freeze: "0", errs: map[string]error{"read cgroup.events": syscall.EIO}}, want: "read the root helper's cgroup"},
		{name: "cgroup.events says nothing of populated", k: &fakeKernel{freeze: "0", events: "frozen 0\n"}, want: `cgroup.events has no "populated"`},
		{name: "cgroup.kill refused", k: &fakeKernel{freeze: "0", procs: []int{10}, errs: map[string]error{"write " + kill1: eacces}}, want: "kill the root helper's cgroup"},
		{name: "the group cannot be frozen", k: &fakeKernel{freeze: "0", procs: []int{10}, noKill: true, errs: map[string]error{"write " + freeze1: eacces}}, want: "freeze the root helper's cgroup"},
		{name: "the group cannot be thawed after the kills", k: &fakeKernel{freeze: "0", procs: []int{10}, noKill: true, errs: map[string]error{"write " + freeze0: eacces}}, want: "thaw the root helper's cgroup"},
		{name: "cgroup.procs cannot be read", k: &fakeKernel{freeze: "0", procs: []int{10}, noKill: true, errs: map[string]error{"read cgroup.procs": syscall.EIO}}, want: "list the root helper's cgroup"},
		{
			name: "cgroup.procs fails on the second read",
			k: &fakeKernel{freeze: "0", procs: []int{10}, noKill: true, onOpen: func(k *fakeKernel, _ int) {
				k.errs = map[string]error{"read cgroup.procs": syscall.EIO}
			}},
			want: "list the root helper's cgroup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := tc.k
			err := k.group().Empty()
			if tc.want == "" && err != nil {
				t.Fatalf("Empty = %v", err)
			}
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Empty = %v, want %q", err, tc.want)
				}
			} else if len(k.procs) != 0 {
				t.Fatalf("left %v in the group", k.procs)
			}
			// A failure's writes and kills depend on how often it tried.
			if (tc.want == "" || tc.wantWrites != nil) && !slices.Equal(k.writes, tc.wantWrites) {
				t.Fatalf("writes %v, want %v", k.writes, tc.wantWrites)
			}
			if (tc.want == "" || tc.wantKilled != nil) && !slices.Equal(k.killed, tc.wantKilled) {
				t.Fatalf("killed %v, want %v", k.killed, tc.wantKilled)
			}
			if k.freeze == "1" && !slices.Contains([]string{"a frozen group cannot be thawed", "the group cannot be thawed after the kills"}, tc.name) {
				t.Fatal("the group was left frozen")
			}
			if k.opened != k.closed {
				t.Fatalf("held %d processes, let go of %d", k.opened, k.closed)
			}
		})
	}
}

// TestHelperGroupRemembersNoKillFile: once cgroup.kill is found missing,
// later kills go straight to the freezer.
func TestHelperGroupRemembersNoKillFile(t *testing.T) {
	k := &fakeKernel{freeze: "0", procs: []int{10}, noKill: true}
	g := k.group()
	if err := g.Empty(); err != nil {
		t.Fatal(err)
	}
	k.procs = []int{11}
	if err := g.Empty(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(k.writes, " "), "cgroup.kill"); n != 1 {
		t.Fatalf("cgroup.kill tried %d times, want once: %v", n, k.writes)
	}
	if !slices.Equal(k.killed, []int{10, 11}) {
		t.Fatalf("killed %v", k.killed)
	}
}

func TestHelperGroupRemove(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{&fs.PathError{Op: "remove", Err: syscall.ENOENT}, ""},
		{&fs.PathError{Op: "remove", Err: syscall.EBUSY}, "remove the root helper's cgroup"},
	} {
		err := (&fakeKernel{rmdirErr: tc.err}).group().Remove()
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("Remove with %v = %v, want %q", tc.err, err, tc.want)
		}
	}
}

// TestNewHelperGroupOnFiles runs the kernel's HelperGroup on plain files:
// it makes the folder, reads cgroup.events, writes only files that are
// there (a cgroup mount makes none), and removes the folder.
func TestNewHelperGroupOnFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "aerolvm-rootd")
	g := NewHelperGroup(dir)
	put := func(name, v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Empty(); err == nil || !strings.Contains(err.Error(), "read the root helper's cgroup") {
		t.Fatalf("Empty with no cgroup.events = %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("the group was not made: %v", err)
	}
	put("cgroup.events", "populated 0\nfrozen 0\n")
	put("cgroup.freeze", "1\n")
	if err := g.Empty(); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(dir, "cgroup.freeze")) != "0" {
		t.Fatal("a group left frozen was not thawed")
	}

	// Populated, and the kill changes nothing on a plain file: it times out.
	put("cgroup.events", "populated 1\nfrozen 0\n")
	put("cgroup.kill", "")
	put("cgroup.procs", "77\n")
	g.(*helperCgroup).wait = 20 * time.Millisecond
	if err := g.Empty(); err == nil || !strings.Contains(err.Error(), "still holds processes [77]") {
		t.Fatalf("Empty = %v", err)
	}
	if read(t, filepath.Join(dir, "cgroup.kill")) != "1" {
		t.Fatal("cgroup.kill was not written")
	}
	if err := g.Remove(); err == nil {
		t.Fatal("removed a folder that holds files")
	}
	for _, n := range []string{"cgroup.events", "cgroup.freeze", "cgroup.kill", "cgroup.procs"} {
		_ = os.Remove(filepath.Join(dir, n))
	}
	if err := g.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := g.Remove(); err != nil {
		t.Fatalf("Remove of a group already gone = %v", err)
	}
	if err := writeCgroupFile(filepath.Join(dir, "cgroup.kill"), "1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a write to a missing file = %v, want ENOENT (never made)", err)
	}
	if err := writeCgroupFile(t.TempDir(), "1"); err == nil {
		t.Fatal("wrote to a folder")
	}
}

// TestHelperStopsOnlyWithItsGroup: a helper leaves a process that outlives
// it (a CNI plugin's IPAM plugin) and then exits, by crash, by drain, by
// the kill after KillAfter, or before it served; the next helper starts
// only once that process is gone. The rig fails the test on a start while
// any leftover runs, and on an Empty while a helper runs.
func TestHelperStopsOnlyWithItsGroup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		swap   bool // stage v2 once v1 serves
		behave func(n int, c *fakeChild)
	}{
		{"a crash", false, func(n int, c *fakeChild) {
			c.serve()
			if n == 0 {
				c.leave()
				time.Sleep(10 * time.Millisecond)
				c.exit()
			}
		}},
		{"a drain on a swap", true, func(n int, c *fakeChild) {
			c.serve()
			if n == 0 {
				c.leave()
			}
		}},
		{"the kill after KillAfter on a swap", true, func(n int, c *fakeChild) {
			if n == 0 {
				c.exitOn = []syscall.Signal{syscall.SIGKILL}
				c.leave()
			}
			c.serve()
		}},
		{"a new helper that dies before it serves", true, func(n int, c *fakeChild) {
			if n == 1 {
				c.leave()
				c.exit()
				return
			}
			c.serve()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newKeeperRig(t, func(k *HelperKeeper) { k.ReadyWait = 200 * time.Millisecond })
			r.behave = tc.behave
			r.rel.stage([]byte("helper v1"), "v1.0.0")
			r.run()
			r.waitStarts(1)
			if tc.swap {
				eventually(t, "v1 serving", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
				r.rel.stage([]byte("helper v2"), "v1.0.1")
			}
			want := 2
			if tc.name == "a new helper that dies before it serves" {
				want = 3 // v2, then v1 again
			}
			all := r.waitStarts(want)
			r.stop()
			for _, c := range all {
				if c.leftover() {
					t.Fatalf("%s's leftover outlived the keeper", c.bin)
				}
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.empties < want+1 || r.removes != 1 {
				t.Fatalf("group emptied %d times and removed %d, want before each of %d starts and at the stop, then removed", r.empties, r.removes, want)
			}
		})
	}
}

// TestHelperWaitsForItsGroupToEmpty: a group that will not empty is an
// error, logged on every try, and no helper starts until it is empty: not
// the crashed one again, and not a newer one staged meanwhile, which then
// starts as itself, not as a failed swap.
func TestHelperWaitsForItsGroupToEmpty(t *testing.T) {
	t.Run("after a crash", func(t *testing.T) {
		r := newKeeperRig(t, nil)
		r.emptyErr = func(n int) error {
			if n == 1 || n == 2 { // the two tries after the crash
				return errors.New("still holds processes [77]")
			}
			return nil
		}
		r.behave = func(n int, c *fakeChild) {
			c.serve()
			if n == 0 {
				c.leave()
				c.exit()
			}
		}
		r.rel.stage([]byte("helper v1"), "v1.0.0")
		r.run()
		all := r.waitStarts(2)
		if all[1].bin != all[0].bin {
			t.Fatalf("restart ran %s", all[1].bin)
		}
		logs := r.logs.String()
		if n := strings.Count(logs, "still holds what the last helper started"); n != 2 || !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "[77]") {
			t.Fatalf("want two error lines, got:\n%s", logs)
		}
	})
	t.Run("a swap", func(t *testing.T) {
		r := newKeeperRig(t, nil)
		r.emptyErr = func(n int) error {
			if n >= 1 && n <= 3 {
				return errors.New("still holds processes [77]")
			}
			return nil
		}
		r.behave = func(n int, c *fakeChild) {
			c.serve()
			if n == 0 {
				c.leave()
			}
		}
		r.rel.stage([]byte("helper v1"), "v1.0.0")
		r.run()
		r.waitStarts(1)
		eventually(t, "v1 serving", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
		r.rel.stage([]byte("helper v2"), "v1.0.1")
		second := r.waitStarts(2)[1]
		if !strings.Contains(second.bin, "v1.0.1") {
			t.Fatalf("after the group emptied ran %s, want v2", second.bin)
		}
		eventually(t, "v2 serving", func() bool { return strings.Count(r.logs.String(), "the root helper serves") == 2 })
		logs := r.logs.String()
		if strings.Count(logs, "still holds what the last helper started") != 3 || strings.Contains(logs, "did not start") {
			t.Fatalf("logs:\n%s", logs)
		}
	})
	t.Run("the supervisor stops meanwhile", func(t *testing.T) {
		r := newKeeperRig(t, func(k *HelperKeeper) { k.MinBackoff, k.MaxBackoff = time.Hour, time.Hour })
		r.emptyErr = func(n int) error {
			if n >= 1 {
				return errors.New("still holds processes [77]")
			}
			return nil
		}
		r.behave = func(n int, c *fakeChild) {
			c.serve()
			c.leave()
			c.exit()
		}
		r.rel.stage([]byte("helper v1"), "v1.0.0")
		r.run()
		r.waitStarts(1)
		eventually(t, "the first failed try", func() bool { return strings.Contains(r.logs.String(), "still holds what") })
		start := time.Now()
		r.stop() // fails the test if Run does not return
		if time.Since(start) > 5*time.Second {
			t.Fatal("the keeper waited out its backoff before it stopped")
		}
		if n := len(r.starts()); n != 1 {
			t.Fatalf("%d starts beside what the first helper left", n)
		}
		logs := r.logs.String()
		if !strings.Contains(logs, "could not empty the root helper's cgroup as it stops") || strings.Contains(logs, "could not start the root helper") {
			t.Fatalf("logs:\n%s", logs)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.removes != 0 {
			t.Fatal("removed a group that still holds processes")
		}
	})
}

// TestHelperStopsMidSwapBesideLeftovers: the supervisor stops while a swap
// waits for the old helper's group to empty. The new helper never starts,
// and a start cut short by the stop is not logged as a failed start.
func TestHelperStopsMidSwapBesideLeftovers(t *testing.T) {
	r := newKeeperRig(t, func(k *HelperKeeper) { k.MinBackoff, k.MaxBackoff = time.Hour, time.Hour })
	r.emptyErr = func(n int) error {
		if n >= 1 {
			return errors.New("still holds processes [77]")
		}
		return nil
	}
	r.behave = func(_ int, c *fakeChild) { c.serve(); c.leave() }
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	r.run()
	r.waitStarts(1)
	eventually(t, "v1 serving", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
	r.rel.stage([]byte("helper v2"), "v1.0.1")
	eventually(t, "the swap waiting on the group", func() bool { return strings.Contains(r.logs.String(), "still holds what") })
	r.stop()
	if n := len(r.starts()); n != 1 {
		t.Fatalf("%d starts beside what v1 left", n)
	}
	if logs := r.logs.String(); strings.Contains(logs, "could not start the root helper") || strings.Contains(logs, "did not start") {
		t.Fatalf("a start cut by the stop was logged as a failure:\n%s", logs)
	}
}

// TestHelperGroupAtStop: the supervisor stopping empties the group once
// the helper has exited, and removes it; a group that cannot be removed
// is logged.
func TestHelperGroupAtStop(t *testing.T) {
	r := newKeeperRig(t, nil)
	r.removeErr = errors.New("EBUSY")
	r.behave = func(_ int, c *fakeChild) { c.serve(); c.leave() }
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	r.run()
	c := r.waitStarts(1)[0]
	eventually(t, "v1 serving", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
	r.stop()
	if c.leftover() {
		t.Fatal("what the helper started outlived the supervisor")
	}
	if !strings.Contains(r.logs.String(), "could not remove the root helper's cgroup") {
		t.Fatalf("logs:\n%s", r.logs.String())
	}
}

// A keeper with no group (tests that have none) neither waits nor removes.
func TestHelperKeeperWithNoGroup(t *testing.T) {
	h := &HelperKeeper{Log: quiet()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !h.clear(ctx) {
		t.Fatal("no group, yet clear waited")
	}
	h.closeGroup()
}
