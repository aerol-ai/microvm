package tap

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// recordingRun is the test seam Host.run takes. Records every invocation
// and lets each test inject a per-invocation response. Indexed by call
// order rather than (cmd,args) so a test that expects "tuntap add fails
// with already-exists then continues" can be expressed linearly.
type recordingRun struct {
	mu    sync.Mutex
	calls []runRecord
	plan  []runReply // popped in order
}

type runRecord struct {
	name string
	args []string
}

type runReply struct {
	out []byte
	err error
}

func (r *recordingRun) fn(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := append([]string(nil), args...)
	r.calls = append(r.calls, runRecord{name: name, args: cp})
	if len(r.plan) == 0 {
		return nil, nil
	}
	reply := r.plan[0]
	r.plan = r.plan[1:]
	return reply.out, reply.err
}

func newHostWithRun(r *recordingRun) *Host {
	return &Host{IPCmd: "/test/ip", run: r.fn}
}

// TestEnsure_HappyPath confirms the three-step sequence (tuntap add,
// addr add, link set up) runs in order with the expected argv. The test
// pins the argv shape because operators reading log lines rely on it;
// reordering or changing the words breaks runbook copy-paste.
func TestEnsure_HappyPath(t *testing.T) {
	r := &recordingRun{}
	h := newHostWithRun(r)

	slot := Slot{
		TapName:  "fctap-1",
		CIDR:     "172.16.0.0/30",
		HostIP:   "172.16.0.1",
		GuestIP:  "172.16.0.2",
		VsockCID: 3,
	}
	if err := h.Ensure(context.Background(), slot); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(r.calls) != 3 {
		t.Fatalf("expected 3 ip calls, got %d (%+v)", len(r.calls), r.calls)
	}
	want := [][]string{
		{"tuntap", "add", "fctap-1", "mode", "tap"},
		{"addr", "add", "172.16.0.1/30", "dev", "fctap-1"},
		{"link", "set", "fctap-1", "up"},
	}
	for i, w := range want {
		if !equalStrings(r.calls[i].args, w) {
			t.Errorf("call %d argv mismatch: got %v want %v", i, r.calls[i].args, w)
		}
	}
}

// TestEnsure_IdempotentOnAlreadyExists confirms that an "ip tuntap add"
// failure with the "File exists" diagnostic is treated as success — the
// daemon-restart-mid-create path depends on this so the slot's already-
// realized device doesn't trip us up.
func TestEnsure_IdempotentOnAlreadyExists(t *testing.T) {
	r := &recordingRun{
		plan: []runReply{
			// tuntap add: device already there.
			{out: []byte("RTNETLINK answers: File exists\n"), err: errors.New("exit 2")},
			// addr add: idempotent.
			{out: []byte("RTNETLINK answers: File exists\n"), err: errors.New("exit 2")},
			// link set up: clean.
			{},
		},
	}
	h := newHostWithRun(r)
	slot := Slot{TapName: "fctap-2", CIDR: "172.16.0.4/30", HostIP: "172.16.0.5"}
	if err := h.Ensure(context.Background(), slot); err != nil {
		t.Errorf("Ensure should be idempotent on 'File exists'; got %v", err)
	}
	if len(r.calls) != 3 {
		t.Errorf("expected 3 calls (idempotent steps still ran), got %d", len(r.calls))
	}
}

// TestEnsure_AddrAddFailureBubbles confirms a non-idempotent addr-add
// failure surfaces verbatim — operator needs the `ip` output to diagnose
// (most commonly: missing CAP_NET_ADMIN on the daemon).
func TestEnsure_AddrAddFailureBubbles(t *testing.T) {
	r := &recordingRun{
		plan: []runReply{
			{}, // tuntap add ok
			{out: []byte("RTNETLINK answers: Operation not permitted"), err: errors.New("exit 1")},
		},
	}
	h := newHostWithRun(r)
	slot := Slot{TapName: "fctap-3", CIDR: "172.16.0.8/30", HostIP: "172.16.0.9"}
	err := h.Ensure(context.Background(), slot)
	if err == nil {
		t.Fatal("expected addr-add failure to bubble")
	}
	// Two calls — link set up should NOT have run (we failed before then).
	if len(r.calls) != 2 {
		t.Errorf("expected 2 calls (no link-up after failure), got %d", len(r.calls))
	}
	// The verbatim stderr substring is the operator-actionable bit.
	if !contains(err.Error(), "Operation not permitted") {
		t.Errorf("error should include ip stderr; got %v", err)
	}
}

// TestEnsure_ValidatesSlot rejects empty TapName / HostIP / CIDR before
// any exec. Cheaper than waiting for `ip` to complain, and these are
// programmer errors anyway (a malformed Slot from the pool).
func TestEnsure_ValidatesSlot(t *testing.T) {
	r := &recordingRun{}
	h := newHostWithRun(r)
	cases := []Slot{
		{},
		{TapName: "fctap-4"},
		{TapName: "fctap-4", HostIP: "172.16.0.1"},
	}
	for i, slot := range cases {
		if err := h.Ensure(context.Background(), slot); err == nil {
			t.Errorf("case %d: expected validation error for slot=%+v", i, slot)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("validation should not exec anything; calls=%d", len(r.calls))
	}
}

func TestHostHelpers(t *testing.T) {
	t.Run("new_host_and_ip_binary", func(t *testing.T) {
		h := NewHost("")
		if h == nil {
			t.Fatal("NewHost returned nil")
		}
		if got := h.ipBinary(); got != "ip" {
			t.Fatalf("ipBinary() = %q, want ip", got)
		}
		h = NewHost("/usr/sbin/ip")
		if got := h.ipBinary(); got != "/usr/sbin/ip" {
			t.Fatalf("ipBinary() = %q, want /usr/sbin/ip", got)
		}
	})

	t.Run("exec_uses_run_seam", func(t *testing.T) {
		r := &recordingRun{plan: []runReply{{out: []byte("ok")}}}
		h := newHostWithRun(r)
		out, err := h.exec(context.Background(), "link", "show", "fctap-x")
		if err != nil {
			t.Fatalf("exec() error = %v", err)
		}
		if string(out) != "ok" {
			t.Fatalf("exec() output = %q, want ok", string(out))
		}
		if len(r.calls) != 1 || r.calls[0].name != "/test/ip" {
			t.Fatalf("calls = %+v, want one /test/ip invocation", r.calls)
		}
	})
}

// TestRemove_HappyPath confirms `ip link delete` is issued with the
// right argv.
func TestRemove_HappyPath(t *testing.T) {
	r := &recordingRun{}
	h := newHostWithRun(r)
	if err := h.Remove(context.Background(), "fctap-5"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(r.calls))
	}
	if !equalStrings(r.calls[0].args, []string{"link", "delete", "fctap-5"}) {
		t.Errorf("argv mismatch: %v", r.calls[0].args)
	}
}

func TestEnsureAndRemoveAdditionalFailures(t *testing.T) {
	t.Run("link_set_failure_bubbles", func(t *testing.T) {
		r := &recordingRun{
			plan: []runReply{
				{},
				{},
				{out: []byte("permission denied"), err: errors.New("exit 1")},
			},
		}
		h := newHostWithRun(r)
		slot := Slot{TapName: "fctap-8", CIDR: "172.16.0.12/30", HostIP: "172.16.0.13"}
		err := h.Ensure(context.Background(), slot)
		if err == nil || !contains(err.Error(), "permission denied") {
			t.Fatalf("Ensure() err = %v, want permission denied", err)
		}
		if len(r.calls) != 3 {
			t.Fatalf("calls = %d, want 3", len(r.calls))
		}
	})

	t.Run("remove_rejects_empty_name", func(t *testing.T) {
		h := newHostWithRun(&recordingRun{})
		if err := h.Remove(context.Background(), ""); err == nil {
			t.Fatal("Remove(empty) err = nil, want error")
		}
	})
}

func TestExistsAndMissingMatchers(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func([]byte) bool
		in   string
		want bool
	}{
		{name: "exists_busy", fn: looksLikeExists, in: "Device or resource busy", want: true},
		{name: "exists_already", fn: looksLikeExists, in: "already exists", want: true},
		{name: "exists_false", fn: looksLikeExists, in: "permission denied", want: false},
		{name: "missing_no_such_device", fn: looksLikeMissing, in: "No such device", want: true},
		{name: "missing_does_not_exist", fn: looksLikeMissing, in: "does not exist", want: true},
		{name: "missing_false", fn: looksLikeMissing, in: "resource busy", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn([]byte(tc.in)); got != tc.want {
				t.Fatalf("matcher(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestRemove_IdempotentOnMissing confirms a "Cannot find device" error
// from `ip link delete` is treated as success — Destroy after a previous
// Remove (or after a host restart that already cleaned the device) must
// not surface a spurious error.
func TestRemove_IdempotentOnMissing(t *testing.T) {
	r := &recordingRun{
		plan: []runReply{
			{out: []byte("Cannot find device \"fctap-6\""), err: errors.New("exit 1")},
		},
	}
	h := newHostWithRun(r)
	if err := h.Remove(context.Background(), "fctap-6"); err != nil {
		t.Errorf("Remove should be idempotent on missing device; got %v", err)
	}
}

// TestRemove_OtherFailureBubbles confirms a non-missing failure (e.g.
// device busy because a child namespace still references it) is
// surfaced — that's a real problem the operator must see.
func TestRemove_OtherFailureBubbles(t *testing.T) {
	r := &recordingRun{
		plan: []runReply{
			{out: []byte("RTNETLINK answers: Device or resource busy"), err: errors.New("exit 1")},
		},
	}
	h := newHostWithRun(r)
	if err := h.Remove(context.Background(), "fctap-7"); err == nil {
		t.Errorf("expected Remove to surface non-missing failure")
	}
}

// TestHostAddrCIDR pins the IP+mask synthesis. The kernel rejects
// addresses with the wrong mask shape; this is the math step we cannot
// afford to get wrong.
func TestHostAddrCIDR(t *testing.T) {
	cases := []struct {
		hostIP string
		cidr   string
		want   string
		ok     bool
	}{
		{"172.16.0.1", "172.16.0.0/30", "172.16.0.1/30", true},
		{"10.0.0.5", "10.0.0.4/30", "10.0.0.5/30", true},
		{"172.16.0.1", "no-slash", "", false},
	}
	for _, c := range cases {
		got, err := hostAddrCIDR(c.hostIP, c.cidr)
		if c.ok && err != nil {
			t.Errorf("hostAddrCIDR(%q,%q): unexpected error %v", c.hostIP, c.cidr, err)
		}
		if !c.ok && err == nil {
			t.Errorf("hostAddrCIDR(%q,%q): expected error", c.hostIP, c.cidr)
		}
		if got != c.want {
			t.Errorf("hostAddrCIDR(%q,%q) = %q want %q", c.hostIP, c.cidr, got, c.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		(len(haystack) > len(needle) && (indexOf(haystack, needle) >= 0)))
}

func indexOf(haystack, needle string) int {
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
