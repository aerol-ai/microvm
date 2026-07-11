package netrules

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

func TestManagerDisabledAndNilGuards(t *testing.T) {
	var nilMgr *Manager
	if nilMgr.Enabled() {
		t.Fatal("nil manager reported enabled")
	}
	if err := nilMgr.BlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("nil BlockAllEgress err = %v", err)
	}
	if err := nilMgr.ClearBlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("nil ClearBlockAllEgress err = %v", err)
	}
	if err := nilMgr.BlockAllIngress("10.0.0.2"); err != nil {
		t.Fatalf("nil BlockAllIngress err = %v", err)
	}
	if err := nilMgr.ClearBlockAllIngress("10.0.0.2"); err != nil {
		t.Fatalf("nil ClearBlockAllIngress err = %v", err)
	}

	disabled := &Manager{enabled: false}
	if disabled.Enabled() {
		t.Fatal("disabled manager reported enabled")
	}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{name: "block_egress", run: func() error { return disabled.BlockAllEgress("10.0.0.2") }},
		{name: "clear_egress", run: func() error { return disabled.ClearBlockAllEgress("10.0.0.2") }},
		{name: "block_ingress", run: func() error { return disabled.BlockAllIngress("10.0.0.2") }},
		{name: "clear_ingress", run: func() error { return disabled.ClearBlockAllIngress("10.0.0.2") }},
		{name: "empty_ip_block_egress", run: func() error { return disabled.BlockAllEgress("") }},
		{name: "empty_ip_clear_egress", run: func() error { return disabled.ClearBlockAllEgress("") }},
		{name: "empty_ip_block_ingress", run: func() error { return disabled.BlockAllIngress("") }},
		{name: "empty_ip_clear_ingress", run: func() error { return disabled.ClearBlockAllIngress("") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != nil {
				t.Fatalf("%s err = %v", tc.name, err)
			}
		})
	}
}

func TestNew_DisabledReturnsDisabledManager(t *testing.T) {
	m, err := New(false)
	if err != nil {
		t.Fatalf("New(false) err = %v", err)
	}
	if m == nil || m.Enabled() {
		t.Fatalf("New(false) = %+v, want non-nil disabled manager", m)
	}
}

func TestNew_EnabledOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this test covers the non-Linux branch only")
	}
	m, err := New(true)
	if err != nil {
		t.Fatalf("New(true) on non-Linux err = %v", err)
	}
	if m == nil || m.Enabled() {
		t.Fatalf("New(true) on non-Linux = %+v, want non-nil disabled manager", m)
	}
}

func TestManagerEnabledPaths(t *testing.T) {
	script, state := writeFakeIPTables(t)
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New() error = %v", err)
	}
	mgr := &Manager{enabled: true, ipt: ipt}

	if err := mgr.BlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("BlockAllEgress() error = %v", err)
	}
	if err := mgr.BlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("BlockAllEgress() duplicate error = %v", err)
	}
	if got := readStateFile(t, state); len(got) != 1 || got[0] != "filter|DOCKER-USER|-s 10.0.0.2 -j DROP" {
		t.Fatalf("egress rules = %+v", got)
	}

	if err := mgr.BlockAllIngress("10.0.0.3"); err != nil {
		t.Fatalf("BlockAllIngress() error = %v", err)
	}
	if got := readStateFile(t, state); len(got) != 2 || got[1] != "filter|DOCKER-USER|-d 10.0.0.3 -j DROP" {
		t.Fatalf("rules after ingress = %+v", got)
	}

	dup := "filter|DOCKER-USER|-s 10.0.0.2 -j DROP\nfilter|DOCKER-USER|-s 10.0.0.2 -j DROP\nfilter|DOCKER-USER|-d 10.0.0.3 -j DROP\n"
	if err := os.WriteFile(state, []byte(dup), 0o600); err != nil {
		t.Fatalf("WriteFile(state) error = %v", err)
	}
	if err := mgr.ClearBlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("ClearBlockAllEgress() error = %v", err)
	}
	if got := readStateFile(t, state); len(got) != 1 || got[0] != "filter|DOCKER-USER|-d 10.0.0.3 -j DROP" {
		t.Fatalf("rules after clear egress = %+v", got)
	}

	if err := mgr.ClearBlockAllIngress("10.0.0.3"); err != nil {
		t.Fatalf("ClearBlockAllIngress() error = %v", err)
	}
	if got := readStateFile(t, state); len(got) != 0 {
		t.Fatalf("rules after clear ingress = %+v", got)
	}
}

func TestManagerEnabledErrors(t *testing.T) {
	script, _ := writeFakeIPTables(t)
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New() error = %v", err)
	}
	mgr := &Manager{enabled: true, ipt: ipt}

	for _, tc := range []struct {
		name    string
		fail    string
		run     func() error
		wantErr string
	}{
		{
			name:    "egress_exists_error",
			fail:    "check",
			run:     func() error { return mgr.BlockAllEgress("10.0.0.2") },
			wantErr: "check existing egress rule",
		},
		{
			name:    "egress_insert_error",
			fail:    "insert",
			run:     func() error { return mgr.BlockAllEgress("10.0.0.2") },
			wantErr: "insert egress rule",
		},
		{
			name:    "ingress_exists_error",
			fail:    "check",
			run:     func() error { return mgr.BlockAllIngress("10.0.0.3") },
			wantErr: "check existing ingress rule",
		},
		{
			name:    "ingress_insert_error",
			fail:    "insert",
			run:     func() error { return mgr.BlockAllIngress("10.0.0.3") },
			wantErr: "insert ingress rule",
		},
		// delete failures on an absent rule are no longer fatal: the Exists
		// fallback confirms the rule is gone (netlink ENOENT path). Genuine
		// delete failures while the rule still exists are covered by
		// TestClearLoopDeleteErrorWhenStillPresent.
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FAKE_IPTABLES_FAIL", tc.fail)
			if err := tc.run(); err == nil || err.Error() == "" || !contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// memBackend is an in-memory RuleBackend for asserting rule-state semantics
// of the selective-egress policy paths (allowlist/denylist + comment scoping)
// without a fake iptables binary. deleteErr selects which flavor of "rule
// absent" error a Delete miss returns — legacy iptables and iptables-nft
// word it differently, and the Manager must terminate its duplicate-sweep
// loops on both.
type memBackend struct {
	mu        sync.Mutex
	rules     []string
	deleteErr error
}

func memKey(table, chain string, spec ...string) string {
	return table + "|" + chain + "|" + strings.Join(spec, "|")
}

func (m *memBackend) Exists(table, chain string, spec ...string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.rules, memKey(table, chain, spec...)), nil
}

func (m *memBackend) Insert(table, chain string, _ int, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append(m.rules, memKey(table, chain, spec...))
	return nil
}

func (m *memBackend) Delete(table, chain string, spec ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(table, chain, spec...)
	for i, r := range m.rules {
		if r == k {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return errNoMatch{}
}

func (m *memBackend) ruleCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules)
}

func (m *memBackend) countMatching(substr string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.rules {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

type errNoMatch struct{}

func (errNoMatch) Error() string { return "No chain/target/match by that name." }

type errNftBadRule struct{}

func (errNftBadRule) Error() string {
	return "iptables v1.8.7 (nf_tables): Bad rule (does a matching rule exist in that chain?)."
}

// The Clear* duplicate-sweep loops probe past the last match, so the flavor
// of the terminating "rule absent" error decides whether the clear reads as
// success. Matching only the legacy wording made ClearBlockAllEgress fail on
// every iptables-nft host (Ubuntu 22.04's default) — which burned a parked
// slot on every warm-pool adopt. Both flavors must terminate cleanly, on a
// present rule (sweep past the delete) and an absent one (immediate probe).
func TestClearLoopsTerminateOnBothIptablesFlavors(t *testing.T) {
	flavors := map[string]error{
		"legacy": errNoMatch{},
		"nft":    errNftBadRule{},
	}
	for name, flavor := range flavors {
		t.Run(name, func(t *testing.T) {
			backend := &memBackend{deleteErr: flavor}
			mgr := NewWithBackend(backend)

			if err := mgr.BlockAllEgress("10.0.0.7"); err != nil {
				t.Fatalf("BlockAllEgress: %v", err)
			}
			if err := mgr.ClearBlockAllEgress("10.0.0.7"); err != nil {
				t.Fatalf("ClearBlockAllEgress with present rule: %v", err)
			}
			if len(backend.rules) != 0 {
				t.Fatalf("rules left after clear: %v", backend.rules)
			}
			if err := mgr.ClearBlockAllEgress("10.0.0.7"); err != nil {
				t.Fatalf("ClearBlockAllEgress with absent rule: %v", err)
			}

			if err := mgr.BlockAllIngress("10.0.0.7"); err != nil {
				t.Fatalf("BlockAllIngress: %v", err)
			}
			if err := mgr.ClearBlockAllIngress("10.0.0.7"); err != nil {
				t.Fatalf("ClearBlockAllIngress with present rule: %v", err)
			}

			if err := mgr.ApplyEgressPolicy("10.0.0.7", []string{"1.2.3.0/24"}, nil); err != nil {
				t.Fatalf("ApplyEgressPolicy: %v", err)
			}
			if err := mgr.ClearEgressPolicy("10.0.0.7", []string{"1.2.3.0/24"}, nil); err != nil {
				t.Fatalf("ClearEgressPolicy: %v", err)
			}
			if len(backend.rules) != 0 {
				t.Fatalf("policy rules left after clear: %v", backend.rules)
			}
		})
	}
}

func TestRuleNotExist(t *testing.T) {
	if ruleNotExist(nil) {
		t.Fatal("nil error must not read as not-exist")
	}
	if !ruleNotExist(errNoMatch{}) || !ruleNotExist(errNftBadRule{}) {
		t.Fatal("both iptables error flavors must read as not-exist")
	}
	if ruleNotExist(os.ErrPermission) {
		t.Fatal("unrelated error must not read as not-exist")
	}
}

// countingBackend tracks Delete/Exists call counts for the clear-loop
// regression suite (exec path must stay at 2 Delete / 0 Exists).
type countingBackend struct {
	memBackend
	mu      sync.Mutex
	deletes int
	exists  int
}

func (c *countingBackend) Exists(table, chain string, spec ...string) (bool, error) {
	c.mu.Lock()
	c.exists++
	c.mu.Unlock()
	return c.memBackend.Exists(table, chain, spec...)
}

func (c *countingBackend) Delete(table, chain string, spec ...string) error {
	c.mu.Lock()
	c.deletes++
	c.mu.Unlock()
	return c.memBackend.Delete(table, chain, spec...)
}

func TestClearLoopExecNoRegression(t *testing.T) {
	backend := &countingBackend{memBackend: memBackend{deleteErr: errNoMatch{}}}
	mgr := NewWithBackend(backend)
	if err := mgr.BlockAllEgress("10.0.0.7"); err != nil {
		t.Fatal(err)
	}
	backend.deletes, backend.exists = 0, 0
	if err := mgr.ClearBlockAllEgress("10.0.0.7"); err != nil {
		t.Fatal(err)
	}
	// Present rule: one successful Delete + one not-exist probe. Exists must
	// never fire when ruleNotExist already recognizes the error.
	if backend.deletes != 2 || backend.exists != 0 {
		t.Fatalf("exec clear: deletes=%d exists=%d, want 2/0", backend.deletes, backend.exists)
	}
}

func TestClearLoopNetlinkAbsentRuleExistsFallback(t *testing.T) {
	// Netlink ENOENT is unrecognized by ruleNotExist — Exists must confirm
	// gone or the clear loop returns fatal (the manager.go:13 adopt bug).
	backend := &countingBackend{memBackend: memBackend{
		deleteErr: errNetlinkNoSuchFile{},
	}}
	mgr := NewWithBackend(backend)
	if err := mgr.ClearBlockAllEgress("10.0.0.7"); err != nil {
		t.Fatalf("netlink absent-rule clear must terminate cleanly: %v", err)
	}
	if backend.deletes < 1 || backend.exists < 1 {
		t.Fatalf("netlink clear: deletes=%d exists=%d, want ≥1 each", backend.deletes, backend.exists)
	}

	// Same for ingress + policy delete paths.
	backend.deletes, backend.exists = 0, 0
	if err := mgr.ClearBlockAllIngress("10.0.0.7"); err != nil {
		t.Fatalf("ingress clear: %v", err)
	}
	backend.deletes, backend.exists = 0, 0
	if err := mgr.ClearEgressPolicy("10.0.0.7", []string{"1.2.3.0/24"}, nil); err != nil {
		t.Fatalf("policy clear: %v", err)
	}
}

type errNetlinkNoSuchFile struct{}

func (errNetlinkNoSuchFile) Error() string { return "no such file or directory" }

type stickyDeleteBackend struct {
	countingBackend
	deleteFail error
}

func (s *stickyDeleteBackend) Delete(table, chain string, spec ...string) error {
	s.deletes++
	if s.deleteFail != nil {
		return s.deleteFail
	}
	return s.memBackend.Delete(table, chain, spec...)
}

func TestClearLoopDeleteErrorWhenStillPresent(t *testing.T) {
	backend := &stickyDeleteBackend{
		countingBackend: countingBackend{memBackend: memBackend{}},
		deleteFail:      os.ErrPermission,
	}
	mgr := NewWithBackend(backend)
	if err := mgr.BlockAllEgress("10.0.0.7"); err != nil {
		t.Fatal(err)
	}
	// Rule still present (Delete always fails) → Exists=true → clear must error.
	if err := mgr.ClearBlockAllEgress("10.0.0.7"); err == nil {
		t.Fatal("expected delete error when rule still present")
	}
}

func TestNewWithBackend(t *testing.T) {
	if m := NewWithBackend(nil); m.Enabled() {
		t.Fatal("nil backend must build a disabled manager")
	}
	if m := NewWithBackend(&memBackend{}); !m.Enabled() {
		t.Fatal("backend-built manager must be enabled")
	}
}

func TestApplyEgressPolicyAllowlist(t *testing.T) {
	backend := &memBackend{}
	mgr := NewWithBackend(backend)
	const ip = "10.0.0.5"
	allow := []string{"1.1.1.1/32", "8.8.8.0/24"}

	if err := mgr.ApplyEgressPolicy(ip, allow, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Idempotent reapply must not duplicate rules.
	if err := mgr.ApplyEgressPolicy(ip, allow, nil); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	if len(backend.rules) != 3 {
		t.Fatalf("rules = %v, want catch-all DROP + 2 ACCEPTs", backend.rules)
	}
	if ok, _ := backend.Exists("filter", "DOCKER-USER", "-s", ip, "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); !ok {
		t.Fatal("allowlist catch-all DROP missing")
	}
	for _, cidr := range allow {
		if ok, _ := backend.Exists("filter", "DOCKER-USER", "-s", ip, "-d", cidr, "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"); !ok {
			t.Fatalf("ACCEPT for %s missing", cidr)
		}
	}

	if err := mgr.ClearEgressPolicy(ip, allow, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(backend.rules) != 0 {
		t.Fatalf("rules after clear = %v", backend.rules)
	}
	// Clearing an already-clean policy must tolerate absent rules.
	if err := mgr.ClearEgressPolicy(ip, allow, nil); err != nil {
		t.Fatalf("re-clear: %v", err)
	}
}

func TestApplyEgressPolicyDenylist(t *testing.T) {
	backend := &memBackend{}
	mgr := NewWithBackend(backend)
	const ip = "10.0.0.6"
	deny := []string{"192.168.0.0/16"}

	if err := mgr.ApplyEgressPolicy(ip, nil, deny); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(backend.rules) != 1 {
		t.Fatalf("rules = %v, want one DROP", backend.rules)
	}
	if ok, _ := backend.Exists("filter", "DOCKER-USER", "-s", ip, "-d", deny[0], "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"); !ok {
		t.Fatal("denylist DROP missing")
	}
	if err := mgr.ClearEgressPolicy(ip, nil, deny); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(backend.rules) != 0 {
		t.Fatalf("rules after clear = %v", backend.rules)
	}
}

func TestApplyEgressPolicyDisabledAndEmptyIP(t *testing.T) {
	if err := (&Manager{}).ApplyEgressPolicy("10.0.0.7", []string{"1.1.1.1/32"}, nil); err != nil {
		t.Fatalf("disabled apply: %v", err)
	}
	if err := (&Manager{}).ClearEgressPolicy("10.0.0.7", []string{"1.1.1.1/32"}, nil); err != nil {
		t.Fatalf("disabled clear: %v", err)
	}
	mgr := NewWithBackend(&memBackend{})
	if err := mgr.ApplyEgressPolicy("", []string{"1.1.1.1/32"}, nil); err != nil {
		t.Fatalf("empty ip apply: %v", err)
	}
}

func writeFakeIPTables(t *testing.T) (scriptPath, statePath string) {
	t.Helper()
	dir := t.TempDir()
	statePath = filepath.Join(dir, "rules.txt")
	scriptPath = filepath.Join(dir, "iptables")
	script := `#!/bin/sh
set -eu
state="${FAKE_IPTABLES_STATE:?}"
if [ "${1:-}" = "--version" ]; then
  echo "iptables v1.8.9 (nf_tables)"
  exit 0
fi
fail="${FAKE_IPTABLES_FAIL:-}"
table=""
op=""
chain=""
spec=""
while [ $# -gt 0 ]; do
  case "$1" in
    --wait)
      shift
      if [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; then
        :
      elif [ $# -gt 0 ] && [ "$1" -eq "$1" ] 2>/dev/null; then
        shift
      fi
      ;;
    -t)
      table="$2"
      shift 2
      ;;
    -C|-I|-D)
      op="$1"
      chain="$2"
      shift 2
      if [ "$op" = "-I" ]; then
        shift
      fi
      spec="$*"
      case "$spec" in
        *" --wait") spec=${spec%" --wait"} ;;
      esac
      break
      ;;
    *)
      shift
      ;;
  esac
done
key="$table|$chain|$spec"
case "$fail:$op" in
  check:-C|insert:-I|delete:-D)
    echo "$fail failed" >&2
    exit 2
    ;;
esac
touch "$state"
case "$op" in
  -C)
    if grep -Fxq "$key" "$state"; then
      exit 0
    fi
    exit 1
    ;;
  -I)
    if ! grep -Fxq "$key" "$state"; then
      printf '%s\n' "$key" >> "$state"
    fi
    ;;
  -D)
    if ! grep -Fxq "$key" "$state"; then
      echo "No chain/target/match by that name." >&2
      exit 1
    fi
    awk -v key="$key" 'BEGIN{removed=0} { if (!removed && $0 == key) { removed=1; next } print }' "$state" > "$state.tmp"
    mv "$state.tmp" "$state"
    ;;
  *)
    echo "unsupported args: $*" >&2
    exit 2
    ;;
esac
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(script) error = %v", err)
	}
	t.Setenv("FAKE_IPTABLES_STATE", statePath)
	return scriptPath, statePath
}

func readStateFile(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if len(data) == 0 {
		return nil
	}
	var out []string
	for _, line := range splitLines(string(data)) {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}())
}

type errBackend struct {
	existsErr error
	insertErr error
	deleteErr error
}

func (e *errBackend) Exists(string, string, ...string) (bool, error) { return false, e.existsErr }
func (e *errBackend) Insert(string, string, int, ...string) error    { return e.insertErr }
func (e *errBackend) Delete(string, string, ...string) error         { return e.deleteErr }

func TestEnsureAndDeletePolicyRuleErrors(t *testing.T) {
	t.Parallel()
	mgr := NewWithBackend(&errBackend{existsErr: errors.New("exists boom")})
	if err := mgr.ApplyEgressPolicy("10.0.0.7", []string{"1.1.1.1/32"}, nil); err == nil || !strings.Contains(err.Error(), "check egress policy rule") {
		t.Fatalf("ensure exists err = %v", err)
	}

	mgr = NewWithBackend(&errBackend{insertErr: errors.New("insert boom")})
	if err := mgr.ApplyEgressPolicy("10.0.0.7", nil, []string{"9.9.9.9/32"}); err == nil || !strings.Contains(err.Error(), "insert egress policy rule") {
		t.Fatalf("ensure insert err = %v", err)
	}

	// deleteUntilGone: Delete errors, Exists also errors → surface Delete err wrapped.
	mgr = NewWithBackend(&errBackend{
		deleteErr: errors.New("delete boom"),
		existsErr: errors.New("exists still failing"),
	})
	if err := mgr.ClearEgressPolicy("10.0.0.7", nil, []string{"9.9.9.9/32"}); err == nil || !strings.Contains(err.Error(), "delete egress policy rule") {
		t.Fatalf("deletePolicyRule err = %v", err)
	}
}

func TestNewWithOptionsDisabled(t *testing.T) {
	t.Parallel()
	m, err := NewWithOptions(false, BackendNetlink)
	if err != nil || m.Enabled() {
		t.Fatalf("disabled NewWithOptions = (%v,%v)", m, err)
	}
}
