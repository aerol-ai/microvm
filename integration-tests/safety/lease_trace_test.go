package safety

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// lockTrace wraps the lease functions so each run writes a TRACE line to
// stderr at every step: the lock path, git's own answers, the worktrees it
// saw, the pins and claims it read, and when it took and freed the lock.
// The concurrency tests print both runs' traces when a round fails. Two
// worktrees got the same domain or claim on CI twice, and nowhere else, so
// this is how that runner shows what it did.
func lockTrace() string {
	return `
__lt() { printf 'TRACE %s root=%s pid=%s bpid=%s %s\n' "$(date +%s.%N)" "${REPO_ROOT##*/}" "$$" "${BASHPID:-?}" "$*" >&2; }
__lt_wrap() { eval "__lt_orig_$(declare -f "$1")"; }
__lt "start host=$(uname -n) $(git --version) rootP=$(cd "$REPO_ROOT" && pwd -P) dotgit=[$(ls -ld "$REPO_ROOT/.git" 2>&1)] common=[$(git -C "$REPO_ROOT" rev-parse --git-common-dir 2>&1)] porcelain=[$(git -C "$REPO_ROOT" worktree list --porcelain 2>&1 | tr '\n' '|')]"
__lt_wrap lease_lock_acquire
lease_lock_acquire() {
  __lt "acquire begin path=[$(lease_lock_path 2>&1)]"
  local rc=0
  __lt_orig_lease_lock_acquire "$@" || rc=$?
  __lt "acquire end rc=$rc lock=${LEASE_LOCK:-} owner=[$(cat "${LEASE_LOCK:-/nonexistent}/owner" 2>&1)] inode=[$(ls -di "${LEASE_LOCK:-/nonexistent}" 2>&1)]"
  return "$rc"
}
__lt_wrap lease_lock_release
lease_lock_release() {
  __lt "release lock=${LEASE_LOCK:-} own_files=[$(ls "$REPO_ROOT"/integration-tests/.tf/*/.leased-domain "$REPO_ROOT"/integration-tests/.tf/*/.state-claim 2>/dev/null | tr '\n' '|')]"
  __lt_orig_lease_lock_release "$@"
}
__lt_wrap worktree_roots
worktree_roots() {
  local out rc=0
  out=$(__lt_orig_worktree_roots) || rc=$?
  __lt "worktree_roots rc=$rc out=[$(printf '%s' "$out" | tr '\n' '|')]"
  printf '%s\n' "$out"
  return "$rc"
}
if declare -F domain_pins >/dev/null; then
  __lt_wrap domain_pins
  domain_pins() {
    local out rc=0
    out=$(__lt_orig_domain_pins "$@") || rc=$?
    __lt "domain_pins rc=$rc own=${1:-} out=[$(printf '%s' "$out" | tr '\n' '|')]"
    [[ -z "$out" ]] || printf '%s\n' "$out"
    return "$rc"
  }
fi
if declare -F scenario_holders >/dev/null; then
  __lt_wrap scenario_holders
  scenario_holders() {
    local out rc=0
    out=$(__lt_orig_scenario_holders "$@") || rc=$?
    __lt "scenario_holders rc=$rc out=[$(printf '%s' "$out" | tr '\n' '|')]"
    [[ -z "$out" ]] || printf '%s\n' "$out"
    return "$rc"
  }
fi
`
}

// treeState lists what each worktree holds under .tf and the shared lock,
// for a failed round's report.
func treeState(a, b string) string {
	var s strings.Builder
	for _, root := range []string{a, b} {
		_ = filepath.Walk(filepath.Join(root, "integration-tests", ".tf"), func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				body, _ := os.ReadFile(p)
				fmt.Fprintf(&s, "  %s = %q\n", p, strings.TrimSpace(string(body)))
			}
			return nil
		})
	}
	lock := filepath.Join(a, ".git", "aerol-itest-domain-lease.lock")
	if _, err := os.Stat(lock); err == nil {
		fmt.Fprintf(&s, "  lock still there: %s\n", lock)
	}
	return s.String()
}
