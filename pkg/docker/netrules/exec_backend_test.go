package netrules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

// writeBootstrapIPTables is like writeFakeIPTables but also handles chain
// bootstrap (-S for ChainExists, -N for NewChain) so execBackend can be
// exercised offline.
func writeBootstrapIPTables(t *testing.T) (scriptPath, statePath string) {
	t.Helper()
	dir := t.TempDir()
	statePath = filepath.Join(dir, "rules.txt")
	chainsPath := filepath.Join(dir, "chains.txt")
	scriptPath = filepath.Join(dir, "iptables")
	script := `#!/bin/sh
set -eu
state="${FAKE_IPTABLES_STATE:?}"
chains="${FAKE_IPTABLES_CHAINS:?}"
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
    -N)
      chain="$2"
      if [ "$fail" = "new" ]; then
        echo "$fail failed" >&2
        exit 2
      fi
      touch "$chains"
      if ! grep -Fxq "$table|$chain" "$chains"; then
        printf '%s\n' "$table|$chain" >> "$chains"
      fi
      exit 0
      ;;
    -S)
      chain="$2"
      if [ "$fail" = "chain" ]; then
        echo "$fail failed" >&2
        exit 2
      fi
      touch "$chains"
      if grep -Fxq "$table|$chain" "$chains"; then
        exit 0
      fi
      exit 1
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
  check:-C|insert:-I|delete:-D|chain:-S|new:-N)
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
		t.Fatalf("WriteFile(script): %v", err)
	}
	t.Setenv("FAKE_IPTABLES_STATE", statePath)
	t.Setenv("FAKE_IPTABLES_CHAINS", chainsPath)
	return scriptPath, statePath
}

func TestExecBackendBootstrapAndRules(t *testing.T) {
	script, state := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "") // isolate from PropagatesErrors env leakage
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be := newExecBackend(ipt)

	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatalf("EnsureUserChain(create): %v", err)
	}
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatalf("EnsureUserChain(idempotent): %v", err)
	}
	if err := be.EnsureForwardJump(ChainAerolvmUser); err != nil {
		t.Fatalf("EnsureForwardJump: %v", err)
	}
	if err := be.EnsureForwardJump(ChainAerolvmUser); err != nil {
		t.Fatalf("EnsureForwardJump(idempotent): %v", err)
	}

	spec := []string{"-s", "10.0.0.1", "-j", "DROP"}
	ok, err := be.Exists("filter", ChainAerolvmUser, spec...)
	if err != nil {
		t.Fatalf("Exists(before): %v", err)
	}
	if ok {
		t.Fatal("rule should not exist yet")
	}
	if err := be.Insert("filter", ChainAerolvmUser, 1, spec...); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	ok, err = be.Exists("filter", ChainAerolvmUser, spec...)
	if err != nil || !ok {
		t.Fatalf("Exists(after) = %v, %v", ok, err)
	}
	if err := be.Delete("filter", ChainAerolvmUser, spec...); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := readStateFile(t, state); len(got) != 1 || !stringsContains(got[0], "FORWARD") || !stringsContains(got[0], ChainAerolvmUser) {
		t.Fatalf("rules after delete = %v", got)
	}
}

func TestExecBackendValidationErrors(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be := newExecBackend(ipt)

	if err := be.EnsureUserChain("  "); err == nil {
		t.Fatal("expected empty chain error")
	}
	if err := be.EnsureForwardJump(""); err == nil {
		t.Fatal("expected empty jump chain error")
	}
}

func TestExecBackendPropagatesErrors(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "new")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be := newExecBackend(ipt)
	if err := be.EnsureUserChain(ChainAerolvmUser); err == nil {
		t.Fatal("expected NewChain error")
	}

	t.Setenv("FAKE_IPTABLES_FAIL", "insert")
	ipt, err = iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be = newExecBackend(ipt)
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatalf("EnsureUserChain: %v", err)
	}
	if err := be.EnsureForwardJump(ChainAerolvmUser); err == nil {
		t.Fatal("expected forward jump error")
	}
}

func stringsContains(s, sub string) bool {
	return strings.Contains(s, sub)
}
