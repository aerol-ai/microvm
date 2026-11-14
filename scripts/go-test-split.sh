#!/usr/bin/env bash
# Runs `go test` over PACKAGES, with the slowest packages split by test name
# into parts that run side by side.
#
# Why: internal/cluster runs its ~1,150 tests one after another. In CI it
# alone took 9.6 min (11.5 min under -race) of a 13 (16) min job. Its tests
# mostly wait on timers and sockets (about 0.2 of a core), so running it as N
# parts at once cuts that to its slowest part. Each part is its own process,
# so tests that share package-level state still never overlap inside one
# process.
#
# Usage:
#   scripts/go-test-split.sh [go test flags] -- PACKAGES...
#
#   # the cluster and service tests, each in parts:
#   GO_TEST_SPLIT="./internal/cluster=3 ./internal/service=2" \
#     scripts/go-test-split.sh -count=1 -- ./internal/cluster ./internal/service
#   # everything else, with one merged coverage profile:
#   GO_TEST_SKIP="./internal/cluster ./internal/service" GO_TEST_COVERPROFILE=coverage.out \
#     scripts/go-test-split.sh -count=1 -- ./cmd/... ./internal/... ./pkg/...
#
# GO_TEST_SPLIT lists "package=parts" pairs; a package not in PACKAGES is
# ignored. GO_TEST_SKIP lists packages to leave out because another job runs
# them. Every other package runs in one plain `go test` call.
#
# CI runs the split cluster and service parts in a job of their own: next to
# the CPU-heavy packages, Raft tests with 250 ms election timers lost their
# leader mid-test.
#
# GO_TEST_NETNS=1 (Linux with passwordless sudo, as on GitHub's runners)
# starts each part of a split package in a network namespace of its own,
# with just a loopback. Without it, the parts share one loopback: a Raft or
# gossip node in one part can be handed a port that another part's cluster
# still sends to. In CI that hung TestClusterFaultLeaderChangeDuringConcurrentReserves
# for 18 minutes and made a closed Raft node panic ("database not open").
# Locally, leave the cluster package whole or accept that risk.
#
# Every top-level test of a split package runs in exactly one part: the
# names come from `go test -list` (with the same flags, so the build is
# reused) and are dealt out in turn. With GO_TEST_COVERPROFILE set, each part
# writes its own profile and they are merged into that file; a block counts
# as covered if any part covered it.
#
# Works with the bash 3.2 that macOS ships, so it runs the same way locally.
set -euo pipefail

flags=()
while [[ $# -gt 0 && "$1" != "--" ]]; do
	flags+=("$1")
	shift
done
if [[ $# -lt 2 ]]; then
	echo "usage: $0 [go test flags] -- PACKAGES..." >&2
	exit 2
fi
shift

GO="${GO:-go}"
work="$(mktemp -d)"
pids=()
names=()
cleanup() {
	for pid in "${pids[@]+"${pids[@]}"}"; do
		kill "$pid" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT

if [[ -n "${GO_TEST_NETNS:-}" ]]; then
	for tool in sudo unshare setpriv ip; do
		command -v "$tool" >/dev/null || { echo "$0: GO_TEST_NETNS needs $tool" >&2; exit 2; }
	done
	sudo -n true || { echo "$0: GO_TEST_NETNS needs passwordless sudo" >&2; exit 2; }
fi

# isolated CMD... runs CMD as this user in a new network namespace with only
# a loopback, up. sudo keeps the environment but resets PATH, so PATH and
# HOME (the Go caches live under it) are passed through again.
isolated() {
	sudo --preserve-env unshare --net -- bash -c '
		ip link set lo up || exit 1
		uid=$1 gid=$2
		shift 2
		exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- "$@"
	' isolated "$(id -u)" "$(id -g)" env "PATH=$PATH" "HOME=$HOME" "$@"
}

list_flags=("${flags[@]+"${flags[@]}"}")
if [[ -n "${GO_TEST_COVERPROFILE:-}" ]]; then
	list_flags+=(-cover)
fi

skip_pkgs=" "
for pattern in ${GO_TEST_SKIP:-}; do
	skip_pkgs+="$("$GO" list "$pattern" | tr '\n' ' ')"
done

all_pkgs=()
while IFS= read -r pkg; do
	[[ "$skip_pkgs" == *" $pkg "* ]] || all_pkgs+=("$pkg")
done < <("$GO" list "$@")

split_pkgs=()
split_parts=()
for spec in ${GO_TEST_SPLIT:-}; do
	split_pkgs+=("$("$GO" list "${spec%=*}")")
	split_parts+=("${spec##*=}")
done

# parts_for PKG prints how many parts PKG is split into, or nothing.
parts_for() {
	local i
	for ((i = 0; i < ${#split_pkgs[@]}; i++)); do
		if [[ "${split_pkgs[i]}" == "$1" ]]; then
			echo "${split_parts[i]}"
			return
		fi
	done
}

# start NAME ISOLATE GO_TEST_ARGS... runs one `go test` in the background
# (in its own network namespace when ISOLATE is "isolate") and keeps its
# output, exit code and duration under $work.
start() {
	local name="$1" isolate="$2"
	shift 2
	local cover=()
	if [[ -n "${GO_TEST_COVERPROFILE:-}" ]]; then
		cover=(-coverprofile="$work/$name.cover")
	fi
	names+=("$name")
	(
		run=("$GO" test "${flags[@]+"${flags[@]}"}" "${cover[@]+"${cover[@]}"}" "$@")
		if [[ "$isolate" == isolate ]]; then
			run=(isolated "${run[@]}")
		fi
		begin=$SECONDS
		rc=0
		"${run[@]}" >"$work/$name.log" 2>&1 || rc=$?
		echo "$rc $((SECONDS - begin))" >"$work/$name.result"
	) &
	pids+=($!)
}

rest=()
for pkg in "${all_pkgs[@]}"; do
	[[ -n "$(parts_for "$pkg")" ]] || rest+=("$pkg")
done
if [[ ${#rest[@]} -gt 0 ]]; then
	start rest shared "${rest[@]}"
fi

part_net=shared
if [[ -n "${GO_TEST_NETNS:-}" ]]; then
	part_net=isolate
fi

for pkg in "${all_pkgs[@]}"; do
	n="$(parts_for "$pkg")"
	[[ -n "$n" ]] || continue
	short="${pkg##*/}"
	if ! "$GO" test "${list_flags[@]+"${list_flags[@]}"}" -list . "$pkg" >"$work/$short.list" 2>&1; then
		cat "$work/$short.list" >&2
		echo "$0: go test -list $pkg failed" >&2
		exit 1
	fi
	tests=()
	while IFS= read -r t; do
		tests+=("$t")
	done < <(grep -E '^(Test|Fuzz|Example)[A-Za-z0-9_]*$' "$work/$short.list" || true)
	for ((i = 0; i < n; i++)); do
		chosen=()
		for ((j = i; j < ${#tests[@]}; j += n)); do
			chosen+=("${tests[j]}")
		done
		[[ ${#chosen[@]} -gt 0 ]] || continue
		pattern="^($(IFS='|'; echo "${chosen[*]}"))\$"
		start "$short-$((i + 1))of$n" "$part_net" -run "$pattern" "$pkg"
	done
done

if [[ ${#names[@]} -eq 0 ]]; then
	echo "$0: nothing to test: every package was skipped or has no tests" >&2
	exit 2
fi

for pid in "${pids[@]+"${pids[@]}"}"; do
	wait "$pid" || true
done
pids=()

group() { if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::group::$1"; else echo "=== $1"; fi; }
endgroup() { if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::endgroup::"; fi; }

failed=()
for name in "${names[@]}"; do
	read -r rc secs <"$work/$name.result"
	if [[ "$rc" -eq 0 ]]; then
		group "$name: ok (${secs}s)"
		cat "$work/$name.log"
		endgroup
	else
		failed+=("$name")
	fi
done
# Failing parts go last and outside a group, so their output is what shows.
for name in "${failed[@]+"${failed[@]}"}"; do
	read -r rc secs <"$work/$name.result"
	echo "=== $name: FAILED (exit $rc, ${secs}s)"
	cat "$work/$name.log"
done

echo "=== parts"
for name in "${names[@]}"; do
	read -r rc secs <"$work/$name.result"
	if [[ "$rc" -eq 0 ]]; then status=ok; else status=FAIL; fi
	printf '%-20s %-4s %5ss\n' "$name" "$status" "$secs"
done

if [[ -n "${GO_TEST_COVERPROFILE:-}" ]]; then
	covers=()
	for name in "${names[@]}"; do
		if [[ -s "$work/$name.cover" ]]; then
			covers+=("$work/$name.cover")
		fi
	done
	if [[ ${#covers[@]} -gt 0 ]]; then
		# Text profiles: a "mode:" line, then "file:range numstmt count".
		# Parts of a split package report the same blocks; keep one line
		# per block.
		awk '
			FNR == 1 { if (mode == "") mode = $0; next }
			{
				key = $1 " " $2
				if (!(key in count)) { order[++n] = key; count[key] = $3 }
				else if (mode == "mode: set") { if ($3 > count[key]) count[key] = $3 }
				else count[key] += $3
			}
			END { print mode; for (i = 1; i <= n; i++) print order[i], count[order[i]] }
		' "${covers[@]}" >"$GO_TEST_COVERPROFILE"
	fi
fi

[[ ${#failed[@]} -eq 0 ]]
