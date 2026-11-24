#!/bin/bash
# n1-bench.sh: N1 for M1, split against single, run inside the cluster (pod
# m1-bench, m1-eks.sh n1) so both sides are timed from one place, through
# the gateway Service, as a client would see them.
#
#   n1-bench.sh cold  <pairs>    a create with no warm slot (busybox: not in
#                                the pool), then its delete
#   n1-bench.sh warm  <pairs>    a pool create (alpine: the pool's image),
#                                paced so each worker's pool refills
#   n1-bench.sh burst <n>        n creates at once on each side (not paired)
#   n1-bench.sh first            one create on each side, nothing before it
#
# A pair is one create on each side, one after the other, the order flipped
# every round. m1-eks.sh cordons (in AerolVM) every worker but one of each
# mode, SPLIT_NODE and SINGLE_NODE; before each create (not timed) this
# cordons the other side's worker too, so the create lands on its side.
# (Placement never matches the gVisor-moves label: live run m1d-2.)
# Prints one line per create:
#   N1 <phase> <round> <mode> client_ms=<n> create_ms=<worker's Server-Timing create;dur> code=<http> id=<id>
# and keeps the whole Server-Timing header on a "N1T" line. Needs bash,
# curl and date only (the Amazon Linux 2023 image).
#
# GW (the gateway Service URL) and TOKEN come from the pod's environment.
set -uo pipefail
phase="${1:?phase}"; n="${2:-10}"
GW="${GW:?}"; TOKEN="${TOKEN:?}"; SPLIT_NODE="${SPLIT_NODE:?}"; SINGLE_NODE="${SINGLE_NODE:?}"
ALPINE=public.ecr.aws/docker/library/alpine:3.20
BUSYBOX=public.ecr.aws/docker/library/busybox:1.36
ms() { date +%s%3N; }

body() { # body <image>
  printf '{"runtime":"gvisor","image":"%s","cpu":0.1,"memory_mb":64,"tags":{"m1-n1":"%s"}}' "$1" "$phase"
}
# pin <mode>: only that side's worker takes new sandboxes (AerolVM's
# admission-only cordon on the other).
pin() {
  local on="$SINGLE_NODE" off="$SPLIT_NODE"
  [[ "$1" == split ]] && { on="$SPLIT_NODE"; off="$SINGLE_NODE"; }
  curl -sS -m 30 -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" "$GW/v1/cluster/nodes/$off/cordon" || true
  curl -sS -m 30 -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" "$GW/v1/cluster/nodes/$on/uncordon" || true
  # A cordon reaches placement a moment later (live run m1d-2: a create right
  # after a flip answered 503).
  sleep 1
}

# one <round> <mode> <image> [nopin]: a create, timed, then its delete (not
# timed). The pin before it is not timed either.
one() {
  local r="$1" mode="$2" image="$3" t0 t1 hdr code id st cdur
  [[ "${4:-}" == nopin ]] || pin "$mode"
  hdr="$(mktemp)"
  t0=$(ms)
  out="$(curl -sS -m 120 -D "$hdr" -o - -w '\n%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d "$(body "$image")" "$GW/v1/sandboxes" 2>/dev/null)"
  t1=$(ms)
  code="${out##*$'\n'}"
  id="$(sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' <<<"${out%$'\n'*}" | head -1)"
  st="$(grep -i '^server-timing:' "$hdr" | tr -d '\r' | sed 's/^[Ss]erver-[Tt]iming: *//' | tr '\n' ',')"
  # The target worker's create;dur comes first; the router's stages
  # (cluster_place, cluster_reserve, cluster_forward) follow it
  # (pkg/api/clustercreate addRouterTiming). "docker_create;dur" is a
  # stage, never first, so the anchor keeps it out.
  cdur="$(grep -o '^create;dur=[0-9.]*' <<<"$st" | cut -d= -f2)"
  rm -f "$hdr"
  # Still the stale moment: once more, after a wait (not timed).
  if [[ "$code" == 503 && -z "$id" && "${5:-}" != retried ]]; then
    echo "N1R $phase $r $mode 503 after the pin; retrying once"
    sleep 2
    one "$r" "$mode" "$image" "${4:-}" retried
    return
  fi
  echo "N1 $phase $r $mode client_ms=$((t1 - t0)) create_ms=${cdur:--1} code=$code id=${id:-none}"
  echo "N1T $phase $r $mode $st"
  if [[ -n "$id" ]]; then
    curl -sS -m 60 -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$GW/v1/sandboxes/$id" 2>/dev/null || true
  fi
}

pairs() { # pairs <image> <count> <pause seconds>
  local i a b
  for i in $(seq 1 "$2"); do
    if (( i % 2 )); then a=split b=single; else a=single b=split; fi
    one "$i" "$a" "$1"
    one "$i" "$b" "$1"
    sleep "$3"
  done
}

case "$phase" in
  first) one 0 split "$ALPINE"; one 0 single "$ALPINE" ;;
  cold)
    # One untimed create of each side first, so the image is on both
    # workers and the first timed create pulls nothing.
    one prime split "$BUSYBOX" >/dev/null; one prime single "$BUSYBOX" >/dev/null
    pairs "$BUSYBOX" "$n" 1 ;;
  warm)
    # Depth 5, refilled every 5 s (values.yaml): one claim per side every
    # 2 s stays inside the refill. The first round waits for full pools.
    sleep 20
    pairs "$ALPINE" "$n" 2 ;;
  burst)
    for mode in split single; do
      pin "$mode"
      sleep 20
      t0=$(ms)
      for i in $(seq 1 "$n"); do one "$i" "$mode" "$ALPINE" nopin & done
      wait
      echo "N1 burst-total $mode $n creates in $(( $(ms) - t0 )) ms"
    done ;;
  *) echo "n1-bench.sh: unknown phase $phase" >&2; exit 2 ;;
esac
# Both sides open again for whoever comes next.
curl -sS -m 30 -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" "$GW/v1/cluster/nodes/$SPLIT_NODE/uncordon" || true
curl -sS -m 30 -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" "$GW/v1/cluster/nodes/$SINGLE_NODE/uncordon" || true
echo "N1 done $phase"
