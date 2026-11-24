#!/bin/bash
# vm-userdata.sh: part B of the M1 drill, on one EC2 machine (vm-n1.sh
# launches it). The chart refuses WASM in a split worker pod, so N1's WASM
# question (+0.63 ms focused, +1.79 ms busy mix on Docker Desktop, #1430) is
# measured on a VM install: AerolVM from the commit's source
# (scripts/install.sh --build-from-source --with-containerd-engine), in
# privilege mode single, then split, then single, then split (ABAB on the
# same machine, so the hardware is the same for both). A source build's
# helper is unsigned; install.sh trusts the checkout for it, as for
# sandboxd. No key is used.
# VMN1 lines go to the serial console, which vm-n1.sh reads; everything else
# to /var/log/m1vm.log. The machine powers off (and so terminates) when done,
# or after @TTL_MIN@ minutes whatever happens.
exec >>/var/log/m1vm.log 2>&1
shutdown -h +@TTL_MIN@
say() { echo "VMN1 $*"; echo "VMN1 $*" >/dev/console; }
finish() { say "DONE"; sync; sleep 120; poweroff; }
export HOME=/root DEBIAN_FRONTEND=noninteractive
cd /root
say "start $(date -u +%FT%TZ); kernel $(uname -r); $(nproc) cpus"
curl -fsS --retry 5 --retry-all-errors -o src.tgz "@SRC_URL@" &&
  curl -fsS --retry 5 --retry-all-errors -o kit.tgz "@KIT_URL@" || { say "staging download FAILED"; finish; exit 0; }
mkdir -p src kit && tar -xzf src.tgz -C src && tar -xzf kit.tgz -C kit
gov="$(awk '/^go /{print $2; exit}' src/go.mod)"
# Go, unpacked only after its SHA-256 matches the one go.dev lists for it.
curl -fsSL --retry 5 -o go.json 'https://go.dev/dl/?mode=json&include=all' &&
  want="$(python3 -I -c 'import json, sys; print(next(f["sha256"] for r in json.load(open(sys.argv[1])) for f in r["files"] if f["filename"] == sys.argv[2]))' go.json "go${gov}.linux-amd64.tar.gz")" &&
  curl -fsSL --retry 5 -o go.tgz "https://go.dev/dl/go${gov}.linux-amd64.tar.gz" &&
  echo "$want  go.tgz" | sha256sum -c - >/dev/null &&
  tar -C /usr/local -xzf go.tgz || { say "Go ${gov} download FAILED or its SHA-256 did not match"; finish; exit 0; }
export PATH=/usr/local/go/bin:$PATH GOFLAGS=-buildvcs=false

# The two WASM modules the busy mix refills (python, ruby), checked by
# their digests from integration-tests/fixtures/wasm/modules.yml.
mkdir -p /root/wasm
fetch_mod() { # fetch_mod <alias> <file>
  local ref dig
  ref="$(awk -v a="$1" '$0 ~ "alias: "a"$" {f=1} f && /ref:/ {gsub(/"/, "", $2); print $2; exit}' src/integration-tests/fixtures/wasm/modules.yml)"
  dig="$(awk -v a="$1" '$0 ~ "alias: "a"$" {f=1} f && /digest:/ {gsub(/"|sha256:/, "", $2); print $2; exit}' src/integration-tests/fixtures/wasm/modules.yml)"
  curl -fsSL --retry 5 -o "/root/wasm/$2" "$ref" && echo "$dig  /root/wasm/$2" | sha256sum -c - >/dev/null
}
fetch_mod python python.wasm && fetch_mod ruby ruby.wasm || { say "WASM module download FAILED"; finish; exit 0; }
openssl rand -hex 24 >/root/pat && chmod 600 /root/pat

# install_mode <single|split>: install.sh in that mode (a re-run switches
# the node), then the bench's settings, then a restart.
install_mode() {
  local t0=$(date +%s)
  if ! (cd src && ./scripts/install.sh --with-containerd-engine --with-isolate --privilege-mode "$1" \
      --public-host 127.0.0.1 --pat-token "$(cat /root/pat)" --build-from-source); then
    say "install $1 FAILED; last lines:"; tail -20 /var/log/m1vm.log | sed 's/^/VMN1   /' >/dev/console
    return 1
  fi
  install -d /var/lib/sandboxd/wasm/modules
  install -m 0644 /root/wasm/python.wasm /root/wasm/ruby.wasm /var/lib/sandboxd/wasm/modules/
  # The warm pool with the resident host off, as #1430 measured it; two
  # modules of 8 slots each (16 slots refilling in the busy mix).
  cat >>/etc/sandboxd/sandboxd.env <<'ENV'

# M1 drill part B (vm-userdata.sh)
SB_ENABLE_WASM=true
SB_WASM_POOL_ENABLED=true
SB_WASM_RESIDENT_HOST_ENABLED=false
SB_WASM_POOL_DEPTH_DEFAULT=8
SB_WASM_STANDARD_MODULES=python=python.wasm,ruby=ruby.wasm
SB_ISOLATE_POOL_DEPTH_DEFAULT=8
ENV
  systemctl restart aerolvm-rootd 2>/dev/null || true
  systemctl restart sandboxd
  for _ in $(seq 1 60); do curl -fsS -m 3 http://127.0.0.1:21212/health >/dev/null 2>&1 && break; sleep 2; done
  say "isolate: $(grep -E '^SB_(ENABLE_ISOLATE|ISOLATE_USE_JAIL)=' /etc/sandboxd/sandboxd.env | tr '\n' ' ')root mount $(findmnt -no PROPAGATION /)"
  say "installed $1 in $(( $(date +%s) - t0 ))s; sandboxd user $(ps -o user= -C sandboxd | head -1); helper $(systemctl is-active aerolvm-rootd 2>/dev/null || echo none)"
}

block=0
for mode in single split single split; do
  block=$((block + 1))
  install_mode "$mode" || { finish; exit 0; }
  sleep 30   # pools fill
  python3 kit/vm-bench.py --mode "$mode" --pair $(( (block + 1) / 2 )) --rounds @ROUNDS@ --busy-rounds @BUSY@ \
    --pat-file /root/pat 2>&1 | while IFS= read -r l; do echo "$l"; case "$l" in N1*|VMN1*) echo "$l" >/dev/console;; esac; done
done
journalctl -u sandboxd -u aerolvm-rootd --no-pager 2>/dev/null | grep -E 'level=(WARN|ERROR)' | tail -6 | cut -c1-300 | sed 's/^/VMN1   log: /' >/dev/console
finish
