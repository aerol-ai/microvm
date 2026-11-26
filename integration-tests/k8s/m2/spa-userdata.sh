#!/bin/bash
# spa-userdata.sh: one SP-A bench leg (plans/security-gaps-m1-m4.md §4.2) on
# one EC2 machine, rendered by spa.sh. Ubuntu 24.04. It installs AerolVM
# single-node with Firecracker from the staged commit (scripts/install.sh
# --with-firecracker --build-from-source), runs spa-bench.py base (cold,
# template, pause and resume busy and idle), turns the warm VMM pool on,
# runs spa-bench.py warm, and PUTs its logs and JSON to the results link.
# SPA lines go to the serial console, which spa.sh reads; nothing comes in
# over the network. The machine powers off when done, or after @TTL_MIN@
# minutes whatever happens; powering off terminates it.
exec >>/var/log/spa.log 2>&1
shutdown -h +@TTL_MIN@
say() { echo "SPA $*"; echo "SPA $*" >/dev/console; }
results=/root/spa-results
mkdir -p "$results"
# finish: results up, then DONE. The console is read every 20 s from
# outside: stay up long enough after the last line for it to be read.
finish() {
  journalctl -u sandboxd --no-pager 2>/dev/null | gzip -c >"$results/sandboxd-journal.log.gz"
  dmesg 2>/dev/null | tail -400 >"$results/dmesg-tail.txt"
  cp /var/log/spa.log "$results/" 2>/dev/null
  cp /root/spa-*.json "$results/" 2>/dev/null
  tar -czf /root/spa-results.tgz -C /root spa-results
  if curl -fsS --retry 3 -X PUT -T /root/spa-results.tgz '@RESULTS_URL@' -o /dev/null; then
    say "results uploaded ($(stat -c %s /root/spa-results.tgz) bytes)"
  else
    say "results upload FAILED"
  fi
  say "DONE"
  sync
  sleep 90
  poweroff
}
export HOME=/root DEBIAN_FRONTEND=noninteractive
cd /root || exit 0
imds() {
  local t
  t="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
  curl -fsS -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/$1"
}
say "start leg @LEG@ $(date -u +%FT%TZ) on $(imds instance-type); kernel $(uname -r); $(nproc) cpus, $(grep -c -w vmx /proc/cpuinfo) with vmx; cpu:$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
[ -e /dev/kvm ] || modprobe kvm_intel
if [ ! -e /dev/kvm ]; then say "/dev/kvm ABSENT"; finish; exit 0; fi
say "host kvm: nested=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null) ept=$(cat /sys/module/kvm_intel/parameters/ept 2>/dev/null) hypervisor-flag=$(grep -c -m1 -w hypervisor /proc/cpuinfo)"

# The source and the kit, each checked against the SHA-256 spa.sh took.
fetch() { # <file> <url> <sha256>
  curl -fsS --retry 5 --retry-all-errors -o "$1" "$2" && echo "$3  $1" | sha256sum -c --quiet -
}
if ! fetch src.tgz '@SRC_URL@' '@SRC_SHA@' || ! fetch kit.tgz '@KIT_URL@' '@KIT_SHA@'; then
  say "staging download FAILED or checksum wrong"; finish; exit 0
fi
mkdir -p src kit && tar -xzf src.tgz -C src && tar -xzf kit.tgz -C kit
# @PATCH@ is "none" except on the opt-in redial leg: the proposed handshake
# redial (spa-redial.patch), on this throwaway build only.
if [ '@PATCH@' = redial ]; then
  if (cd src && git apply --check ../kit/spa-redial.patch && git apply ../kit/spa-redial.patch); then
    say "patch: spa-redial.patch applied to this build only"
  else
    say "patch: spa-redial.patch does NOT apply to this commit; the leg stops"; finish; exit 0
  fi
fi
gov="$(awk '/^go /{print $2; exit}' src/go.mod)"
curl -fsSL --retry 5 "https://go.dev/dl/go${gov}.linux-amd64.tar.gz" | tar -C /usr/local -xz
export PATH=/usr/local/go/bin:$PATH GOFLAGS=-buildvcs=false
openssl rand -hex 24 >/root/pat && chmod 600 /root/pat
t0=$(date +%s)
if ! (cd src && ./scripts/install.sh --with-firecracker --public-host 127.0.0.1 --pat-token "$(cat /root/pat)" --build-from-source); then
  say "install FAILED; last lines:"; tail -20 /var/log/spa.log | sed 's/^/SPA   /' >/dev/console; finish; exit 0
fi
say "install done in $(( $(date +%s) - t0 ))s; $(/usr/local/bin/firecracker --version 2>&1 | head -1); kernel files: $(ls /var/lib/sandboxd/firecracker/ | tr '\n' ' ')"

# Only SPA lines go to the console (it keeps its last 64 KB); the rest is
# in the results.
bench() {
  python3 kit/spa-bench.py "$@" 2>&1 | while IFS= read -r l; do
    echo "$l"
    case "$l" in SPA*) echo "$l" >/dev/console ;; esac
  done
}
bench base --samples @SAMPLES@ --cycles @CYCLES@ --idle-cycles @IDLE_CYCLES@ --leg @LEG@

# The warm VMM pool: off by default (ship-dark), on here for the warm row.
# The template spa-bench.py base built is the pool's input.
printf 'SB_FIRECRACKER_VMM_POOL_ENABLED=true\nSB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT=4\n' >>/etc/sandboxd/sandboxd.env
systemctl restart sandboxd
bench warm --samples @SAMPLES@ --depth 4 --leg @LEG@
# A warm spawn that failed: the first one, in short (the full log is in
# the results).
journalctl -u sandboxd --no-pager 2>/dev/null | grep -m1 'vmm pool: spawn failed' | grep -o 'error=.*' | cut -c1-400 | sed 's/^/SPA   warm spawn: /' >/dev/console
finish
