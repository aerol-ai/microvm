#!/bin/bash
# spb-run.sh: SP-B's second boot (plans/security-gaps-m1-m4.md §4.2), run
# once by spb-run.service after spb-userdata.sh reserved the Nitro memory
# pool. Builds the tools (spb-setup.sh), runs each step in /opt/spb/steps
# (spb.py), prints the verdicts, PUTs the results to S3 and powers off,
# which terminates the machine. SPB lines go to the serial console, which
# spb.sh reads; everything else to /var/log/spb.log.
exec >>/var/log/spb.log 2>&1
rm -f /etc/spb-second-boot
say() { echo "SPB $*"; echo "SPB $*" >/dev/console; }
finish() {
  python3 /opt/spb/kit/spb.py verdict 2>&1 | grep '^SPB ' | while IFS= read -r l; do echo "$l" >/dev/console; done
  mkdir -p /root/spb-out
  cp /root/spb-results.jsonl /root/spb-doc-*.b64 /root/meminfo-nopool.txt /var/log/spb.log /root/spb-out/ 2>/dev/null
  # sandboxd's log and setup log, with the admin token masked.
  for f in /var/log/sandboxd.log /root/spb-sandboxd-setup.log; do
    [ -s "$f" ] && sed "s/$(cat /root/pat 2>/dev/null || echo NOPAT)/<pat>/g" "$f" | gzip -c >"/root/spb-out/$(basename "$f").gz"
  done
  dmesg | tail -300 >/root/spb-out/dmesg-tail.txt
  tar -czf /root/spb-results.tgz -C /root spb-out
  if curl -fsS --retry 3 -X PUT -T /root/spb-results.tgz "$(cat /opt/spb/results-url)" -o /dev/null; then
    say "results uploaded ($(stat -c %s /root/spb-results.tgz) bytes)"
  else
    say "results upload FAILED"
  fi
  say "DONE"
  sync
  sleep 90
  poweroff
}
trap finish EXIT
ne=/sys/class/misc/nitro_enclaves
say "second boot $(date -u +%FT%TZ); kernel $(uname -r); cmdline pool: $(grep -o 'nitro_enclaves.mempool=[^ ]*' /proc/cmdline)"
say "nitro: device $(ls -l /dev/nitro_enclaves 2>&1 | cut -c1-60); pcie_slots_total $(cat $ne/pcie_slots_total 2>&1); mem_pool/total $(cat $ne/mem_pool/total 2>&1); cpu_pool/total $(cat $ne/cpu_pool/total 2>&1)"
# AWS's minimum parent kernel for Nitro Sandboxes (Firecracker
# docs/nitro-sandboxes/getting-started.md).
if ! printf '%s\n%s\n' 6.18.51-120.162 "$(uname -r | sed 's/\.amzn2023.*//')" | sort -V -C; then
  say "kernel $(uname -r) is older than 6.18.51-120.162: the steps may fail"
fi
t0=$(date +%s)
if ! bash /opt/spb/kit/spb-setup.sh /opt/spb/src /opt/spb/kit >/root/spb-setup.log 2>&1; then
  say "setup FAILED; last lines:"
  tail -15 /root/spb-setup.log | cut -c1-240 | sed 's/^/SPB   /' >/dev/console
  cp /root/spb-setup.log /var/log/ 2>/dev/null
  exit 0
fi
say "setup done in $(( $(date +%s) - t0 ))s: $(tail -1 /root/spb-setup.log | cut -c1-300)"
cd /opt/spb/kit || exit 0
spb() { # spb.py with its SPB lines on the console, at most 20 min a step
  timeout 1200 python3 spb.py "$@" 2>&1 | while IFS= read -r l; do
    echo "$l"
    case "$l" in SPB*) echo "$l" | cut -c1-3000 >/dev/console ;; esac
  done
  say "step $1 ended ($(date -u +%T))"
}
for step in $(cat /opt/spb/steps); do
  case "$step" in
    step1) spb step1 --samples 20 ;;
    step2) spb step2 ;;
    step3a) spb step3a --samples 10 ;;
    step3b) spb step3b ;;
    step4) spb step4 --count 50 --vcpus 1 --mem 256 ;;
    step5) spb step5 ;;
    step6) spb step6 ;;
    parked) spb parked --samples 12 ;;
    sandboxd)
      # AerolVM's own sandboxd on the Nitro backend (plan §4.3).
      if bash /opt/spb/kit/spb-sandboxd.sh /opt/spb/src /opt/spb/kit >/root/spb-sandboxd-setup.log 2>&1; then
        say "sandboxd setup: $(tail -1 /root/spb-sandboxd-setup.log | cut -c1-300)"
        spb sandboxd --samples 10
      else
        say "sandboxd setup FAILED; last lines:"
        tail -15 /root/spb-sandboxd-setup.log | sed "s/$(cat /root/pat 2>/dev/null || echo NOPAT)/<pat>/g" | cut -c1-240 | sed 's/^/SPB   /' >/dev/console
      fi
      ;;
    probe-*) spb probe --what "${step#probe-}" ;;
    *) say "unknown step $step" ;;
  esac
done
python3 spb.py clean
