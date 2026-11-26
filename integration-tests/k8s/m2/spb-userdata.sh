#!/bin/bash
# spb-userdata.sh: SP-B's first boot (plans/security-gaps-m1-m4.md §4.2), an
# Amazon Linux 2023 kernel-6.18 machine launched with Nitro Enclaves on;
# rendered by spb.sh. It sets a power-off deadline that holds across the
# reboot, records memory with no Nitro pool (step 5's baseline), fetches
# the source and the kit and checks their SHA-256, installs spb-run.sh as a
# unit for the second boot, reserves the pool (nitro_enclaves.mempool=@POOL@)
# and reboots once. Powering off terminates the machine.
exec >>/var/log/spb.log 2>&1
say() { echo "SPB $*"; echo "SPB $*" >/dev/console; }
stop() { say "$*"; say "DONE"; sync; sleep 90; poweroff; exit 0; }
deadline=$(( $(date +%s) + @TTL_MIN@ * 60 ))
echo "$deadline" >/etc/spb-deadline
cat >/usr/local/sbin/spb-deadline <<'SH'
#!/bin/sh
left=$(( ($(cat /etc/spb-deadline) - $(date +%s)) / 60 ))
[ "$left" -gt 1 ] || left=1
shutdown -h +"$left"
SH
chmod 755 /usr/local/sbin/spb-deadline
cat >/etc/systemd/system/spb-deadline.service <<'UNIT'
[Unit]
Description=SP-B power-off deadline (re-armed on every boot)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/spb-deadline
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now spb-deadline.service
say "first boot $(date -u +%FT%TZ); kernel $(uname -r); $(nproc) cpus; /dev/nitro_enclaves: $(ls -l /dev/nitro_enclaves 2>&1)"
grep -E '^(MemTotal|MemFree|MemAvailable|CmaTotal|CmaFree):' /proc/meminfo | tr -s ' ' | tee /root/meminfo-nopool.txt | sed 's/^/SPB nopool /' >/dev/console
dnf -y -q install nftables e2fsprogs python3-pip python3-cryptography jq tar gzip cpio xz zstd >/dev/null 2>&1 || say "dnf install had errors"
pip3 -q install cbor2 >/dev/null 2>&1 || say "pip install cbor2 failed (step 3b cannot check the document)"

mkdir -p /opt/spb && cd /opt/spb || stop "no /opt/spb"
fetch() { # <file> <url> <sha256>
  curl -fsS --retry 5 --retry-all-errors -o "$1" "$2" && echo "$3  $1" | sha256sum -c --quiet -
}
if ! fetch src.tgz '@SRC_URL@' '@SRC_SHA@' || ! fetch kit.tgz '@KIT_URL@' '@KIT_SHA@'; then
  stop "staging download FAILED or checksum wrong"
fi
mkdir -p src kit && tar -xzf src.tgz -C src && tar -xzf kit.tgz -C kit || stop "unpack failed"
printf '%s\n' '@RESULTS_URL@' >/opt/spb/results-url
chmod 600 /opt/spb/results-url
printf '%s\n' '@STEPS@' >/opt/spb/steps
install -m 0755 kit/spb-run.sh /usr/local/sbin/spb-run
cat >/etc/systemd/system/spb-run.service <<'UNIT'
[Unit]
Description=SP-B steps (second boot)
After=network-online.target spb-deadline.service
Wants=network-online.target
ConditionPathExists=/etc/spb-second-boot
[Service]
# simple, not oneshot: the boot target does not wait the run out.
Type=simple
ExecStart=/usr/local/sbin/spb-run
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable spb-run.service
grubby --update-kernel=ALL --args="nitro_enclaves.mempool=@POOL@" || stop "grubby failed"
say "pool argument set: $(grubby --info=DEFAULT | grep ^args)"
touch /etc/spb-second-boot
say "rebooting"
sync
reboot
