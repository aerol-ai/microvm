#!/bin/bash
# userdata.sh: spike S6 on one EC2 instance with nested virtualization.
# Everything is printed to the serial console, which s6.py reads; the
# instance needs no SSH and no inbound rule. It powers itself off after 40
# minutes in case nobody terminates it (shutdown behaviour: terminate).
exec > >(tee /dev/console) 2>&1
shutdown -h +40
cd /root
echo "S6: kernel $(uname -r); cpu:$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
echo "S6: cpus with the vmx flag: $(grep -c -w vmx /proc/cpuinfo) of $(nproc)"
[ -e /dev/kvm ] || modprobe kvm_intel 2>&1 | sed 's/^/S6: modprobe: /'
if [ -e /dev/kvm ]; then echo "S6: /dev/kvm: present ($(stat -c '%t:%T' /dev/kvm))"; else echo "S6: /dev/kvm: ABSENT"; echo S6-DONE; exit 0; fi
dnf -y -q install e2fsprogs >/dev/null 2>&1
arch=x86_64
rel="$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/firecracker-microvm/firecracker/releases/latest)")"
curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/$rel/firecracker-$rel-$arch.tgz" | tar -xz
fc="release-$rel-$arch/firecracker-$rel-$arch"
# Firecracker's CI publishes guest kernels per minor version, and lags the
# releases (first S6 run: v1.18 had none, so no kernel was fetched and every
# boot failed at once). Take the newest CI version that has one.
bucket=http://spec.ccfc.min.s3.amazonaws.com
key=""
for ci in $(curl -fsSL "$bucket/?prefix=firecracker-ci/&delimiter=/&list-type=2" | grep -oP '(?<=<Prefix>firecracker-ci/)v1\.[0-9]+(?=/</Prefix>)' | sort -Vr); do
  key="$(curl -fsSL "$bucket/?prefix=firecracker-ci/$ci/$arch/vmlinux-&list-type=2" | grep -oP "(?<=<Key>)(firecracker-ci/$ci/$arch/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" | sort -V | tail -1)"
  [ -n "$key" ] && break
done
[ -n "$key" ] || { echo "S6: no guest kernel found in Firecracker's CI bucket"; echo S6-DONE; exit 0; }
curl -fsSL -o vmlinux "https://s3.amazonaws.com/spec.ccfc.min/$key"
# A tiny root disk: static busybox and an init that prints a marker on the
# serial port and reboots, which ends the Firecracker process. A disk, not an
# initrd: Firecracker's CI kernels are built for a root disk on virtio-blk.
mkdir -p root/bin root/dev root/proc
curl -fsSL -o root/bin/busybox https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
chmod +x root/bin/busybox
printf '#!/bin/busybox sh\n/bin/busybox mount -t devtmpfs dev /dev\n/bin/busybox echo S6-GUEST-BOOTED > /dev/ttyS0\n/bin/busybox reboot -f\n' > root/init
chmod +x root/init
mkfs.ext4 -q -d root rootfs.ext4 32M
echo "S6: firecracker $rel; kernel ${key##*/}"
cat > vm.json <<JSON
{"boot-source": {"kernel_image_path": "vmlinux",
  "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet init=/init"},
 "drives": [{"drive_id": "rootfs", "path_on_host": "rootfs.ext4", "is_root_device": true, "is_read_only": false}],
 "machine-config": {"vcpu_count": 1, "mem_size_mib": 256}}
JSON
for i in 1 2 3 4 5; do
  t0=$(date +%s%N)
  out="$(timeout 60 "./$fc" --no-api --config-file vm.json 2>&1)"
  t1=$(date +%s%N)
  booted=no; echo "$out" | grep -q S6-GUEST-BOOTED && booted=yes
  echo "S6: boot $i: $(( (t1 - t0) / 1000000 )) ms from start to the guest's reboot; guest printed its marker: $booted"
  # A boot that printed no marker: show why, once.
  if [ "$booted" = no ] && [ "$i" = 1 ]; then echo "$out" | tail -5 | sed 's/^/S6: firecracker said: /'; fi
done
echo S6-DONE
