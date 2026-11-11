#!/bin/sh
# gvisor-node.sh: puts gVisor into the machine's own containerd, as
# agent-sandbox's gVisor examples have you do (it installs no runtime itself).
# Runs in a privileged DaemonSet pod with the machine's root at /host.
set -eu
dnf -y -q install tar bzip2 findutils util-linux >/dev/null
base=https://storage.googleapis.com/gvisor/releases/release/latest/x86_64
cd /tmp
curl -fsSL -o g.tar.bz2 "$base/gvisor.tar.bz2"
curl -fsSL -o g.sha512 "$base/gvisor.tar.bz2.sha512"
echo "$(cut -d' ' -f1 g.sha512)  g.tar.bz2" | sha512sum -c --quiet -
mkdir g && tar -xjf g.tar.bz2 -C g
runsc="$(find g -type f -name runsc | head -1)"
install -m 0755 "$runsc" /host/usr/local/bin/runsc
install -m 0755 "$(find g -type f -name containerd-shim-runsc-v1 | head -1)" /host/usr/local/bin/containerd-shim-runsc-v1
if [ -d "$(dirname "$runsc")/gvisor-bin" ]; then
  mkdir -p /host/usr/local/bin/gvisor-bin
  find "$(dirname "$runsc")/gvisor-bin" -maxdepth 1 -type f -exec install -m 0755 {} /host/usr/local/bin/gvisor-bin/ \;
fi
cfg=/host/etc/containerd/config.toml
# containerd 2's config (version 3) and 1.7's (version 2) name the CRI
# plugin differently.
cri='io.containerd.grpc.v1.cri'
grep -Eq '^version *= *3' "$cfg" && cri='io.containerd.cri.v1.runtime'
if ! grep -q 'runtimes.runsc' "$cfg"; then
  printf '\n[plugins."%s".containerd.runtimes.runsc]\n  runtime_type = "io.containerd.runsc.v1"\n' "$cri" >> "$cfg"
  nsenter -t 1 -m -u -i -n -p -- systemctl restart containerd
fi
echo "gvisor-node: runsc $(/host/usr/local/bin/runsc --version | head -1) in the machine's containerd"
sleep infinity
