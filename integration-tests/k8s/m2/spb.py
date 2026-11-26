#!/usr/bin/env python3
"""spb.py: spike SP-B (plans/security-gaps-m1-m4.md §4.2) on a machine
launched with Nitro Enclaves on, after spb-setup.sh. Run as root
(spb-run.sh runs it on the machine's second boot).

Each VM is started the way AerolVM starts one: the jailer with
internal/runtime/firecracker/jailer.go jailerArgv's argv, then the REST
calls configureVMM makes (machine config, boot source, root drive, TAP,
vsock), plus PUT /enclave before InstanceStart. Readiness is AerolVM's
handshake: "CONNECT 1024" on the vsock socket and {"op":"ping"} answered
by toolboxd in the guest.

    spb.py step1 [--samples N]     boot to toolboxd ping, direct mode
    spb.py step2                   TAP networking under an nft rule on the TAP
    spb.py step3a [--samples N]    confidential mode, same disk and kernel
    spb.py step3b --kernel K --initrd I   attestation from /dev/nsm, verified
    spb.py step4 [--count N] [--mem M] [--vcpus V]   N creates at once
    spb.py step5                   does the parent use the pool's memory?
    spb.py step6                   does the guest see a vmgenid device?
    spb.py parked [--samples N]    parked VMs: time a claim (adopt + set_env)
    spb.py probe --what ...        one-off checks (AerolVM's own boot args etc.)
    spb.py clean                   kill every VM, remove TAPs and chroots
    spb.py verdict [--results F]   plan §4.2's bars, read from the results

Prints "SPB ..." lines and appends JSON results to /root/spb-results.jsonl.
"""
import argparse
import base64
import concurrent.futures as cf
import glob
import hashlib
import http.client
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time

D = "/opt/spb"
JAIL = "/srv/jailer"
FC = "/usr/local/bin/firecracker"
JAILER = "/usr/local/bin/jailer"
NE = "/sys/class/misc/nitro_enclaves"
RESULTS = "/root/spb-results.jsonl"
TOKEN = "spb-" + hashlib.sha256(os.urandom(16)).hexdigest()[:32]
# AerolVM's base boot args for amd64 (driver.go baseBootArgsAMD64) carry
# pci=off; a Nitro guest is PCIe only, so they are left out here (probe
# --what pci-off shows what they do).
BOOT_BASE = "console=ttyS0 reboot=k panic=1 nomodules quiet ipv6.disable_ipv6=1"


def say(*parts):
    print("SPB", *parts, flush=True)


def record(step, data):
    data = dict(data, step=step, at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    with open(RESULTS, "a") as f:
        f.write(json.dumps(data) + "\n")
    say("RESULT", json.dumps(data, separators=(",", ":")))


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, max(0, int(p / 100 * (len(s) - 1) + 0.5)))], 1)


def stats(values):
    return {"n": len(values), "p50_ms": pct(values, 50), "p90_ms": pct(values, 90), "p99_ms": pct(values, 99),
            "min_ms": round(min(values), 1) if values else None, "max_ms": round(max(values), 1) if values else None}


def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("%s: %s" % (cmd, r.stderr.strip()))
    return r.stdout.strip()


def sysfs(name):
    try:
        return open(os.path.join(NE, name)).read().strip()
    except OSError as e:
        return "?(%s)" % e.strerror


def ne_state():
    return {k: sysfs(k) for k in ("pcie_slots", "pcie_slots_total", "pcie_slots_in_use", "cpu_pool/total",
                                  "cpu_pool/in_use", "cpu_pool/free", "mem_pool/total", "mem_pool/in_use", "mem_pool/free")}


def meminfo():
    out = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":", 1)
        if k in ("MemTotal", "MemFree", "MemAvailable", "CmaTotal", "CmaFree", "AnonPages", "Cached"):
            out[k] = int(v.split()[0]) // 1024
    return out


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        self.sock = s


def readline(s):
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(1)
        if not c:
            raise ConnectionError("EOF after %r" % buf)
        buf += c
    return buf.decode().strip()


class VM:
    """One Nitro Sandbox started the way AerolVM's driver starts a VM."""

    def __init__(self, idx, mode="direct", vcpus=1, mem=512, dedicated=False, debug=False,
                 kernel="bzImage", rootfs="rootfs.ext4", initrd=None, boot_args=None,
                 net=True, vsock=True, machine_extra=None, drive_extra=None):
        self.idx, self.mode, self.vcpus, self.mem = idx, mode, vcpus, mem
        self.dedicated, self.debug, self.net, self.vsock = dedicated, debug, net, vsock
        self.kernel, self.rootfs, self.initrd = kernel, rootfs, initrd
        self.machine_extra, self.drive_extra = machine_extra or {}, drive_extra or {}
        self.id = "spb-%d" % idx
        self.tap = "fctap%d" % idx
        a = idx * 4
        self.host_ip = "172.16.%d.%d" % (a // 256, a % 256 + 1)
        self.guest_ip = "172.16.%d.%d" % (a // 256, a % 256 + 2)
        self.cid = 3 + idx
        self.dir = os.path.join(JAIL, "firecracker", self.id)
        self.root = os.path.join(self.dir, "root")
        self.boot_args = boot_args if boot_args is not None else (
            "%s ip=%s::%s:255.255.255.252::eth0:off init=/usr/local/bin/toolboxd-init" % (BOOT_BASE, self.guest_ip, self.host_ip))
        self.proc = None
        self.t = {}
        self.error = None
        u = pwd.getpwnam("sandboxd-jailer")
        self.uid, self.gid = u.pw_uid, u.pw_gid

    # Not timed: what AerolVM's create does before it spawns (TAP slot,
    # rootfs build) has its own numbers in SP-A.
    def prepare(self):
        self.destroy(quiet=True)
        os.makedirs(self.root)
        os.link(os.path.join(D, self.kernel), os.path.join(self.root, "kernel"))
        if self.rootfs:
            sh("cp --reflink=auto %s %s" % (os.path.join(D, self.rootfs), os.path.join(self.root, "rootfs.ext4")))
        if self.initrd:
            shutil.copy(os.path.join(D, self.initrd), os.path.join(self.root, "initrd"))
        sh("chown -R %d:%d %s" % (self.uid, self.gid, self.dir))
        if self.net:
            sh("ip tuntap add dev %s mode tap user %d group %d" % (self.tap, self.uid, self.gid))
            sh("sysctl -qw net.ipv6.conf.%s.disable_ipv6=1" % self.tap, check=False)
            sh("ip addr add %s/30 dev %s && ip link set %s up" % (self.host_ip, self.tap, self.tap))

    def api(self, method, path, body):
        c = UnixHTTP(os.path.join(self.root, "api.socket"))
        c.request(method, path, body=json.dumps(body), headers={"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read().decode()
        c.close()
        if r.status >= 300:
            raise RuntimeError("%s %s -> %d %s" % (method, path, r.status, data.strip()[:400]))
        return data

    def start(self, wait_ready=True, ready_timeout=60):
        """Process start to toolboxd's ping ack. Returns True on success."""
        log = open(os.path.join(self.dir, "fc.log"), "w")
        t0 = time.monotonic()
        # jailer.go jailerArgv, verbatim.
        argv = [JAILER, "--id", self.id, "--exec-file", FC, "--uid", str(self.uid), "--gid", str(self.gid),
                "--chroot-base-dir", JAIL, "--", "--api-sock", "api.socket"]
        # Output to a file, never a pipe (the EPIPE wedge in the gotchas).
        self.proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True)
        sock = os.path.join(self.root, "api.socket")
        try:
            while True:
                if os.path.exists(sock):
                    try:
                        s = socket.socket(socket.AF_UNIX)
                        s.connect(sock)
                        s.close()
                        break
                    except OSError:
                        pass
                if self.proc.poll() is not None:
                    raise RuntimeError("jailer/firecracker exited %s before its API socket" % self.proc.returncode)
                if time.monotonic() - t0 > 10:
                    raise RuntimeError("no API socket after 10 s")
                time.sleep(0.001)
            self.t["api_socket_ms"] = (time.monotonic() - t0) * 1000
            mc = {"vcpu_count": self.vcpus, "mem_size_mib": self.mem}
            mc.update(self.machine_extra)
            self.api("PUT", "/machine-config", mc)
            bs = {"kernel_image_path": "kernel", "boot_args": self.boot_args}
            if self.initrd:
                bs["initrd_path"] = "initrd"
            self.api("PUT", "/boot-source", bs)
            if self.rootfs:
                drv = {"drive_id": "rootfs", "path_on_host": "rootfs.ext4", "is_root_device": True,
                       "is_read_only": False, "cache_type": "Writeback"}
                drv.update(self.drive_extra)
                self.api("PUT", "/drives/rootfs", drv)
            if self.net:
                mac = "06:00:%02x:%02x:%02x:%02x" % tuple(int(x) for x in self.guest_ip.split("."))
                self.api("PUT", "/network-interfaces/eth0", {"iface_id": "eth0", "host_dev_name": self.tap, "guest_mac": mac})
            if self.vsock:
                self.api("PUT", "/vsock", {"guest_cid": self.cid, "uds_path": "v.sock"})
            if self.debug:
                self.api("PUT", "/serial", {"serial_out_path": "serial.out"})
            enc = {"direct_mode": self.mode == "direct", "debug_mode": self.debug, "cpu_overcommit": not self.dedicated}
            self.api("PUT", "/enclave", enc)
            self.t["configure_ms"] = (time.monotonic() - t0) * 1000 - self.t["api_socket_ms"]
            t1 = time.monotonic()
            self.api("PUT", "/actions", {"action_type": "InstanceStart"})
            self.t["instance_start_ms"] = (time.monotonic() - t1) * 1000
            if not wait_ready:
                return True
            t2 = time.monotonic()
            self.vsock_op("ping", None, deadline=time.monotonic() + ready_timeout)
            self.t["boot_to_ping_ms"] = (time.monotonic() - t2) * 1000
            self.t["total_ms"] = (time.monotonic() - t0) * 1000
            return True
        except Exception as e:
            self.error = str(e)
            return False

    def vsock_op(self, op, data, deadline=None, attempts_out=None):
        """AerolVM's vsock op (snapshot.go openVsockOpWithin): CONNECT 1024,
        one JSON line, one JSON ack. Retries until deadline while the guest
        is not listening yet."""
        deadline = deadline or time.monotonic() + 10
        last = None
        n = 0
        while time.monotonic() < deadline:
            n += 1
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5)
            try:
                s.connect(os.path.join(self.root, "v.sock"))
                s.sendall(b"CONNECT 1024\n")
                ok = readline(s)
                if not ok.startswith("OK"):
                    raise ConnectionError(ok)
                msg = {"op": op}
                if data is not None:
                    msg["data"] = data
                s.sendall((json.dumps(msg) + "\n").encode())
                ack = json.loads(readline(s))
                if attempts_out is not None:
                    attempts_out.append(n)
                if not ack.get("ok"):
                    raise RuntimeError("guest refused %s: %s" % (op, ack))
                return ack
            except (OSError, ConnectionError, ValueError) as e:
                last = e
                time.sleep(0.005)
            finally:
                s.close()
            if self.proc is not None and self.proc.poll() is not None:
                raise RuntimeError("firecracker exited %s while waiting for the guest" % self.proc.returncode)
        raise TimeoutError("vsock %s: no ack by the deadline (last: %s)" % (op, last))

    def adopt(self):
        self.vsock_op("adopt", {"sandbox_id": self.id, "token": TOKEN})

    def exec(self, command, timeout=60):
        c = http.client.HTTPConnection(self.guest_ip, 2280, timeout=timeout)
        c.request("POST", "/process/execute", body=json.dumps({"command": command}),
                  headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
        r = c.getresponse()
        body = r.read().decode()
        c.close()
        try:
            js = json.loads(body)
        except ValueError:
            js = {"raw": body[:300]}
        js["http"] = r.status
        return js

    def fc_log(self, n=8):
        try:
            return open(os.path.join(self.dir, "fc.log")).read().strip().splitlines()[-n:]
        except OSError:
            return []

    def serial(self, n=40):
        try:
            return open(os.path.join(self.root, "serial.out"), errors="replace").read().strip().splitlines()[-n:]
        except OSError:
            return []

    def destroy(self, quiet=False):
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except OSError:
                pass
            self.proc.wait()
        # [f]: the pattern must not match the shell running pgrep.
        for p in sh("pgrep -f '[f]irecracker --id %s ' || true" % self.id, check=False).split():
            sh("kill -9 %s" % p, check=False)
        shutil.rmtree(self.dir, ignore_errors=True)
        if self.net:
            sh("ip link del %s 2>/dev/null" % self.tap, check=False)


def ensure_slots(n):
    """A fresh parent holds 4 sandboxes; each raise of pcie_slots donates
    128 MiB of the pool per 8 slots, and only a reboot gives it back."""
    try:
        if int(sysfs("pcie_slots")) < n:
            open(os.path.join(NE, "pcie_slots"), "w").write(str(n))
    except (OSError, ValueError) as e:
        say("pcie_slots write %d: %s" % (n, e))
    return sysfs("pcie_slots")


def clean():
    sh("pkill -9 -f '[j]ailer --id spb-|[f]irecracker --id spb-' || true", check=False)
    time.sleep(0.5)
    shutil.rmtree(os.path.join(JAIL, "firecracker"), ignore_errors=True)
    for tap in os.listdir("/sys/class/net"):
        if tap.startswith("fctap"):
            sh("ip link del %s" % tap, check=False)
    sh("nft delete table inet spbfw 2>/dev/null || true", check=False)


def boot_series(label, n, **kw):
    """n VMs one after another, each to its ping ack, then destroyed."""
    rows, fails = [], []
    for i in range(n):
        vm = VM(i, **kw)
        vm.prepare()
        ok = vm.start()
        if ok:
            rows.append(vm.t)
        else:
            fails.append(vm.error)
            say("%s sample %d failed: %s; fc.log: %s; serial: %s" % (label, i, vm.error, vm.fc_log(4), vm.serial(6)))
        vm.destroy()
        if len(fails) >= 3 and not rows:
            break
    out = {"label": label, "samples": len(rows), "failures": len(fails), "errors": fails[:3], "config": {
        k: v for k, v in kw.items() if k in ("mode", "vcpus", "mem", "dedicated", "debug", "kernel")}}
    for key in ("api_socket_ms", "configure_ms", "instance_start_ms", "boot_to_ping_ms", "total_ms"):
        out[key] = stats([r[key] for r in rows if key in r])
    return out


def step1(a):
    say("step1: %d boots, direct mode, 1 vCPU (cpu_overcommit), 512 MiB, jailer argv as AerolVM" % a.samples)
    res = boot_series("direct, overcommit, 1 vCPU", a.samples, mode="direct", vcpus=1, mem=512)
    record("step1-direct-overcommit-1vcpu", res)
    res = boot_series("direct, dedicated core, 2 vCPU", max(5, a.samples // 4), mode="direct", vcpus=2, mem=512, dedicated=True)
    record("step1-direct-dedicated-2vcpu", res)


def step3a(a):
    say("step3a: confidential mode, CI kernel (DMB patches), the same toolboxd disk")
    res = boot_series("confidential, overcommit, 1 vCPU", a.samples, mode="confidential", vcpus=1, mem=512)
    record("step3a-confidential-ci-kernel", res)


def step2(a):
    say("step2: TAP networking with an nft rule on the TAP")
    vm = VM(0)
    vm.prepare()
    if not vm.start():
        record("step2", {"ok": False, "error": vm.error, "fc_log": vm.fc_log()})
        return
    vm.adopt()
    srv = subprocess.Popen(["python3", "-m", "http.server", "8088", "--bind", vm.host_ip], cwd="/tmp",
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    probe = ("wget -q -T 4 -O /dev/null http://%s:8088/ && echo host-port-ok || echo host-port-blocked; "
             "wget -q -T 4 -O - http://checkip.amazonaws.com 2>/dev/null | head -c 20 | sed 's/^/internet-ok /' || true; "
             "echo; ip -4 addr show eth0 | grep inet" % vm.host_ip)
    before = vm.exec(probe)
    # The two shapes of AerolVM's rules: the per-guest egress chain on
    # forwarded traffic, and the node guard on traffic to the host itself.
    sh("""nft -f - <<'NFT'
table inet spbfw {
  chain guest_fwd { type filter hook forward priority -10; iifname "%s" tcp dport 80 counter drop; }
  chain guest_in { type filter hook input priority -10; iifname "%s" tcp dport 8088 counter drop; }
}
NFT""" % (vm.tap, vm.tap))
    after = vm.exec(probe)
    counters = sh("nft list table inet spbfw | grep -E 'drop'", check=False)
    sh("nft delete table inet spbfw", check=False)
    restored = vm.exec(probe)
    srv.terminate()
    record("step2", {"ok": True, "before": before.get("stdout", before), "with_nft_rules": after.get("stdout", after),
                     "rules": counters, "rules_removed": restored.get("stdout", restored)})
    vm.destroy()


def step6(a):
    say("step6: vmgenid in the guest (CI kernel has CONFIG_VMGENID=y)")
    out = {}
    for mode in ("direct", "confidential"):
        vm = VM(0, mode=mode)
        vm.prepare()
        if not vm.start():
            out[mode] = {"error": vm.error}
            vm.destroy()
            continue
        vm.adopt()
        r = vm.exec("ls /sys/bus/acpi/devices/ | tr '\\n' ' '; echo; echo DRIVER:; ls /sys/bus/acpi/drivers/vmgenid/ 2>&1 | tr '\\n' ' '; "
                    "echo; dmesg | grep -iE 'vmgen|VMGENCTR|QEMUVGID' ; echo; uname -r; cat /proc/cmdline")
        out[mode] = r.get("stdout", r)
        vm.destroy()
    record("step6", out)


def step4(a):
    say("step4: %d creates at once, %d vCPU each (cpu_overcommit), %d MiB, direct mode" % (a.count, a.vcpus, a.mem))
    # pcie_slots cannot pass pcie_slots_total (5 per parent vCPU).
    try:
        total = int(sysfs("pcie_slots_total"))
    except ValueError:
        total = a.count + 8
    ensure_slots(a.slots or min(a.count + 8, total))
    before = ne_state()
    vms = [VM(i, vcpus=a.vcpus, mem=a.mem) for i in range(a.count)]
    for vm in vms:
        vm.prepare()
    t0 = time.monotonic()
    with cf.ThreadPoolExecutor(max_workers=a.count) as ex:
        oks = list(ex.map(lambda v: v.start(ready_timeout=120), vms))
    wall = (time.monotonic() - t0) * 1000
    during = ne_state()
    ok = [v for v, k in zip(vms, oks) if k]
    errs = {}
    for v, k in zip(vms, oks):
        if not k:
            key = (v.error or "?")[:260]
            errs.setdefault(key, []).append(v.idx)
    # Every running guest still answers, after all of them started.
    alive = 0
    for v in ok:
        try:
            v.vsock_op("ping", None, deadline=time.monotonic() + 5)
            alive += 1
        except Exception:
            pass
    res = {"count": a.count, "vcpus": a.vcpus, "mem": a.mem, "started": len(ok), "alive_after": alive,
           "wall_ms": round(wall), "total_ms_of_started": stats([v.t["total_ms"] for v in ok if "total_ms" in v.t]),
           "instance_start_ms_of_started": stats([v.t["instance_start_ms"] for v in ok if "instance_start_ms" in v.t]),
           "errors": {k: {"count": len(v), "first_idx": v[:5]} for k, v in errs.items()},
           "nitro_before": before, "nitro_during": during, "parent_cpus": os.cpu_count()}
    for v in vms:
        v.destroy()
    res["nitro_after"] = ne_state()
    record("step4-%dx%dvcpu-%dmib" % (a.count, a.vcpus, a.mem), res)


def step5(a):
    say("step5: does the parent use the pool's memory while no VM runs?")
    base = meminfo()
    pool = ne_state()
    # Allocate (and touch) all but ~1.5 GiB of what the parent says it has.
    mib = max(256, base["MemAvailable"] - 1536)
    hog = subprocess.Popen(["python3", "-c", """
import sys, time
n = int(sys.argv[1]) << 20
b = bytearray(n)
for i in range(0, n, 4096):
    b[i] = 1
print("allocated", flush=True)
time.sleep(3600)
""", str(mib)], stdout=subprocess.PIPE, text=True)
    line = hog.stdout.readline().strip()
    held = meminfo()
    # A VM now: its memory must come out of the CMA pool the parent is using.
    vm = VM(0)
    vm.prepare()
    t0 = time.monotonic()
    ok = vm.start()
    vm_ms = (time.monotonic() - t0) * 1000
    with_vm = meminfo()
    vm_pool = ne_state()
    err = vm.error
    vm.destroy()
    hog.kill()
    hog.wait()
    time.sleep(1)
    record("step5", {"allocated_mib": mib, "hog": line, "meminfo_pool_no_vm": base, "meminfo_hog_held": held,
                     "meminfo_hog_plus_vm": with_vm, "vm_started_under_pressure": ok, "vm_total_ms": round(vm_ms),
                     "vm_t": vm.t, "vm_error": err, "nitro_idle": pool, "nitro_with_vm": vm_pool,
                     "meminfo_after": meminfo()})


def parked(a):
    say("parked: %d VMs booted ahead (token-less toolboxd), then each claimed; pcie_slots %s" % (a.samples, ensure_slots(a.samples)))
    vms = [VM(i) for i in range(a.samples)]
    for vm in vms:
        vm.prepare()
    booted = []
    for vm in vms:
        if vm.start():
            booted.append(vm)
        else:
            say("parked boot %d failed: %s" % (vm.idx, vm.error))
    time.sleep(2)
    claim, first_exec = [], []
    for vm in booted:
        t0 = time.monotonic()
        # What a claim does (plan §4.3, R19): the vsock handshake, the
        # sandbox's identity and env, then the first call over the TAP.
        vm.vsock_op("ping", None)
        vm.adopt()
        vm.vsock_op("set_env", {"env": {"SPB_CLAIMED": vm.id}})
        claim.append((time.monotonic() - t0) * 1000)
        t1 = time.monotonic()
        r = vm.exec("echo $SPB_CLAIMED")
        first_exec.append((time.monotonic() - t1) * 1000)
        if r.get("http") != 200:
            say("parked exec %d: %s" % (vm.idx, r))
    for vm in vms:
        vm.destroy()
    record("parked", {"booted": len(booted), "claim_ms": stats(claim), "first_exec_ms": stats(first_exec),
                      "claim_plus_first_exec_ms": stats([c + e for c, e in zip(claim, first_exec)])})


def probe(a):
    out = {}
    if a.what == "pci-off":
        # AerolVM's own amd64 boot args (baseBootArgsAMD64) carry pci=off.
        vm = VM(0, boot_args="console=ttyS0 reboot=k panic=1 pci=off nomodules quiet ipv6.disable_ipv6=1 "
                             "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off init=/usr/local/bin/toolboxd-init", debug=True)
        vm.prepare()
        ok = vm.start(ready_timeout=20)
        out = {"ok": ok, "error": vm.error, "serial_tail": vm.serial(12)}
        vm.destroy()
    elif a.what == "dirty-pages":
        # AerolVM's configureVMM sets track_dirty_pages for every VM.
        vm = VM(0, machine_extra={"track_dirty_pages": True})
        vm.prepare()
        ok = vm.start(ready_timeout=20)
        out = {"ok": ok, "error": vm.error}
        vm.destroy()
    elif a.what == "debug-boot":
        vm = VM(0, mode=a.mode, debug=True, kernel=a.kernel)
        vm.prepare()
        ok = vm.start(ready_timeout=30)
        out = {"ok": ok, "error": vm.error, "t": vm.t, "serial_tail": vm.serial(30), "fc_log": vm.fc_log(10)}
        vm.destroy()
    elif a.what == "min-mem":
        for mem in (64, 128, 256):
            vm = VM(0, mem=mem)
            vm.prepare()
            ok = vm.start(ready_timeout=30)
            out[str(mem)] = {"ok": ok, "error": vm.error, "total_ms": round(vm.t.get("total_ms", 0))}
            vm.destroy()
    elif a.what == "pause":
        vm = VM(0)
        vm.prepare()
        vm.start()
        try:
            vm.api("PATCH", "/vm", {"state": "Paused"})
            out["pause"] = "accepted"
        except Exception as e:
            out["pause"] = str(e)
        try:
            vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": "s", "mem_file_path": "m"})
            out["snapshot"] = "accepted"
        except Exception as e:
            out["snapshot"] = str(e)
        vm.destroy()
    record("probe-" + a.what, out)


COLD_GO_MS = 2000.0


def asked_steps(path="/opt/spb/steps"):
    """The steps this run was asked for (spb-userdata.sh writes them), or
    None when the file is not there (a verdict read off the machine)."""
    try:
        with open(path) as f:
            return set(f.read().split())
    except OSError:
        return None


def verdict(path, asked=None):
    """Plan §4.2's go for SP-B: steps 1-4 pass and a cold create (process
    start to toolboxd's ping) is under 2 s at the p50. One SPB VERDICT line
    per step, then the overall one. Returns True on go. With asked (the
    steps the run was asked for), only those are judged: a run of the
    sandboxd step alone (plan §4.3) is not a failed SP-B."""
    last = {}
    try:
        for line in open(path):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            last[r.get("step", "")] = r
    except OSError:
        pass

    def line(step, ok, text):
        say("VERDICT %s: %s -> %s" % (step, text, "PASS" if ok else "FAIL"))
        return ok

    oks = []
    if asked is not None and asked.isdisjoint({"step1", "step2", "step3a", "step3b", "step4"}):
        if "sandboxd" in asked:
            import spb_sandboxd
            oks.append(line("sandboxd", *spb_sandboxd.verdict(last.get("sandboxd"))))
        go = bool(oks) and all(oks)
        say("VERDICT SP-B: %s" % ("go" if go else "NO GO"))
        return go
    r = last.get("step1-direct-overcommit-1vcpu")
    if r:
        p50 = (r.get("total_ms") or {}).get("p50_ms")
        oks.append(line("step1", r.get("failures") == 0 and r.get("samples", 0) > 0 and p50 is not None and p50 < COLD_GO_MS,
                        "%d boots, %d failed, start to ping p50 %s ms p90 %s ms (go: under %g)"
                        % (r.get("samples", 0), r.get("failures", 0), p50, (r.get("total_ms") or {}).get("p90_ms"), COLD_GO_MS)))
    else:
        oks.append(line("step1", False, "no result"))
    r = last.get("step2")
    if r:
        before, during, after = (str(r.get(k, "")) for k in ("before", "with_nft_rules", "rules_removed"))
        oks.append(line("step2", bool(r.get("ok")) and "host-port-ok" in before and "host-port-blocked" in during and "host-port-ok" in after,
                        "host port reachable, blocked by the rule on the TAP, reachable again"))
    else:
        oks.append(line("step2", False, "no result"))
    r = last.get("step3a-confidential-ci-kernel")
    oks.append(line("step3a", bool(r) and r.get("failures") == 0 and r.get("samples", 0) > 0,
                    "confidential boots: %s, failed %s" % ((r or {}).get("samples"), (r or {}).get("failures"))))
    r = (last.get("step3b-attestation") or {}).get("confidential, debug off") or {}
    v = r.get("verify") or {}
    oks.append(line("step3b", bool(v.get("ok")) and bool(v.get("cose_signature_verified")) and bool(v.get("chain_verified")),
                    "attestation document from a confidential sandbox, chain %s, signature %s"
                    % (v.get("chain_verified"), v.get("cose_signature_verified"))))
    r = next((v for k, v in last.items() if k.startswith("step4-")), None)
    if r:
        cap = (r.get("nitro_before") or {}).get("pcie_slots_total")
        oks.append(line("step4", r.get("started", 0) > 0 and r.get("alive_after") == r.get("started"),
                        "%s of %s started at once (cap %s = 5 per parent vCPU, %s vCPUs), %s still answer; past the cap: %s"
                        % (r.get("started"), r.get("count"), cap, r.get("parent_cpus"), r.get("alive_after"),
                           "; ".join("%dx %s" % (e["count"], k[:120]) for k, e in (r.get("errors") or {}).items()) or "none")))
    else:
        oks.append(line("step4", False, "no result"))
    r = last.get("parked")
    if r:
        say("VERDICT parked (R19, information): %s booted ahead; claim p50 %s ms, claim + first exec p50 %s ms"
            % (r.get("booted"), (r.get("claim_ms") or {}).get("p50_ms"), (r.get("claim_plus_first_exec_ms") or {}).get("p50_ms")))
    if asked is not None and "sandboxd" in asked:
        import spb_sandboxd
        oks.append(line("sandboxd", *spb_sandboxd.verdict(last.get("sandboxd"))))
    go = all(oks)
    say("VERDICT SP-B: %s" % ("go" if go else "NO GO"))
    return go


def main():
    global RESULTS  # the sandboxd step records to --results
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd")
    ap.add_argument("--samples", type=int, default=20)
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--vcpus", type=int, default=1)
    ap.add_argument("--mem", type=int, default=128)
    ap.add_argument("--slots", type=int, default=0)
    ap.add_argument("--what", default="")
    ap.add_argument("--mode", default="direct")
    ap.add_argument("--kernel", default="bzImage")
    ap.add_argument("--initrd", default="")
    ap.add_argument("--results", default=RESULTS)
    # --steps: the steps to judge, for a verdict read off the machine.
    ap.add_argument("--steps", default=None)
    a = ap.parse_args()
    if a.cmd == "verdict":
        sys.exit(0 if verdict(a.results, set(a.steps.split()) if a.steps is not None else asked_steps()) else 1)
    if a.cmd == "sandboxd":
        # sandboxd's own VMs through its API: no root, and no clean()
        # around it (that kills the spb- VMs, not sandboxd's).
        RESULTS = a.results
        import spb_sandboxd
        spb_sandboxd.run(a, record, say)
        return
    if os.geteuid() != 0:
        sys.exit("spb.py: run as root")
    os.makedirs(os.path.join(JAIL, "firecracker"), exist_ok=True)
    fn = {"step1": step1, "step2": step2, "step3a": step3a, "step4": step4, "step5": step5, "step6": step6,
          "parked": parked, "probe": probe}.get(a.cmd)
    if a.cmd == "clean":
        clean()
        return
    if a.cmd == "step3b":
        import spb_attest
        spb_attest.step3b(a, VM, record, say)
        return
    if fn is None:
        sys.exit("spb.py: unknown step %s" % a.cmd)
    clean()
    fn(a)
    clean()


if __name__ == "__main__":
    main()
