"""spb_attest.py: SP-B step 3b. A confidential Nitro Sandbox asks /dev/nsm
for an attestation document and hands it to the parent over vsock; the
parent checks its COSE signature and its certificate chain up to the AWS
Nitro Enclaves Root-G1 certificate.

The guest is the parent's own Amazon Linux 2023 kernel6.18 kernel (an
EFI-stub bzImage carrying the DMB virtio patches; Firecracker's docs say it
works as a guest kernel) with an initramfs: Alpine's busybox, the modules
the guest needs (nsm, vsock) from the parent's /lib/modules, and
nsm-attest. Called from spb.py step3b.
"""
import base64
import datetime
import glob
import hashlib
import io
import json
import os
import platform
import socket
import subprocess
import threading
import time
import urllib.request
import zipfile

D = "/opt/spb"
ROOT_ZIP = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
# The root certificate's SHA-256 fingerprint as AWS publishes it (Nitro
# Enclaves User Guide, "Verifying the root of trust").
ROOT_FP = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
NEEDED = ["CONFIG_VIRTIO_PCI", "CONFIG_NSM", "CONFIG_VSOCKETS", "CONFIG_VIRTIO_VSOCKETS_COMMON", "CONFIG_VIRTIO_VSOCKETS"]
MODULE_OF = {"CONFIG_VIRTIO_PCI": "virtio_pci", "CONFIG_NSM": "nsm", "CONFIG_VSOCKETS": "vsock",
             "CONFIG_VIRTIO_VSOCKETS_COMMON": "vmw_vsock_virtio_transport_common",
             "CONFIG_VIRTIO_VSOCKETS": "vmw_vsock_virtio_transport"}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout.strip()


def build_initrd(say):
    rel = platform.release()
    cfg = {}
    for line in open("/boot/config-" + rel):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            cfg[k] = v
    want = {k: cfg.get(k, "unset") for k in NEEDED}
    say("guest kernel %s config: %s" % (rel, want))
    work = os.path.join(D, "attest-root")
    sh("rm -rf %s && cp -a %s %s" % (work, os.path.join(D, "rootfs"), work))
    os.makedirs(os.path.join(work, "mods"), exist_ok=True)
    order = []
    for k in NEEDED:
        if want[k] != "m":
            continue
        for line in sh("modprobe --show-depends %s" % MODULE_OF[k]).splitlines():
            parts = line.split()
            if parts[:1] != ["insmod"]:
                continue
            path = parts[1]
            name = os.path.basename(path)
            for ext in (".xz", ".zst", ".gz"):
                name = name[:-len(ext)] if name.endswith(ext) else name
            if name in order:
                continue
            dst = os.path.join(work, "mods", name)
            if path.endswith(".xz"):
                sh("xz -dc %s > %s" % (path, dst))
            elif path.endswith(".zst"):
                sh("zstd -qdc %s > %s" % (path, dst))
            elif path.endswith(".gz"):
                sh("gzip -dc %s > %s" % (path, dst))
            else:
                sh("cp %s %s" % (path, dst))
            order.append(name)
    open(os.path.join(work, "mods", "order"), "w").write("\n".join(order) + "\n")
    open(os.path.join(work, "init"), "w").write("""#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
for m in $(cat /mods/order); do insmod /mods/$m || echo "SPB-INIT insmod $m failed"; done
echo "SPB-INIT kernel $(uname -r); nsm: $(ls -l /dev/nsm 2>&1)"
/usr/local/bin/nsm-attest -vsock 5000 -nonce "$(cat /proc/sys/kernel/random/uuid | tr -d -)"
sleep 1
poweroff -f
""")
    os.chmod(os.path.join(work, "init"), 0o755)
    sh("cd %s && find . | cpio -o -H newc --quiet | gzip -1 > %s/attest.cpio.gz" % (work, D))
    kernel = "al2023-vmlinuz"
    sh("cp /boot/vmlinuz-%s %s/%s" % (rel, D, kernel))
    return kernel, "attest.cpio.gz", want, order


def root_cert():
    from cryptography import x509
    raw = urllib.request.urlopen(ROOT_ZIP, timeout=30).read()
    z = zipfile.ZipFile(io.BytesIO(raw))
    pem = z.read([n for n in z.namelist() if n.endswith(".pem")][0])
    cert = x509.load_pem_x509_certificate(pem)
    from cryptography.hazmat.primitives import hashes
    fp = cert.fingerprint(hashes.SHA256()).hex()
    return cert, fp, hashlib.sha256(raw).hexdigest()


def verify(resp_b64):
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    out = {}
    resp = cbor2.loads(base64.b64decode(resp_b64))
    if "Attestation" not in resp:
        return {"ok": False, "nsm_response": str(resp)[:300]}
    doc = resp["Attestation"]["document"]
    cose = cbor2.loads(doc)
    if isinstance(cose, cbor2.CBORTag):
        cose = cose.value
    protected, _unprotected, payload, sig = cose
    att = cbor2.loads(payload)
    leaf = x509.load_der_x509_certificate(att["certificate"])
    bundle = [x509.load_der_x509_certificate(c) for c in att["cabundle"]]
    root, fp, zip_sha = root_cert()
    out["root_fingerprint_matches_aws"] = fp == ROOT_FP
    out["root_zip_sha256"] = zip_sha
    out["bundle_root_is_aws_root"] = bundle[0].public_bytes(encoding=_der()) == root.public_bytes(encoding=_der())
    chain = bundle + [leaf]
    now = datetime.datetime.now(datetime.timezone.utc)
    for parent, child in zip(chain, chain[1:]):
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        # cryptography < 42 (AL2023's python3-cryptography is 36) has only
        # the naive-UTC properties.
        nb = getattr(child, "not_valid_before_utc", None) or child.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = getattr(child, "not_valid_after_utc", None) or child.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        assert nb <= now <= na, "certificate out of date"
    out["chain_verified"] = len(chain)
    out["chain_subjects"] = [c.subject.rfc4514_string()[:80] for c in chain]
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    half = len(sig) // 2
    der = utils.encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
    leaf.public_key().verify(der, to_sign, ec.ECDSA(hashes.SHA384()))
    out["cose_signature_verified"] = True
    pcrs = att.get("pcrs", {})
    out["pcrs"] = {str(k): v.hex()[:24] + "..." for k, v in sorted(pcrs.items()) if k in (0, 1, 2, 3, 4, 8)}
    out["pcr0_all_zero"] = not any(pcrs.get(0, b"\0"))
    out["pcr_count"] = len(pcrs)
    out["module_id"] = att.get("module_id")
    out["digest"] = att.get("digest")
    out["timestamp"] = att.get("timestamp")
    out["nonce_present"] = bool(att.get("nonce"))
    out["ok"] = out["root_fingerprint_matches_aws"] and out["bundle_root_is_aws_root"]
    return out


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def listen(path, uid, gid, box):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chown(path, uid, gid)
    s.listen(1)
    s.settimeout(90)
    try:
        c, _ = s.accept()
        c.settimeout(30)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
        box["line"] = buf.decode().strip()
        box["at"] = time.monotonic()
    except OSError as e:
        box["error"] = str(e)


def step3b(a, VM, record, say):
    kernel, initrd, cfg, mods = build_initrd(say)
    results = {"guest_kernel": platform.release(), "kernel_config": cfg, "modules": mods}
    for label, mode, debug in (("confidential, debug off", "confidential", False),
                               ("confidential, debug on", "confidential", True),
                               ("direct", "direct", True)):
        vm = VM(0, mode=mode, debug=debug, kernel=kernel, rootfs=None, initrd=initrd, net=False,
                boot_args="console=ttyS0 panic=1 quiet rdinit=/init")
        vm.prepare()
        box = {}
        th = threading.Thread(target=listen, args=(os.path.join(vm.root, "v.sock_5000"), vm.uid, vm.gid, box))
        th.start()
        time.sleep(0.2)
        t0 = time.monotonic()
        ok = vm.start(wait_ready=False)
        th.join(timeout=100)
        r = {"started": ok, "error": vm.error, "t": vm.t}
        if "at" in box:
            r["doc_after_ms"] = round((box["at"] - t0) * 1000)
        line = box.get("line", "")
        if line.startswith("NSM-DOC"):
            _, us, b64 = line.split(" ", 2)
            open("/root/spb-doc-%s-%s.b64" % (mode, "debug" if debug else "nodebug"), "w").write(b64)
            r["nsm_ioctl_us"] = int(us)
            try:
                r["verify"] = verify(b64)
            except Exception as e:
                r["verify"] = {"ok": False, "error": repr(e)[:300]}
        else:
            r["guest_said"] = line[:300] or box.get("error")
        if debug:
            r["serial_tail"] = [l[:200] for l in vm.serial(15) if "SPB-INIT" in l or "NSM" in l or "nsm" in l][-6:]
        vm.destroy()
        results[label] = r
        say("%s: %s" % (label, json.dumps(r)[:600]))
    record("step3b-attestation", results)
