#!/usr/bin/env python3
"""Push the drill's images straight to the registry over its HTTP API, no
Docker daemon (Docker Desktop's pushes stalled for minutes at a time in the
first runs). Each image is a base image already in the registry plus one
layer of random bytes, so each is its own cold pull.

  push.py --registry http://127.0.0.1:15000 --base drill/app:v1 drill/hot:R drill/cold:R-1 ...

The base must be a Docker schema 2 or OCI image manifest; drills-local.sh
pushes it once with docker (alpine plus a file).
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import urllib.error
import urllib.request

MANIFEST_TYPES = ("application/vnd.docker.distribution.manifest.v2+json,"
                  "application/vnd.oci.image.manifest.v1+json")


def req(method, url, data=None, headers=None):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(r, timeout=120) as resp:
        return resp.status, dict(resp.headers), resp.read()


def blob_exists(reg, repo, digest):
    try:
        return req("HEAD", f"{reg}/v2/{repo}/blobs/{digest}")[0] == 200
    except urllib.error.HTTPError:
        return False


def put_blob(reg, repo, data, digest, mount_from=None):
    if blob_exists(reg, repo, digest):
        return
    q = f"?mount={digest}&from={mount_from}" if mount_from else ""
    st, h, _ = req("POST", f"{reg}/v2/{repo}/blobs/uploads/{q}", data=b"")
    if st == 201:  # mounted from the base repository
        return
    if data is None:  # no mount: copy it over
        data = req("GET", f"{reg}/v2/{mount_from}/blobs/{digest}")[2]
    loc = h["Location"]
    if loc.startswith("/"):
        loc = reg + loc
    sep = "&" if "?" in loc else "?"
    req("PUT", f"{loc}{sep}digest={digest}", data=data, headers={"Content-Type": "application/octet-stream"})


def random_layer(size):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        info = tarfile.TarInfo("blob")
        info.size = size
        info.mode = 0o644
        t.addfile(info, io.BytesIO(os.urandom(size)))
    tar = raw.getvalue()
    gz = gzip.compress(tar, compresslevel=1)
    return gz, "sha256:" + hashlib.sha256(gz).hexdigest(), "sha256:" + hashlib.sha256(tar).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--registry", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--size", type=int, default=4 << 20)
    p.add_argument("tags", nargs="+")
    a = p.parse_args()
    reg = a.registry.rstrip("/")
    brepo, btag = a.base.rsplit(":", 1)
    _, h, body = req("GET", f"{reg}/v2/{brepo}/manifests/{btag}", headers={"Accept": MANIFEST_TYPES})
    base = json.loads(body)
    mtype = h.get("Content-Type", base.get("mediaType"))
    _, _, cfg_raw = req("GET", f"{reg}/v2/{brepo}/blobs/{base['config']['digest']}")
    cfg = json.loads(cfg_raw)
    for tag in a.tags:
        repo, ref = tag.rsplit(":", 1)
        gz, digest, diff_id = random_layer(a.size)
        # The base's own layers, plus a fresh last one in place of its last.
        layers = base["layers"][:-1]
        for l in layers:
            put_blob(reg, repo, None, l["digest"], mount_from=brepo)
        put_blob(reg, repo, gz, digest)
        c = json.loads(json.dumps(cfg))
        c["rootfs"]["diff_ids"] = c["rootfs"]["diff_ids"][:len(layers)] + [diff_id]
        craw = json.dumps(c).encode()
        cdigest = "sha256:" + hashlib.sha256(craw).hexdigest()
        put_blob(reg, repo, craw, cdigest)
        m = json.loads(json.dumps(base))
        m["config"] = dict(base["config"], digest=cdigest, size=len(craw))
        m["layers"] = layers + [dict(base["layers"][-1], digest=digest, size=len(gz))]
        req("PUT", f"{reg}/v2/{repo}/manifests/{ref}", data=json.dumps(m).encode(), headers={"Content-Type": mtype})
        print(f"pushed {tag}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
