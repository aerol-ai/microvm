#!/usr/bin/env python3
"""Push the drill's images straight to the registry over its HTTP API, no
Docker daemon (Docker Desktop's pushes stalled for minutes at a time in the
first runs). Each image is a base image already in the registry plus one
layer of random bytes, so each is its own cold pull.

  push.py --registry http://127.0.0.1:15000 --base drill/app:v1 drill/hot:R drill/cold:R-1 ...

The base must be a Docker schema 2 or OCI image manifest; drills-local.sh
pushes it once with docker (alpine plus a file). On EKS (drills-eks.sh) the
script runs in the cluster and has more to do:

  --from https://public.ecr.aws/docker/library/alpine:3.20
            make the base itself: that image's linux/amd64 layers (a
            registry's anonymous token is fetched when it asks for one),
            plus one random layer of --size, pushed as --base
  --cafile  the CA the registry's certificate is signed by
  --auth-file
            a file holding user:password for Basic auth (Amazon ECR:
            AWS:<get-login-password>)
  --size    the random layer's size; past 64 MiB it is written to a
            temporary file and uploaded in chunks, so a layer of a few GB
            never sits in memory
  --layers  that many random layers instead of one (each --size), so one
            pull fetches that many blobs (the ECR throttling storm)
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import ssl
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MANIFEST_TYPES = ("application/vnd.docker.distribution.manifest.v2+json,"
                  "application/vnd.oci.image.manifest.v1+json,"
                  "application/vnd.docker.distribution.manifest.list.v2+json,"
                  "application/vnd.oci.image.index.v1+json")
INDEX_TYPES = ("application/vnd.docker.distribution.manifest.list.v2+json",
               "application/vnd.oci.image.index.v1+json")
STREAM_PAST = 64 << 20
CHUNK = 8 << 20

ctx = None
opener = None
auth = {}  # registry base URL -> Authorization header value


class DropAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """A blob GET redirects to object storage with a signed URL, which
    refuses a request that also carries the registry's Authorization."""

    def redirect_request(self, req_, fp, code, msg, headers, newurl):
        new = super().redirect_request(req_, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req_.full_url).netloc:
            new.remove_header("Authorization")
        return new


def req(method, url, data=None, headers=None, tries=2):
    """One call; a Bearer challenge is answered once with an anonymous
    token (a public registry), Basic auth is sent where given."""
    h = dict(headers or {})
    base = re.match(r"https?://[^/]+", url).group(0)
    if base in auth:
        h.setdefault("Authorization", auth[base])
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with opener.open(r, timeout=600) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        chal = e.headers.get("WWW-Authenticate", "")
        if e.code == 401 and chal.lower().startswith("bearer") and tries > 1 and base not in auth:
            auth[base] = "Bearer " + anonymous_token(chal)
            if hasattr(data, "seek"):
                data.seek(0)
            return req(method, url, data, headers, tries - 1)
        raise


def anonymous_token(challenge):
    kv = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    q = urllib.parse.urlencode({k: v for k, v in kv.items() if k in ("service", "scope")})
    with opener.open(kv["realm"] + "?" + q, timeout=60) as resp:
        body = json.loads(resp.read())
    return body.get("token") or body["access_token"]


def blob_exists(reg, repo, digest):
    try:
        return req("HEAD", f"{reg}/v2/{repo}/blobs/{digest}")[0] == 200
    except urllib.error.HTTPError:
        return False


def location(reg, h):
    loc = h["Location"]
    return reg + loc if loc.startswith("/") else loc


def put_blob(reg, repo, data, digest, mount_from=None, path=None):
    """data: bytes; or path: a file uploaded in CHUNK-sized PATCHes."""
    if blob_exists(reg, repo, digest):
        return
    q = f"?mount={digest}&from={mount_from}" if mount_from else ""
    st, h, _ = req("POST", f"{reg}/v2/{repo}/blobs/uploads/{q}", data=b"")
    if st == 201:  # mounted from the base repository
        return
    if data is None and path is None:  # no mount: copy it over
        data = req("GET", f"{reg}/v2/{mount_from}/blobs/{digest}")[2]
    loc = location(reg, h)
    if path is not None:
        size, sent = os.path.getsize(path), 0
        with open(path, "rb") as f:
            while sent < size:
                chunk = f.read(CHUNK)
                _, h, _ = req("PATCH", loc, data=chunk, headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Range": f"{sent}-{sent + len(chunk) - 1}", "Content-Length": str(len(chunk))})
                sent += len(chunk)
                loc = location(reg, h)
        data = b""
    sep = "&" if "?" in loc else "?"
    req("PUT", f"{loc}{sep}digest={digest}", data=data, headers={"Content-Type": "application/octet-stream"})


def random_layer(size):
    """(gzip bytes or None, path or None, digest, diff_id)."""
    if size <= STREAM_PAST:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as t:
            info = tarfile.TarInfo("blob")
            info.size = size
            info.mode = 0o644
            t.addfile(info, io.BytesIO(os.urandom(size)))
        tar = raw.getvalue()
        gz = gzip.compress(tar, compresslevel=1)
        return gz, None, "sha256:" + hashlib.sha256(gz).hexdigest(), "sha256:" + hashlib.sha256(tar).hexdigest()
    # Streamed: random bytes through tar and gzip into a temporary file,
    # both digests taken on the way.
    fd, path = tempfile.mkstemp(prefix="layer-", suffix=".tar.gz")
    os.close(fd)
    gz_sha, tar_sha = hashlib.sha256(), hashlib.sha256()

    class Tee(io.RawIOBase):
        def __init__(self, f):
            self.f = f

        def writable(self):
            return True

        def write(self, b):
            gz_sha.update(b)
            return self.f.write(b)

    class TarSink(io.RawIOBase):
        def __init__(self, g):
            self.g = g

        def writable(self):
            return True

        def write(self, b):
            tar_sha.update(b)
            return self.g.write(b)

    class RandomReader(io.RawIOBase):
        def __init__(self, n):
            self.left = n

        def readable(self):
            return True

        def readinto(self, b):
            n = min(len(b), self.left, CHUNK)
            if n <= 0:
                return 0
            b[:n] = os.urandom(n)
            self.left -= n
            return n

    with open(path, "wb") as out, gzip.GzipFile(fileobj=Tee(out), mode="wb", compresslevel=1) as g:
        with tarfile.open(fileobj=TarSink(g), mode="w|") as t:
            info = tarfile.TarInfo("blob")
            info.size = size
            info.mode = 0o644
            t.addfile(info, io.BufferedReader(RandomReader(size), CHUNK))
    return None, path, "sha256:" + gz_sha.hexdigest(), "sha256:" + tar_sha.hexdigest()


def resolve_manifest(url_base, repo, ref):
    """The image manifest for linux/amd64 (an index is followed)."""
    _, h, body = req("GET", f"{url_base}/v2/{repo}/manifests/{ref}", headers={"Accept": MANIFEST_TYPES})
    m = json.loads(body)
    mtype = h.get("Content-Type", m.get("mediaType", ""))
    if mtype.split(";")[0] in INDEX_TYPES or "manifests" in m:
        d = next(x["digest"] for x in m["manifests"]
                 if x.get("platform", {}).get("os") == "linux" and x.get("platform", {}).get("architecture") == "amd64")
        return resolve_manifest(url_base, repo, d)
    return m, mtype


def make_base(src, reg, base, size):
    """Copy src's linux/amd64 image into reg as base, plus one random layer."""
    u = urllib.parse.urlparse(src)
    srepo, sref = u.path.lstrip("/").rsplit(":", 1)
    sbase = f"{u.scheme}://{u.netloc}"
    m, mtype = resolve_manifest(sbase, srepo, sref)
    brepo, btag = base.rsplit(":", 1)
    for l in m["layers"]:
        put_blob(reg, brepo, req("GET", f"{sbase}/v2/{srepo}/blobs/{l['digest']}")[2], l["digest"])
    cfg = json.loads(req("GET", f"{sbase}/v2/{srepo}/blobs/{m['config']['digest']}")[2])
    gz, path, digest, diff_id = random_layer(size)
    lsize = len(gz) if gz is not None else os.path.getsize(path)
    put_blob(reg, brepo, gz, digest, path=path)
    if path:
        os.unlink(path)
    cfg["rootfs"]["diff_ids"].append(diff_id)
    craw = json.dumps(cfg).encode()
    cdigest = "sha256:" + hashlib.sha256(craw).hexdigest()
    put_blob(reg, brepo, craw, cdigest)
    layer_type = m["layers"][-1]["mediaType"]
    out = dict(m, config=dict(m["config"], digest=cdigest, size=len(craw)),
               layers=m["layers"] + [{"mediaType": layer_type, "digest": digest, "size": lsize}])
    return out, mtype, craw


def main():
    global ctx, opener
    p = argparse.ArgumentParser()
    p.add_argument("--registry", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--size", type=int, default=4 << 20)
    p.add_argument("--layers", type=int, default=1)
    p.add_argument("--from", dest="src", default="")
    p.add_argument("--cafile", default="")
    p.add_argument("--auth-file", default="")
    p.add_argument("tags", nargs="*")
    a = p.parse_args()
    # The public CAs (a public base image) and, with --cafile, the private
    # one the drill registry's certificate is signed by.
    ctx = ssl.create_default_context()
    if a.cafile:
        ctx.load_verify_locations(a.cafile)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), DropAuthOnRedirect())
    reg = a.registry.rstrip("/")
    if a.auth_file:
        auth[reg] = "Basic " + base64.b64encode(open(a.auth_file).read().strip().encode()).decode()
    brepo, btag = a.base.rsplit(":", 1)
    if a.src:
        m, mtype, _ = make_base(a.src, reg, a.base, a.size)
        req("PUT", f"{reg}/v2/{brepo}/manifests/{btag}", data=json.dumps(m).encode(), headers={"Content-Type": mtype})
        print(f"pushed base {a.base} from {a.src}", flush=True)
    _, h, body = req("GET", f"{reg}/v2/{brepo}/manifests/{btag}", headers={"Accept": MANIFEST_TYPES})
    base = json.loads(body)
    mtype = h.get("Content-Type", base.get("mediaType"))
    _, _, cfg_raw = req("GET", f"{reg}/v2/{brepo}/blobs/{base['config']['digest']}")
    cfg = json.loads(cfg_raw)
    for tag in a.tags:
        repo, ref = tag.rsplit(":", 1)
        # The base's own layers, plus fresh last ones in place of its last.
        layers = base["layers"][:-1]
        for l in layers:
            put_blob(reg, repo, None, l["digest"], mount_from=brepo)
        fresh, diff_ids = [], []
        for _ in range(max(1, a.layers)):
            gz, path, digest, diff_id = random_layer(a.size)
            size = len(gz) if gz is not None else os.path.getsize(path)
            put_blob(reg, repo, gz, digest, path=path)
            if path:
                os.unlink(path)
            fresh.append(dict(base["layers"][-1], digest=digest, size=size))
            diff_ids.append(diff_id)
        c = json.loads(json.dumps(cfg))
        c["rootfs"]["diff_ids"] = c["rootfs"]["diff_ids"][:len(layers)] + diff_ids
        craw = json.dumps(c).encode()
        cdigest = "sha256:" + hashlib.sha256(craw).hexdigest()
        put_blob(reg, repo, craw, cdigest)
        m = json.loads(json.dumps(base))
        m["config"] = dict(base["config"], digest=cdigest, size=len(craw))
        m["layers"] = layers + fresh
        req("PUT", f"{reg}/v2/{repo}/manifests/{ref}", data=json.dumps(m).encode(), headers={"Content-Type": mtype})
        print(f"pushed {tag}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
