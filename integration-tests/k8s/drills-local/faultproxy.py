#!/usr/bin/env python3
"""A registry that is slow, rate-limits or hangs on demand, for the
image-pull storm drill (drills-local.sh, issue #1343).

It sits in front of a plain registry:2 and forwards every request to it,
except as the current mode says. Workers reach it as localhost:5000 (a
forwarder in each worker pod, see drills-local.sh), so containerd talks
plain HTTP to it as it would HTTPS to a bank's registry.

  faultproxy.py --upstream http://drills-registry:5000 --listen 5000 --control 5001

On EKS (drills-eks.sh) it listens over HTTPS, with a certificate a private
CA signed, which the workers trust through the chart's worker.registryCA:

  faultproxy.py --upstream http://127.0.0.1:5000 --listen 443 --control 5001 \
      --tls-cert /tls/tls.crt --tls-key /tls/tls.key

Modes, set with  curl -X POST 'http://127.0.0.1:<control>/mode?name=slow&delay=20&bps=20000'
(add &repo=drill/hot to set one repository's mode; without it, the mode of
every repository that has none of its own):
  healthy   forward everything
  slow      wait `delay` seconds before forwarding, then send the body at
            `bps` bytes a second (0: no cap)
  ratelimit answer 429 Too Many Requests with Retry-After (`status` picks
            another code, for example 503)
  hang      accept and answer nothing: the client gives up on its own, or
            /mode/clear drops the connection (and ends a slow transfer)

GET /mode on the control port prints the mode. GET /stats prints how many
requests each client made, by kind (manifest, blob, ping): the drill reads
it to show one worker pulls an image once, however many creates want it.
Each request is also one JSON line on stdout.
"""
import argparse
import http.client
import ssl
import http.server
import json
import socketserver
import sys
import threading
import time
import urllib.parse

state = {"name": "healthy", "delay": 0.0, "bps": 0, "status": 429}
# Bumped by /mode/clear: a request held in hang mode drops its connection,
# as a registry that is restarted or fixed would.
generation = [0]
# Per-repository modes, by repository name (drill/hot): they win over state.
repos = {}
stats = {}
lock = threading.Lock()


def kind_of(path):
    if "/manifests/" in path:
        return "manifest"
    if "/blobs/" in path:
        return "blob"
    if path.rstrip("/") == "/v2":
        return "ping"
    return "other"


def repo_of(path):
    # /v2/<name>/manifests/<ref> or /v2/<name>/blobs/<digest>
    for sep in ("/manifests/", "/blobs/"):
        if sep in path:
            return path[len("/v2/"):path.index(sep)]
    return ""


def log(**kw):
    kw["t"] = round(time.time(), 3)
    sys.stdout.write(json.dumps(kw) + "\n")
    sys.stdout.flush()


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream = None

    def log_message(self, *_):
        pass

    def handle_any(self):
        with lock:
            mode = dict(repos.get(repo_of(self.path), state))
            gen = generation[0]
            k = (self.client_address[0], self.command, kind_of(self.path))
            stats[k] = stats.get(k, 0) + 1
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        log(client=self.client_address[0], method=self.command, path=self.path, mode=mode["name"])
        if mode["name"] == "hang":
            # Hold the connection without a byte back until the client goes,
            # or the registry is fixed (/mode/clear).
            while True:
                time.sleep(5)
                if generation[0] != gen:
                    self.close_connection = True
                    return
                try:
                    self.connection.settimeout(0.01)
                    if self.connection.recv(1, 2) == b"":  # MSG_PEEK: closed?
                        return
                except (BlockingIOError, TimeoutError, OSError):
                    pass
        if mode["name"] == "ratelimit":
            msg = json.dumps({"errors": [{"code": "TOOMANYREQUESTS", "message": "drill: rate limited"}]}).encode()
            self.send_response(mode["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "30")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(msg)
            return
        if mode["name"] == "slow" and mode["delay"] > 0:
            time.sleep(mode["delay"])
        u = urllib.parse.urlsplit(self.upstream)
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=600)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        headers["Host"] = u.netloc
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            r = conn.getresponse()
        except OSError as e:
            self.send_error(502, f"upstream: {e}")
            return
        self.send_response(r.status, r.reason)
        chunked = r.getheader("Transfer-Encoding", "").lower() == "chunked"
        for k, v in r.getheaders():
            if k.lower() in ("connection", "transfer-encoding"):
                continue
            # The registry answers a pull's redirects with its own address;
            # keep them pointing back here.
            if k.lower() == "location" and v.startswith(self.upstream):
                v = v[len(self.upstream):]
            # A header copied from the registry's answer never carries a line
            # break (http.client parses one header per line), but strip any so
            # the copy can never start a header or body of its own.
            k = k.replace("\r", "").replace("\n", "")
            v = v.replace("\r", "").replace("\n", "")
            self.send_header(k, v)
        if chunked:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command == "HEAD":
            r.read()
            return
        bps = mode["bps"] if mode["name"] == "slow" else 0
        step = max(1024, bps // 4) if bps else 65536
        while True:
            if generation[0] != gen:
                # The registry was fixed: a crawling transfer ends, as it
                # would when the registry restarts.
                self.close_connection = True
                return
            chunk = r.read(step)
            if not chunk:
                break
            try:
                self.wfile.write(chunk)
            except OSError:
                return
            if bps:
                time.sleep(len(chunk) / bps)
        conn.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any


class Control(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, v):
        b = json.dumps(v).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/stats"):
            with lock:
                rows = [{"client": c, "method": m, "kind": k, "n": n} for (c, m, k), n in sorted(stats.items())]
            return self.reply(rows)
        with lock:
            return self.reply({"default": state, "repos": repos})

    def do_POST(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        with lock:
            if self.path.startswith("/stats/reset"):
                stats.clear()
                return self.reply({"reset": True})
            if self.path.startswith("/mode/clear"):
                repos.clear()
                generation[0] += 1
                state.update(name="healthy", delay=0.0, bps=0, status=429)
                log(control="clear")
                return self.reply({"default": state, "repos": repos})
            m = {"name": q.get("name", ["healthy"])[0], "delay": float(q.get("delay", [0])[0]),
                 "bps": int(q.get("bps", [0])[0]), "status": int(q.get("status", [429])[0])}
            repo = q.get("repo", [""])[0]
            if repo:
                repos[repo] = m
            else:
                state.update(m)
            log(control=m, repo=repo or "*")
            return self.reply({"default": state, "repos": repos})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--upstream", required=True)
    p.add_argument("--listen", type=int, default=5000)
    p.add_argument("--control", type=int, default=5001)
    p.add_argument("--tls-cert", default="")
    p.add_argument("--tls-key", default="")
    args = p.parse_args()
    Proxy.upstream = args.upstream.rstrip("/")
    threading.Thread(target=Server(("0.0.0.0", args.control), Control).serve_forever, daemon=True).start()
    srv = Server(("0.0.0.0", args.listen), Proxy)
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Registries and containerd speak TLS 1.2+; never offer older.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        # The handshake in each request's own thread, not in the accept
        # loop: one slow client must not hold up every other.
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    log(listening=args.listen, upstream=Proxy.upstream, tls=bool(args.tls_cert))
    srv.serve_forever()


if __name__ == "__main__":
    main()
