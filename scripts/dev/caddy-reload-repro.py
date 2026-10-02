#!/usr/bin/env python3
"""Reproduce connection loss on Caddy config reloads (TODOS.md: "Ingress route
changes reset in-flight TLS connections on :443").

Setup (Caddy with caddy-l4, same as the ingress):
    curl -fsSL -o caddy "https://caddyserver.com/api/download?os=$(uname -s | tr A-Z a-z)&arch=amd64&p=github.com/mholt/caddy-l4"
    chmod +x caddy && ./caddy run --config scripts/dev/caddy-reload-repro.json &
    python3 scripts/dev/caddy-reload-repro.py

It mirrors the ingress: a layer4 tls-mux on :19443 whose fallback route proxies
to an internal-TLS http server on 127.0.0.1:18443. 8 clients each open a fresh
TLS connection per request while the churner adds/deletes a route by @id,
which is what the ingress reconciler does per sandbox.
"""
import json, socket, ssl, threading, time, urllib.request, collections, sys
ADMIN="http://127.0.0.1:12019"
def admin(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(ADMIN+path, data=data, method=method, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
ctx = ssl.create_default_context(); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
def one():
    s = socket.create_connection(("127.0.0.1",19443), timeout=5)
    t = ctx.wrap_socket(s, server_hostname="repro.localhost")
    t.sendall(b"GET / HTTP/1.1\r\nHost: repro.localhost\r\nConnection: close\r\n\r\n")
    buf=b""
    while True:
        d=t.recv(4096)
        if not d: break
        buf+=d
    t.close()
    if b"\r\n\r\nok" not in buf: raise RuntimeError("bad body")
def phase(name, secs, churn):
    stop=time.time()+secs; res=collections.Counter(); lock=threading.Lock()
    def client():
        while time.time()<stop:
            try: one(); k="ok"
            except Exception as e: k=type(e).__name__+":"+str(e)[:60]
            with lock: res[k]+=1
    ths=[threading.Thread(target=client) for _ in range(8)]
    for t in ths: t.start()
    n=0
    while time.time()<stop:
        if churn: churn(n); n+=1
        else: time.sleep(0.05)
    for t in ths: t.join()
    total=sum(res.values()); bad=total-res["ok"]
    print(f"{name}: {total} requests, {bad} failed ({100*bad/max(total,1):.2f}%), churn ops={n}")
    for k,v in res.most_common():
        if k!="ok": print("   ",v,k)
    sys.stdout.flush()
def l4churn(n):
    rid=f"sandbox-sb{n}-ingress-sni"
    route={"@id":rid,"match":[{"tls":{"sni":[f"sb{n}.repro.localhost"]}}],"handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:9"]}]}]}
    admin("PUT","/config/apps/layer4/servers/tls-mux/routes/0",route)
    admin("DELETE","/id/"+rid)
def httpchurn(n):
    rid=f"http-sb{n}"
    admin("POST","/config/apps/http/servers/srv0/routes",{"@id":rid,"match":[{"host":[f"sb{n}.repro.localhost"]}],"handle":[{"handler":"static_response","body":"x"}]})
    admin("DELETE","/id/"+rid)
phase("control (no churn)",10,None)
phase("layer4 route churn",20,l4churn)
phase("http route churn",20,httpchurn)
