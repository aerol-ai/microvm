#!/usr/bin/env python3
"""The receiver Alertmanager sends to in the SLO drill (drills-local.sh): it
prints one JSON line per alert in each webhook it gets, with the path it
came to (/sandboxd or /sandboxd-critical, the two receivers of
setup/alertmanager/sandboxd-alertmanager-example.yml) and when.

  echo.py --listen 8080
"""
import argparse
import http.server
import json
import socketserver
import sys
import time


class Echo(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        now = round(time.time(), 3)
        try:
            msg = json.loads(raw or b"{}")
        except ValueError:
            msg = {"raw": raw.decode(errors="replace")[:500]}
        for a in msg.get("alerts", []) or [{}]:
            sys.stdout.write(json.dumps({
                "t": now, "path": self.path, "receiver": msg.get("receiver"),
                "status": a.get("status", msg.get("status")),
                "alertname": a.get("labels", {}).get("alertname"),
                "severity": a.get("labels", {}).get("severity"),
                "startsAt": a.get("startsAt"), "endsAt": a.get("endsAt"),
            }) + "\n")
        sys.stdout.flush()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, default=8080)
    Server(("0.0.0.0", p.parse_args().listen), Echo).serve_forever()


if __name__ == "__main__":
    main()
