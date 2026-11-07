"""Per-call timeouts (plan S6): every public call takes timeout=, which
bounds the whole call, its retries and the waits between them."""

import http.server
import inspect
import json
import threading
import time
import unittest
import unittest.mock
import urllib.request

from microvm import MicroVM, MicroVMTimeoutError
from microvm import client as client_module


def _serve(test, handler_fn):
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            hits.append((self.command, self.path))
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            handler_fn(self)

        do_GET = do_POST = do_DELETE = do_PUT = _answer

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return "http://127.0.0.1:%d" % server.server_port, hits


def _json(handler, status, payload, headers=None):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    for key, value in (headers or {}).items():
        handler.send_header(key, value)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


_SANDBOX = {"id": "sb-1", "name": "a", "image": "alpine", "status": "started", "lifecycle": {}}


class PerCallTimeoutTests(unittest.TestCase):
    def test_a_slow_answer_raises_a_timeout_error(self):
        def slow(handler):
            time.sleep(5)
            _json(handler, 200, _SANDBOX)

        url, _ = _serve(self, slow)
        client = MicroVM(url, "pat")
        started = time.monotonic()
        with self.assertRaises(MicroVMTimeoutError) as ctx:
            client.get("sb-1", timeout=0.3)
        self.assertLess(time.monotonic() - started, 3)
        err = ctx.exception
        self.assertEqual(err.status_code, 0)
        self.assertIsInstance(err, TimeoutError)
        self.assertIn("0.3s", str(err))

    def test_a_retry_wait_never_runs_past_the_timeout(self):
        def busy(handler):
            _json(handler, 503, {"error": "busy", "code": "overloaded"}, {"Retry-After": "5"})

        url, hits = _serve(self, busy)
        client = MicroVM(url, "pat")
        started = time.monotonic()
        with self.assertRaises(MicroVMTimeoutError) as ctx:
            client.get("sb-1", timeout=0.5)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(len(hits), 1)
        # The 503 that could not be retried in time is kept as the cause.
        self.assertIsNotNone(ctx.exception.__cause__)

    def test_the_timeout_bounds_every_request_of_one_call(self):
        # get_or_create looks the name up (fast), then creates (slow): the
        # one timeout covers both.
        def handler(h):
            if h.command == "GET":
                _json(h, 200, [])
            else:
                time.sleep(5)
                _json(h, 201, _SANDBOX)

        url, hits = _serve(self, handler)
        with self.assertRaises(MicroVMTimeoutError):
            MicroVM(url, "pat").get_or_create("a", image="alpine", timeout=0.4)
        self.assertEqual([m for m, _ in hits], ["GET", "POST"])

    def test_a_sandbox_method_timeout_bounds_its_client_call(self):
        def slow(handler):
            time.sleep(5)
            _json(handler, 200, {"exit_code": 0, "stdout": "", "stderr": ""})

        url, _ = _serve(self, slow)
        sandbox = client_module.Sandbox(MicroVM(url, "pat"), dict(_SANDBOX))
        with self.assertRaises(MicroVMTimeoutError):
            sandbox.exec_command("sleep 10", timeout=0.3)

    def test_a_download_that_keeps_arriving_is_cut_off(self):
        def trickle(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/octet-stream")
            handler.end_headers()
            try:
                for _ in range(40):
                    handler.wfile.write(b"x" * 1024)
                    handler.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass

        url, _ = _serve(self, trickle)
        with self.assertRaises(MicroVMTimeoutError):
            MicroVM(url, "pat").download_file("sb-1", "/f", timeout=0.4)

    def test_without_a_timeout_nothing_changes(self):
        url, _ = _serve(self, lambda h: _json(h, 200, _SANDBOX))
        client = MicroVM(url, "pat")
        with unittest.mock.patch.object(urllib.request, "urlopen", wraps=urllib.request.urlopen) as opened:
            client.get("sb-1")
            self.assertNotIn("timeout", opened.call_args.kwargs)
            client.get("sb-1", timeout=30)
            self.assertLessEqual(opened.call_args.kwargs["timeout"], 30)
            self.assertGreater(opened.call_args.kwargs["timeout"], 29)

    def test_a_bad_timeout_is_refused(self):
        client = MicroVM("http://127.0.0.1:9", "pat")
        for bad in (0, -1, "5", True):
            with self.subTest(timeout=bad):
                with self.assertRaises(ValueError):
                    client.get("sb-1", timeout=bad)

    def test_a_nested_timeout_can_only_shorten_the_deadline(self):
        with client_module._call_deadline(10):
            outer = client_module._CALL_DEADLINE.get()
            with client_module._call_deadline(60):
                self.assertEqual(client_module._CALL_DEADLINE.get(), outer)
            with client_module._call_deadline(1):
                inner = client_module._CALL_DEADLINE.get()
                self.assertLess(inner[0], outer[0])
                self.assertEqual(inner[1], 1.0)
            self.assertEqual(client_module._CALL_DEADLINE.get(), outer)
        self.assertIsNone(client_module._CALL_DEADLINE.get())

    def test_iter_pages_bounds_each_page(self):
        def slow(handler):
            time.sleep(1)
            _json(handler, 200, [_SANDBOX])

        url, _ = _serve(self, slow)
        pages = MicroVM(url, "pat").iter_pages(timeout=0.3)
        with self.assertRaises(MicroVMTimeoutError):
            next(pages)

    def test_a_stream_timeout_bounds_only_the_opening(self):
        calls = []

        class FakeWS:
            def __init__(self):
                self.timeouts = []

            def settimeout(self, value):
                self.timeouts.append(value)

            def send(self, payload, opcode=None):
                pass

            def recv(self):
                time.sleep(0.05)
                return json.dumps({"type": "exit", "code": 0})

            def close(self):
                pass

        ws = FakeWS()

        class FakeModule:
            class ABNF:
                OPCODE_BINARY = 2

            @staticmethod
            def create_connection(url, **kwargs):
                calls.append(kwargs)
                return ws

        with unittest.mock.patch.object(client_module, "_load_websocket_module", lambda: FakeModule):
            client = MicroVM("http://127.0.0.1:9", "pat")
            client.exec_stream("sb-1", {"command": "true"}).wait(5)
            self.assertNotIn("timeout", calls[-1])
            client.exec_stream("sb-1", {"command": "true"}, timeout=5).wait(5)
            self.assertLessEqual(calls[-1]["timeout"], 5)
            # Opened within the timeout, then unbounded for the stream's life.
            self.assertEqual(ws.timeouts, [None])

    def test_every_public_call_takes_a_keyword_only_timeout(self):
        for cls in (client_module.MicroVM, client_module.Sandbox, client_module.Tokens):
            for name, member in vars(cls).items():
                if name.startswith("_") or name in ("to_dict",) or not callable(member):
                    continue
                if cls is client_module.MicroVM and name == "close":
                    continue  # sends nothing: urllib holds no connections
                with self.subTest(method=f"{cls.__name__}.{name}"):
                    param = inspect.signature(member).parameters.get("timeout")
                    self.assertIsNotNone(param, "no timeout parameter")
                    self.assertEqual(param.kind, inspect.Parameter.KEYWORD_ONLY)
                    self.assertIsNone(param.default)


if __name__ == "__main__":
    unittest.main()
