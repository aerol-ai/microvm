import json
import queue
import threading
import unittest
import urllib.parse

from microvm import FileEvent, FileWatchHandle, MicroVM, MicroVMError, MicroVMHTTPError, MicroVMUnsupportedFeatureError
from microvm import client as client_module


class _Closed(Exception):
    pass


class QueueWebSocket:
    """A fake socket whose recv blocks until the test pushes a frame, so a
    watch that is still running looks like one."""

    def __init__(self):
        self.frames = queue.Queue()
        self.closed = False

    def push(self, frame):
        self.frames.put(json.dumps(frame) if isinstance(frame, dict) else frame)

    def recv(self):
        item = self.frames.get(timeout=5)
        if item is _Closed:
            raise _Closed("socket closed")
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True
        self.frames.put(_Closed)


class FakeModule:
    def __init__(self, ws=None, error=None):
        self.ws = ws
        self.error = error
        self.calls = []

    def create_connection(self, url, header, enable_multithread):
        self.calls.append((url, header, enable_multithread))
        if self.error is not None:
            raise self.error
        return self.ws


class FakeBadStatus(Exception):
    """Shaped like websocket-client's WebSocketBadStatusException."""

    def __init__(self, status_code, body, headers=None):
        super().__init__(f"Handshake status {status_code}")
        self.status_code = status_code
        self.resp_body = body.encode() if isinstance(body, str) else body
        self.resp_headers = headers or {}


class WatchFilesTests(unittest.TestCase):
    def setUp(self):
        self.original_loader = client_module._load_websocket_module
        self.addCleanup(setattr, client_module, "_load_websocket_module", self.original_loader)
        self.client = MicroVM(api_url="https://sandbox.example.com", pat_token="pat-token")

    def use(self, module):
        client_module._load_websocket_module = lambda: module
        return module

    def started(self, recursive=False):
        ws = QueueWebSocket()
        ws.push({"type": "start", "path": "/work", "recursive": recursive})
        return ws

    def test_url_query_and_auth(self):
        for recursive in (False, True):
            module = self.use(FakeModule(self.started(recursive)))
            handle = self.client.watch_files("sb 1", "/work dir/a&b", lambda ev: None, recursive=recursive)
            handle.stop()
            url, header, multithread = module.calls[0]
            parsed = urllib.parse.urlparse(url)
            self.assertEqual(parsed.scheme, "wss")
            self.assertEqual(parsed.path, "/v1/sandboxes/sb%201/toolbox/files/watch")
            query = urllib.parse.parse_qs(parsed.query)
            self.assertEqual(query["path"], ["/work dir/a&b"])
            if recursive:
                self.assertEqual(query["recursive"], ["true"])
            else:
                self.assertNotIn("recursive", query)
            self.assertEqual(header, ["Authorization: Bearer pat-token"])
            self.assertTrue(multithread)

    def test_team_header_is_carried(self):
        module = self.use(FakeModule(self.started()))
        client = MicroVM(api_url="https://sandbox.example.com", pat_token="pat-token", team="red")
        client.watch_files("sb-1", "/work", lambda ev: None).stop()
        self.assertIn("X-AerolVM-Team: red", module.calls[0][1])

    def test_returns_only_after_start_and_delivers_events_in_order(self):
        ws = QueueWebSocket()
        self.use(FakeModule(ws))
        events = []
        got = threading.Event()
        result = {}

        def run():
            result["handle"] = self.client.watch_files("sb-1", "/work", events.append, recursive=True)
            got.set()

        threading.Thread(target=run, daemon=True).start()
        self.assertFalse(got.wait(0.2), "watch_files returned before the start frame")
        ws.push({"type": "start", "path": "/work", "recursive": True})
        self.assertTrue(got.wait(5))
        handle = result["handle"]
        self.assertIsInstance(handle, FileWatchHandle)

        ws.push(
            {
                "type": "events",
                "events": [
                    {"type": "create", "path": "/work/a"},
                    {"type": "write", "path": "/work/a"},
                    {"type": "create", "path": "/work/sub", "is_dir": True},
                    {"type": "overflow", "reason": "watch_limit", "path": "/work/deep"},
                    {"type": "brand-new", "path": "/work/b"},
                ],
            }
        )
        ws.push({"type": "something-newer"})
        ws.push({"type": "events", "events": [{"type": "chmod", "path": "/work/a"}, {"type": "remove", "path": "/work/a"}, {"type": "rename", "path": "/work/c"}]})
        for _ in range(100):
            if len(events) == 8:
                break
            threading.Event().wait(0.02)
        self.assertEqual(
            events,
            [
                FileEvent("create", "/work/a"),
                FileEvent("write", "/work/a"),
                FileEvent("create", "/work/sub", is_dir=True),
                FileEvent("overflow", "/work/deep", reason="watch_limit"),
                FileEvent("brand-new", "/work/b"),
                FileEvent("chmod", "/work/a"),
                FileEvent("remove", "/work/a"),
                FileEvent("rename", "/work/c"),
            ],
        )
        handle.stop()
        handle.wait(1)

    def test_end_frame_fails_wait_with_the_reason(self):
        ws = self.started()
        self.use(FakeModule(ws))
        events = []
        handle = self.client.watch_files("sb-1", "/work", events.append)
        ws.push({"type": "events", "events": [{"type": "remove", "path": "/work", "is_dir": True}]})
        ws.push({"type": "end", "reason": "the watched folder was removed"})
        with self.assertRaises(MicroVMError) as ctx:
            handle.wait(5)
        self.assertEqual(str(ctx.exception), "the watched folder was removed")
        self.assertEqual(events, [FileEvent("remove", "/work", is_dir=True)])
        self.assertTrue(ws.closed)

    def test_stop_ends_wait_normally_and_is_idempotent(self):
        ws = self.started()
        self.use(FakeModule(ws))
        handle = self.client.watch_files("sb-1", "/work", lambda ev: None)
        handle.stop()
        handle.stop()
        self.assertIsNone(handle.wait(5))
        self.assertTrue(handle.done.done())
        self.assertTrue(ws.closed)

    def test_dropped_connection_fails_wait(self):
        ws = self.started()
        self.use(FakeModule(ws))
        handle = self.client.watch_files("sb-1", "/work", lambda ev: None)
        ws.push(ConnectionResetError("reset by peer"))
        with self.assertRaises(MicroVMError) as ctx:
            handle.wait(5)
        self.assertIn("reset by peer", str(ctx.exception))

    def test_callback_error_ends_the_watch_with_it(self):
        ws = self.started()
        self.use(FakeModule(ws))

        def boom(ev):
            raise ValueError("callback broke")

        handle = self.client.watch_files("sb-1", "/work", boom)
        ws.push({"type": "events", "events": [{"type": "create", "path": "/work/a"}]})
        with self.assertRaises(MicroVMError) as ctx:
            handle.wait(5)
        self.assertIn("callback broke", str(ctx.exception))

    def test_wait_times_out_while_running(self):
        ws = self.started()
        self.use(FakeModule(ws))
        handle = self.client.watch_files("sb-1", "/work", lambda ev: None)
        with self.assertRaises(TimeoutError):
            handle.wait(0.05)
        handle.stop()

    def test_old_agent_is_an_unsupported_feature(self):
        cases = [
            FakeBadStatus(404, '{"error":"not found"}', {"x-toolbox-route": "none"}),
            FakeBadStatus(404, "", {"X-Toolbox-Route": "none"}),
            FakeBadStatus(404, '{"error":"not found"}'),
        ]
        for error in cases:
            self.use(FakeModule(error=error))
            with self.assertRaises(MicroVMUnsupportedFeatureError) as ctx:
                self.client.watch_files("sb-1", "/work", lambda ev: None)
            self.assertEqual(ctx.exception.features, ["files.watch"])
            self.assertEqual(ctx.exception.sandbox_id, "sb-1")
            self.assertIn("restart the sandbox", str(ctx.exception))

    def test_other_refusals_are_http_errors(self):
        cases = [
            (501, '{"error":"file watching needs a gVisor or Firecracker sandbox"}', {}),
            (404, '{"error":"path not found: /x"}', {}),
            (404, '{"error":"sandbox not found"}', {}),
            (409, '{"error":"not a folder: /x"}', {}),
            (429, '{"error":"too many file watches open in this sandbox; stop one first"}', {"retry-after": "2"}),
            (502, "<html>bad gateway</html>", {}),
        ]
        for status, body, headers in cases:
            self.use(FakeModule(error=FakeBadStatus(status, body, headers)))
            with self.assertRaises(MicroVMHTTPError) as ctx:
                self.client.watch_files("sb-1", "/x", lambda ev: None)
            err = ctx.exception
            self.assertNotIsInstance(err, MicroVMUnsupportedFeatureError)
            self.assertEqual(err.status_code, status)
            expected = json.loads(body)["error"] if body.startswith("{") else body
            self.assertEqual(str(err), expected)
            if status == 429:
                self.assertEqual(err.retry_after, 2.0)

    def test_transport_failure_is_a_plain_error(self):
        self.use(FakeModule(error=OSError("connection refused")))
        with self.assertRaises(MicroVMError) as ctx:
            self.client.watch_files("sb-1", "/work", lambda ev: None)
        self.assertNotIsInstance(ctx.exception, MicroVMHTTPError)
        self.assertIn("connection refused", str(ctx.exception))

    def test_closed_or_wrong_first_frame_is_an_error(self):
        ws = QueueWebSocket()
        ws.push(ConnectionResetError("gone"))
        self.use(FakeModule(ws))
        with self.assertRaises(MicroVMError) as ctx:
            self.client.watch_files("sb-1", "/work", lambda ev: None)
        self.assertIn("before it started", str(ctx.exception))
        self.assertTrue(ws.closed)

        ws = QueueWebSocket()
        ws.push({"type": "events", "events": []})
        self.use(FakeModule(ws))
        with self.assertRaises(MicroVMError) as ctx:
            self.client.watch_files("sb-1", "/work", lambda ev: None)
        self.assertIn("did not start", str(ctx.exception))
        self.assertTrue(ws.closed)

    def test_path_and_callback_are_required(self):
        module = self.use(FakeModule(self.started()))
        with self.assertRaises(MicroVMError):
            self.client.watch_files("sb-1", "  ", lambda ev: None)
        with self.assertRaises(MicroVMError):
            self.client.watch_files("sb-1", "/work", None)  # type: ignore[arg-type]
        self.assertEqual(module.calls, [])

    def test_sandbox_watch_files_uses_its_id(self):
        module = self.use(FakeModule(self.started(True)))
        sandbox = client_module.Sandbox(self.client, {"id": "sb-9"})
        handle = sandbox.watch_files("/work", lambda ev: None, recursive=True)
        handle.stop()
        parsed = urllib.parse.urlparse(module.calls[0][0])
        self.assertEqual(parsed.path, "/v1/sandboxes/sb-9/toolbox/files/watch")
        self.assertEqual(urllib.parse.parse_qs(parsed.query)["recursive"], ["true"])


if __name__ == "__main__":
    unittest.main()
