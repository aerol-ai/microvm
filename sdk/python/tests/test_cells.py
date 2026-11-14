"""Cell redirects (C16): a 421 carrying X-Aerolvm-Cell-Endpoint sends the
request once to the cell it names, and the client remembers that cell for
the sandbox. CellRedirectTests runs on MicroVM; AsyncCellRedirectTests runs
the same scenarios on AsyncMicroVM (with the optional httpx)."""

import asyncio
import email.message
import http.server
import io
import json
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request

from microvm import AsyncMicroVM, MicroVM, MicroVMHTTPError, MicroVMNotFoundError
from microvm import client as client_module
from microvm.client import CELL_ENDPOINT_HEADER

try:  # discover -s tests puts tests/ on the path; -m tests.test_cells does not
    from test_client import FakeWebSocket, FakeWebSocketModule
except ImportError:
    from tests.test_client import FakeWebSocket, FakeWebSocketModule

try:
    import httpx
except ImportError:  # the sync-only install
    httpx = None

_FAST = {"retry": {"maxRetries": 3, "baseDelayMs": 1, "maxDelayMs": 1}}
_MOVED = {"error": "this sandbox is in another cell"}
_EXEC = {"exit_code": 0, "stdout": "hi\n", "stderr": ""}


def _sandbox(sandbox_id):
    return {"id": sandbox_id, "name": sandbox_id, "image": "alpine", "status": "started", "lifecycle": {}}


def _serve(method, path):
    """What a cell that holds the sandbox answers."""
    if path.endswith("/toolbox/process/execute"):
        return 200, _EXEC, None
    if method == "GET" and path.startswith("/v1/sandboxes/"):
        return 200, _sandbox(path.split("/")[3].split("?")[0]), None
    return 200, {}, None


def _cell_server(test, answer):
    """A local server standing in for one cell. ``answer(method, path)``
    gives (status, JSON body, headers). Every request is recorded as
    (method, path, headers, body)."""
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            body_in = b""
            if self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    size = int(self.rfile.readline().strip() or b"0", 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    body_in += self.rfile.read(size)
                    self.rfile.readline()
            else:
                length = int(self.headers.get("Content-Length") or 0)
                body_in = self.rfile.read(length) if length else b""
            hits.append((self.command, self.path, self.headers, body_in))
            status, body, headers = answer(self.command, self.path)
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = do_DELETE = do_PUT = _answer

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return "http://127.0.0.1:%d" % server.server_port, hits


def _paths(hits):
    return [path.split("?")[0] for _, path, _, _ in hits]


class _SyncDriver:
    """Runs ``fn(client)`` on a MicroVM."""

    def __init__(self, test, url, **kwargs):
        self.client = MicroVM(url, "pat", config=_FAST, **kwargs)

    def __call__(self, fn):
        return fn(self.client)

    @classmethod
    def answering(cls, test, url, status, headers, body):
        """A client whose every request gets this answer, with no server.
        Returns the driver and the list of URLs it sent to."""
        sent = []

        def urlopen(request, **kwargs):
            sent.append(request.full_url)
            message = email.message.Message()
            for key, value in headers.items():
                message[key] = value
            raise urllib.error.HTTPError(request.full_url, status, "Misdirected Request", message, io.BytesIO(body))

        patcher = unittest.mock.patch.object(urllib.request, "urlopen", side_effect=urlopen)
        patcher.start()
        test.addCleanup(patcher.stop)
        return cls(test, url), sent


class _AsyncDriver:
    """Runs ``fn(client)`` on an AsyncMicroVM, on one event loop for the
    whole test (the routes live in the client, and httpx's pool is bound to
    its loop), so a scenario reads the same as on MicroVM."""

    def __init__(self, test, url, http_client=None, **kwargs):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        test.addCleanup(self._close)

        async def make():
            return AsyncMicroVM(url, "pat", config=_FAST, http_client=http_client, **kwargs)

        self.http_client = http_client
        self.client = self._await(make())

    def _await(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    def __call__(self, fn):
        return self._await(fn(self.client))

    def _close(self):
        self._await(self.client.close())
        if self.http_client is not None:
            self._await(self.http_client.aclose())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()

    @classmethod
    def answering(cls, test, url, status, headers, body):
        sent = []

        def handler(request):
            sent.append(str(request.url))
            return httpx.Response(status, headers=headers, content=body)

        return cls(test, url, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))), sent


class CellRedirectTests(unittest.TestCase):
    driver = _SyncDriver

    def two_cells(self, cell2=_serve):
        """Cell 1 answers anything for sb-x with a 421 naming cell 2, and
        serves every other sandbox itself."""
        urls = {}

        def cell1(method, path):
            if path.startswith("/v1/sandboxes/sb-x"):
                return 421, _MOVED, {CELL_ENDPOINT_HEADER: urls["cell2"]}
            return _serve(method, path)

        urls["cell2"], hits2 = _cell_server(self, cell2)
        url1, hits1 = _cell_server(self, cell1)
        return url1, hits1, urls["cell2"], hits2

    def test_a_cell_redirect_resends_the_request_to_that_cell(self):
        # exec is not idempotent, and is followed anyway: the other cell
        # answered before doing anything.
        url1, hits1, _, hits2 = self.two_cells()
        call = self.driver(self, url1, team="t1", headers={"X-Trace": "abc"})

        result = call(lambda c: c.exec("sb-x", {"command": "echo hi"}))

        self.assertEqual(result["stdout"], "hi\n")
        self.assertEqual(_paths(hits1), ["/v1/sandboxes/sb-x/toolbox/process/execute"])
        self.assertEqual(_paths(hits2), ["/v1/sandboxes/sb-x/toolbox/process/execute"])
        (method1, _, headers1, body1), (method2, _, headers2, body2) = hits1[0], hits2[0]
        self.assertEqual((method2, body2), (method1, body1))
        self.assertEqual(json.loads(body2)["command"], "echo hi")
        for name in ("Authorization", "X-AerolVM-Team", "X-Trace", "Content-Type"):
            self.assertEqual(headers2.get(name), headers1.get(name), name)
        self.assertEqual(headers2.get("Authorization"), "Bearer pat")

    def test_the_cell_is_remembered_per_sandbox(self):
        url1, hits1, url2, hits2 = self.two_cells()
        call = self.driver(self, url1)

        self.assertEqual(call(lambda c: c.get("sb-x")).id, "sb-x")
        self.assertEqual(call(lambda c: c.get("sb-x")).id, "sb-x")
        self.assertEqual(call(lambda c: c.get("sb-y")).id, "sb-y")

        self.assertEqual(_paths(hits1), ["/v1/sandboxes/sb-x", "/v1/sandboxes/sb-y"])
        self.assertEqual(_paths(hits2), ["/v1/sandboxes/sb-x", "/v1/sandboxes/sb-x"])
        self.assertEqual(dict(call.client._cell_routes), {"sb-x": url2})

    def test_a_421_without_the_header_is_retried_on_the_same_cell(self):
        def cell1(method, path):
            if len(hits1) == 1:
                return 421, {"error": "misdirected request; reconnect"}, {"Connection": "close"}
            return _serve(method, path)

        url1, hits1 = _cell_server(self, cell1)
        call = self.driver(self, url1)

        self.assertEqual(call(lambda c: c.get("sb-x")).id, "sb-x")
        self.assertEqual(_paths(hits1), ["/v1/sandboxes/sb-x", "/v1/sandboxes/sb-x"])
        self.assertEqual(dict(call.client._cell_routes), {})

    def test_a_second_cell_redirect_is_not_followed(self):
        # Cell 2 names cell 1 back: following it would loop.
        urls = {}
        url1, hits1, _, hits2 = self.two_cells(cell2=lambda m, p: (421, _MOVED, {CELL_ENDPOINT_HEADER: urls["cell1"]}))
        urls["cell1"] = url1
        call = self.driver(self, url1)

        with self.assertRaises(MicroVMHTTPError) as ctx:
            call(lambda c: c.get("sb-x"))

        self.assertEqual(ctx.exception.status_code, 421)
        self.assertEqual((len(hits1), len(hits2)), (1, 1))

    def test_an_https_client_does_not_follow_an_http_cell(self):
        call, sent = self.driver.answering(
            self, "https://cell1.test", 421, {CELL_ENDPOINT_HEADER: "http://cell2.test"}, json.dumps(_MOVED).encode()
        )

        with self.assertRaises(MicroVMHTTPError) as ctx:
            call(lambda c: c.get("sb-x"))

        self.assertEqual(ctx.exception.status_code, 421)
        self.assertEqual(sent, ["https://cell1.test/v1/sandboxes/sb-x"])
        self.assertEqual(dict(call.client._cell_routes), {})

    def test_a_404_from_the_remembered_cell_forgets_it(self):
        def cell2(method, path):
            if len(hits2) == 1:
                return _serve(method, path)
            return 404, {"error": "sandbox not found"}, None

        url1, hits1, url2, hits2 = self.two_cells(cell2=cell2)
        call = self.driver(self, url1)

        call(lambda c: c.get("sb-x"))
        self.assertEqual(dict(call.client._cell_routes), {"sb-x": url2})
        with self.assertRaises(MicroVMNotFoundError):
            call(lambda c: c.get("sb-x"))
        self.assertEqual(dict(call.client._cell_routes), {})
        # Forgotten: the next call asks the configured cell again.
        with self.assertRaises(MicroVMNotFoundError):
            call(lambda c: c.get("sb-x"))

        self.assertEqual(_paths(hits1), ["/v1/sandboxes/sb-x", "/v1/sandboxes/sb-x"])
        self.assertEqual(len(hits2), 3)

    def test_a_missing_file_keeps_the_route(self):
        # The sandbox itself answered that 404, so it is still in cell 2.
        def cell2(method, path):
            if "/toolbox/files/info" in path:
                return 404, {"error": "path not found", "code": "file_not_found"}, None
            return _serve(method, path)

        url1, hits1, url2, _ = self.two_cells(cell2=cell2)
        call = self.driver(self, url1)

        self.assertFalse(call(lambda c: c.file_exists("sb-x", "/nope")))
        self.assertFalse(call(lambda c: c.file_exists("sb-x", "/nope")))

        self.assertEqual(len(hits1), 1)
        self.assertEqual(dict(call.client._cell_routes), {"sb-x": url2})

    def test_a_streamed_body_is_not_resent_but_the_cell_is_remembered(self):
        url1, hits1, url2, hits2 = self.two_cells()
        call = self.driver(self, url1)

        with self.assertRaises(MicroVMHTTPError) as ctx:
            call(lambda c: c.upload_file_from("sb-x", "/dst", io.BytesIO(b"streamed body"), chunk_size=4))
        self.assertEqual(ctx.exception.status_code, 421)
        self.assertEqual((len(hits1), len(hits2)), (1, 0))
        self.assertEqual(dict(call.client._cell_routes), {"sb-x": url2})

        # The caller's own retry goes straight to the right cell.
        call(lambda c: c.upload_file_from("sb-x", "/dst", io.BytesIO(b"streamed body"), chunk_size=4))
        self.assertEqual(len(hits1), 1)
        self.assertIn(b"streamed body", hits2[0][3])

    def test_a_body_in_memory_is_resent(self):
        url1, hits1, _, hits2 = self.two_cells()
        call = self.driver(self, url1)

        call(lambda c: c.upload_file("sb-x", "/f", b"plain body"))

        self.assertEqual((len(hits1), len(hits2)), (1, 1))
        self.assertIn(b"plain body", hits2[0][3])
        self.assertEqual(hits2[0][3], hits1[0][3])

    def test_the_cell_base_keeps_its_own_path_prefix(self):
        urls = {}

        def cell1(method, path):
            return 421, _MOVED, {CELL_ENDPOINT_HEADER: urls["cell2"] + "/edge/"}

        urls["cell2"], hits2 = _cell_server(self, lambda m, p: _serve(m, p[len("/edge"):]))
        url1, hits1 = _cell_server(self, cell1)
        call = self.driver(self, url1 + "/api")

        self.assertEqual(call(lambda c: c.get("sb-x")).id, "sb-x")

        self.assertEqual(_paths(hits1), ["/api/v1/sandboxes/sb-x"])
        self.assertEqual(_paths(hits2), ["/edge/v1/sandboxes/sb-x"])
        self.assertEqual(dict(call.client._cell_routes), {"sb-x": urls["cell2"] + "/edge"})


@unittest.skipIf(httpx is None, "AsyncMicroVM needs the optional httpx")
class AsyncCellRedirectTests(CellRedirectTests):
    driver = _AsyncDriver


class CellRouteTests(unittest.TestCase):
    """The pieces under the redirect: parsing the header, the downgrade
    rule, the bound, and the stream handshakes."""

    def test_cell_endpoint_values(self):
        cases = [
            ("https://cell2.example.com", "https://cell2.example.com"),
            ("https://cell2.example.com/", "https://cell2.example.com"),
            ("http://10.0.0.2:8080/prefix/", "http://10.0.0.2:8080/prefix"),
            ("HTTPS://cell2.example.com", "https://cell2.example.com"),
            ("", None),
            ("cell2.example.com", None),
            ("/v1/elsewhere", None),
            ("ftp://cell2.example.com", None),
            ("https://", None),
            ("https://cell2.example.com?x=1", None),
            ("https://cell2.example.com#x", None),
            ("https://cell2.example.com:port", None),
            ("https://cell2 .example.com", None),
        ]
        for value, want in cases:
            with self.subTest(value=value):
                self.assertEqual(client_module._cell_endpoint(value), want)

    def test_only_https_to_http_is_refused(self):
        cases = [
            ("https://cell1.test", "http://cell2.test", None),
            ("HTTPS://cell1.test", "http://cell2.test", None),
            ("https://cell1.test", "https://cell2.test", "https://cell2.test"),
            ("http://cell1.test", "https://cell2.test", "https://cell2.test"),
            ("http://cell1.test", "http://cell2.test", "http://cell2.test"),
        ]
        for api_url, header, want in cases:
            with self.subTest(api_url=api_url, header=header):
                client = MicroVM(api_url, "pat")
                self.assertEqual(client._learn_cell("sb-x", header), want)
                self.assertEqual(dict(client._cell_routes), {} if want is None else {"sb-x": want})

    def test_the_sandbox_id_comes_from_the_path(self):
        cases = [
            ("/v1/sandboxes/sb-1", "sb-1"),
            ("/v1/sandboxes/sb-1?include_env=true", "sb-1"),
            ("/v1/sandboxes/sb%2D1/toolbox/files?path=%2Fa", "sb-1"),
            ("/v1/sandboxes", ""),
            ("/v1/sandboxes?tags=a", ""),
            ("/v1/snapshots/sb-1", ""),
        ]
        for path, want in cases:
            with self.subTest(path=path):
                self.assertEqual(client_module._path_sandbox_id(path, "/v1"), want)

    def test_routes_are_bounded_oldest_first(self):
        client = MicroVM("http://cell1.test", "pat")
        with unittest.mock.patch.object(client_module, "_MAX_CELL_ROUTES", 2):
            for sandbox_id in ("sb-a", "sb-b", "sb-c"):
                client._learn_cell(sandbox_id, "http://cell2.test")
            self.assertEqual(list(client._cell_routes), ["sb-b", "sb-c"])
            # Learning one again makes it the newest.
            client._learn_cell("sb-b", "http://cell3.test")
            client._learn_cell("sb-d", "http://cell2.test")
            self.assertEqual(dict(client._cell_routes), {"sb-b": "http://cell3.test", "sb-d": "http://cell2.test"})

    def test_routes_stay_bounded_under_concurrent_use(self):
        client = MicroVM("http://cell1.test", "pat")
        with unittest.mock.patch.object(client_module, "_MAX_CELL_ROUTES", 50):
            def learn(worker):
                for i in range(200):
                    client._learn_cell("sb-%d-%d" % (worker, i), "http://cell2.test")
                    client._cell_base("sb-%d-%d" % (worker, i // 2))

            threads = [threading.Thread(target=learn, args=(w,)) for w in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(client._cell_routes), 50)

    def test_a_stream_opens_on_the_remembered_cell(self):
        cases = [("sb-x", "wss://cell2.example.com/v1/sandboxes/sb-x/toolbox/process/exec/stream"),
                 ("sb-y", "wss://sandbox.example.com/v1/sandboxes/sb-y/toolbox/process/exec/stream")]
        client = MicroVM("https://sandbox.example.com", "pat")
        client._learn_cell("sb-x", "https://cell2.example.com")
        for sandbox_id, want in cases:
            with self.subTest(sandbox=sandbox_id):
                module = FakeWebSocketModule(FakeWebSocket([json.dumps({"type": "exit", "code": 0})]))
                with unittest.mock.patch.object(client_module, "_load_websocket_module", return_value=module):
                    client.exec_stream(sandbox_id, {"command": "true"}).wait(1)
                self.assertEqual(module.calls[0][0], want)


if __name__ == "__main__":
    unittest.main()
