"""AsyncMicroVM (plan S1): the same calls as MicroVM, from the same ops,
over httpx. The parity tests need nothing; the behaviour tests need the
optional httpx and skip without it."""

import asyncio
import http.server
import inspect
import io
import json
import threading
import time
import unittest
import unittest.mock

from microvm import (
    AsyncExecStreamHandle,
    AsyncFileWatchHandle,
    AsyncMicroVM,
    AsyncSandbox,
    AsyncSessionAttachHandle,
    AsyncTokens,
    FileWatchHandle,
    MicroVM,
    MicroVMError,
    MicroVMFileTooLargeError,
    MicroVMHTTPError,
    MicroVMNotFoundError,
    MicroVMTimeoutError,
    Tokens,
)
from microvm import aio as aio_module
from microvm import client as client_module

try:  # discover -s tests puts tests/ on the path; -m tests.test_async does not
    from test_fleet import FakeSandboxd
except ImportError:
    from tests.test_fleet import FakeSandboxd

try:
    import httpx
except ImportError:  # the sync-only install
    httpx = None

needs_httpx = unittest.skipIf(httpx is None, "AsyncMicroVM needs the optional httpx")
_FAST = {"retry": {"maxRetries": 3, "baseDelayMs": 1, "maxDelayMs": 1}}
_SANDBOX = {"id": "sb-1", "name": "a", "image": "alpine", "status": "started", "lifecycle": {}}


def _public(cls):
    return {name for name in dir(cls) if not name.startswith("_")}


class AsyncParityTests(unittest.TestCase):
    """The two clients cannot drift: same public calls, same parameters."""

    PAIRS = [
        (MicroVM, AsyncMicroVM),
        (client_module.Sandbox, AsyncSandbox),
        (Tokens, AsyncTokens),
        (client_module.ExecStreamHandle, AsyncExecStreamHandle),
        (client_module.SessionAttachHandle, AsyncSessionAttachHandle),
        (FileWatchHandle, AsyncFileWatchHandle),
    ]

    def test_public_calls_and_parameters_match(self):
        for sync_cls, async_cls in self.PAIRS:
            with self.subTest(cls=sync_cls.__name__):
                self.assertEqual(_public(sync_cls), _public(async_cls))
            for name in sorted(_public(sync_cls)):
                sync_member = inspect.getattr_static(sync_cls, name)
                async_member = inspect.getattr_static(async_cls, name)
                with self.subTest(member=f"{sync_cls.__name__}.{name}"):
                    if isinstance(sync_member, property) or not callable(getattr(sync_cls, name)):
                        self.assertEqual(type(sync_member), type(async_member))
                        continue
                    sync_fn, async_fn = getattr(sync_cls, name), getattr(async_cls, name)
                    shape = lambda fn: [(p.name, p.kind, p.default) for p in inspect.signature(fn).parameters.values()]
                    self.assertEqual(shape(sync_fn), shape(async_fn))
                    if sync_cls is not client_module.Sandbox or name != "to_dict":
                        self.assertTrue(
                            inspect.iscoroutinefunction(async_fn) or inspect.isasyncgenfunction(async_fn),
                            "not a coroutine",
                        )

    def test_every_op_is_a_generator(self):
        ops = [name for name in dir(client_module._MicroVMCore) if name.startswith("_op_")]
        self.assertGreater(len(ops), 80)
        for name in ops:
            self.assertTrue(inspect.isgeneratorfunction(getattr(client_module._MicroVMCore, name)), name)

    def test_async_calls_carry_the_sync_docs(self):
        for name in ("get_or_create", "destroy_all", "upload_file", "watch_files"):
            self.assertEqual(getattr(AsyncMicroVM, name).__doc__, getattr(MicroVM, name).__doc__)
        self.assertEqual(AsyncTokens.create.__doc__, Tokens.create.__doc__)

    def test_without_httpx_the_error_names_the_extra(self):
        with unittest.mock.patch.object(aio_module, "httpx", None):
            with self.assertRaises(MicroVMError) as ctx:
                AsyncMicroVM("http://127.0.0.1:9", "pat")
        self.assertIn("aerolvm-sdk[async]", str(ctx.exception))


def _scripted_server(test, script):
    """Answers each request with the next (status, body, headers) in
    ``script``; the last one repeats. Records (method, path)."""
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            body_in = self.rfile.read(length) if length else b""
            if self.headers.get("Transfer-Encoding") == "chunked":
                body_in = b""
                while True:
                    size = int(self.rfile.readline().strip() or b"0", 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    body_in += self.rfile.read(size)
                    self.rfile.readline()
            hits.append((self.command, self.path, body_in))
            status, body, headers = script[min(len(hits) - 1, len(script) - 1)]
            if callable(body):
                body = body(self)
                if body is None:
                    return
            raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = _answer

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return "http://127.0.0.1:%d" % server.server_port, hits


@needs_httpx
class AsyncRetryParityTests(unittest.TestCase):
    """One scenario table, both transports: the same attempts and the same
    outcome, so the httpx retry loop cannot drift from urllib's."""

    def run_both(self, script, call):
        results = []
        for kind in ("sync", "async"):
            url, hits = _scripted_server(self, script)
            if kind == "sync":
                client = MicroVM(url, "pat", config=_FAST)
                try:
                    outcome = ("ok", call(client))
                except MicroVMHTTPError as err:
                    outcome = (type(err).__name__, err.status_code, err.code, str(err))
            else:
                async def go():
                    async with AsyncMicroVM(url, "pat", config=_FAST) as client:
                        try:
                            return ("ok", await call(client))
                        except MicroVMHTTPError as err:
                            return (type(err).__name__, err.status_code, err.code, str(err))

                outcome = asyncio.run(go())
            results.append((outcome, len(hits)))
        return results

    def test_statuses_by_retry_tier(self):
        busy = {"error": "busy", "code": "overloaded"}
        cases = [
            # (name, script, call, want attempts)
            ("get retries 503 then succeeds", [(503, busy, {"Retry-After": "0"}), (200, _SANDBOX, None)], lambda c: c.get("sb-1"), 2),
            ("get retries 421, 502 and 504", [(421, busy, None), (502, b"<html>bad</html>", None), (504, busy, None), (200, _SANDBOX, None)], lambda c: c.get("sb-1"), 4),
            ("get gives up after the retries", [(502, b"<html>bad</html>", None)], lambda c: c.get("sb-1"), 4),
            ("get does not retry 404", [(404, {"error": "sandbox not found"}, None)], lambda c: c.get("sb-1"), 1),
            ("get does not retry 422", [(422, {"error": "no", "code": "idempotency_key_reused"}, None)], lambda c: c.get("sb-1"), 1),
            ("exec does not retry 502", [(502, b"<html>bad</html>", None)], lambda c: c.exec("sb-1", {"command": "true"}), 1),
            ("exec retries 429", [(429, busy, {"Retry-After": "0"}), (200, {"exit_code": 0, "stdout": "", "stderr": ""}, None)], lambda c: c.exec("sb-1", {"command": "true"}), 2),
            (
                "a retried delete that finds the file gone succeeds",
                [(503, busy, None), (404, {"error": "gone", "code": "file_not_found"}, None)],
                lambda c: c.delete_file("sb-1", "/f"),
                2,
            ),
            ("a first delete of a missing file fails", [(404, {"error": "gone", "code": "file_not_found"}, None)], lambda c: c.delete_file("sb-1", "/f"), 1),
        ]
        for name, script, call, want in cases:
            with self.subTest(name):
                (sync_outcome, sync_hits), (async_outcome, async_hits) = self.run_both(script, call)
                if sync_outcome[0] == "ok":
                    self.assertEqual(async_outcome[0], "ok")
                else:
                    self.assertEqual(sync_outcome, async_outcome)
                self.assertEqual((sync_hits, async_hits), (want, want))


@needs_httpx
class AsyncClientTests(unittest.TestCase):
    def test_get_or_create_gives_concurrent_tasks_one_sandbox(self):
        callers = 8
        fake = FakeSandboxd(self, lookup_barrier=callers)

        async def go():
            async with AsyncMicroVM(fake.url, "pat", config={"retry": {"maxRetries": 0}}) as client:
                return await asyncio.gather(*(client.get_or_create("shared", image="alpine") for _ in range(callers)))

        results = asyncio.run(go())
        self.assertEqual(len({sandbox.id for sandbox, _ in results}), 1)
        self.assertEqual(sum(1 for _, created in results if created), 1)
        self.assertTrue(all(isinstance(sandbox, AsyncSandbox) for sandbox, _ in results))

    def test_destroy_all_and_async_with_delete_on_exit(self):
        fake = FakeSandboxd(self)
        for i in range(3):
            fake.add("a-%d" % i, {"run": "42"})

        async def go():
            async with AsyncMicroVM(fake.url, "pat") as client:
                gone = await client.destroy_all(tags={"run": "42"})
                async with await client.create(image="alpine", name="kept") as kept:
                    pass
                async with await client.create(image="alpine", name="temp", destroy_on_exit=True) as temp:
                    self.assertTrue(temp.destroy_on_exit)
                pages = [page async for page in client.iter_pages()]
                return gone, kept.id, pages

        gone, kept_id, pages = asyncio.run(go())
        self.assertEqual(len(gone), 3)
        self.assertEqual([[s.id for s in page] for page in pages], [[kept_id]])

    def test_typed_errors_and_the_per_call_timeout(self):
        def slow(handler):
            time.sleep(5)
            return _SANDBOX

        url, _ = _scripted_server(self, [(200, slow, None)])
        missing_url, _ = _scripted_server(self, [(404, {"error": "sandbox not found"}, None)])

        async def go():
            async with AsyncMicroVM(url, "pat") as client, AsyncMicroVM(missing_url, "pat") as missing:
                started = time.monotonic()
                with self.assertRaises(MicroVMTimeoutError) as ctx:
                    await client.get("sb-1", timeout=0.3)
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(ctx.exception.status_code, 0)
                with self.assertRaises(MicroVMNotFoundError):
                    await missing.get("sb-1")

        asyncio.run(go())

    def test_files_stream_both_ways(self):
        payload = b"x" * 5000

        def chunked(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/octet-stream")
            handler.end_headers()
            for start in range(0, len(payload), 1000):
                handler.wfile.write(payload[start : start + 1000])
            return None

        url, hits = _scripted_server(self, [(200, chunked, None)])
        upload_url, upload_hits = _scripted_server(self, [(201, {}, None)])

        async def go():
            async with AsyncMicroVM(url, "pat") as client, AsyncMicroVM(upload_url, "pat") as uploads:
                whole = await client.download_file("sb-1", "/f")
                sink = io.BytesIO()
                with self.assertRaises(MicroVMFileTooLargeError):
                    await client.download_file_to("sb-1", "/f", sink, max_bytes=1500, chunk_size=700)
                await uploads.upload_file_from("sb-1", "/dst", io.BytesIO(b"streamed body"), chunk_size=4)
                await uploads.upload_file("sb-1", "/plain", b"plain body")
                return whole, sink.getvalue()

        whole, partial = asyncio.run(go())
        self.assertEqual(whole, payload)
        self.assertEqual(partial, payload[:1500])
        self.assertIn(b"streamed body", upload_hits[0][2])
        self.assertIn(b"plain body", upload_hits[1][2])

    def test_stream_callbacks_run_on_the_event_loop(self):
        class FakeWS:
            def __init__(self):
                self.frames = [b"\x01hello", json.dumps({"type": "exit", "code": 0})]
                self.sent = []

            def send(self, payload, opcode=None):
                self.sent.append(payload)

            def recv(self):
                time.sleep(0.02)
                return self.frames.pop(0)

            def settimeout(self, value):
                pass

            def close(self):
                pass

        ws = FakeWS()

        class FakeModule:
            class ABNF:
                OPCODE_BINARY = 2

            @staticmethod
            def create_connection(url, **kwargs):
                return ws

        seen = []

        async def go():
            loop_thread = threading.get_ident()
            async with AsyncMicroVM("http://127.0.0.1:9", "pat") as client:
                handle = await client.exec_stream(
                    "sb-1", {"command": "echo hello", "onStdout": lambda chunk: seen.append((chunk, threading.get_ident() == loop_thread))}
                )
                self.assertIsInstance(handle, AsyncExecStreamHandle)
                await handle.write("input")
                exit_info = await handle.wait(5)
                await asyncio.sleep(0.05)
                return exit_info

        with unittest.mock.patch.object(client_module, "_load_websocket_module", lambda: FakeModule):
            exit_info = asyncio.run(go())
        self.assertEqual(exit_info, {"code": 0})
        self.assertEqual(seen, [(b"hello", True)])
        self.assertIn(b"input", ws.sent)

    def test_watch_and_attach_run_their_callbacks_on_the_loop(self):
        class FakeWS:
            def __init__(self, frames):
                self.frames = list(frames)
                self.sent = []

            def send(self, payload, opcode=None):
                self.sent.append(payload)

            def recv(self):
                time.sleep(0.02)
                if not self.frames:
                    raise ConnectionError("closed")
                return self.frames.pop(0)

            def settimeout(self, value):
                pass

            def close(self):
                self.frames = []

        sockets = {
            "watch": FakeWS([
                json.dumps({"type": "start"}),
                json.dumps({"type": "events", "events": [{"type": "create", "path": "/w/a.txt"}]}),
                json.dumps({"type": "end", "reason": "the watched folder was removed"}),
            ]),
            "attach": FakeWS([b"\x02oops", json.dumps({"type": "exit", "code": 3})]),
        }

        class FakeModule:
            class ABNF:
                OPCODE_BINARY = 2

            @staticmethod
            def create_connection(url, **kwargs):
                return sockets["watch" if "/files/watch" in url else "attach"]

        events, errors = [], []

        async def go():
            loop_thread = threading.get_ident()
            async with AsyncMicroVM("http://127.0.0.1:9", "pat") as client:
                watch = await client.watch_files("sb-1", "/w", lambda e: events.append((e.path, threading.get_ident() == loop_thread)))
                self.assertIsInstance(watch, AsyncFileWatchHandle)
                with self.assertRaises(MicroVMError):
                    await watch.wait(5)
                attach = await client.attach_session(
                    "sb-1", "sess-1", {"cols": 80, "rows": 24, "onStderr": lambda c: errors.append((c, threading.get_ident() == loop_thread))}
                )
                self.assertIsInstance(attach, AsyncSessionAttachHandle)
                info = await attach.wait(5)
                await asyncio.sleep(0.05)
                return info

        with unittest.mock.patch.object(client_module, "_load_websocket_module", lambda: FakeModule):
            info = asyncio.run(go())
        self.assertEqual(events, [("/w/a.txt", True)])
        self.assertEqual(errors, [(b"oops", True)])
        self.assertEqual(info, {"code": 3})
        self.assertIn('"resize"', sockets["attach"].sent[0])

    def test_tokens_and_a_passed_in_http_client(self):
        url, hits = _scripted_server(self, [(200, {"tokens": [{"id": "tok_1", "name": "ci"}]}, None)])

        async def go():
            async with httpx.AsyncClient() as http:
                client = AsyncMicroVM(url, "pat", http_client=http, headers={"X-Proxy-Auth": "abc"})
                listed = await client.tokens.list()
                await client.close()  # the caller's pool stays open
                self.assertFalse(http.is_closed)
                return listed

        listed = asyncio.run(go())
        self.assertEqual(listed["tokens"][0]["id"], "tok_1")


if __name__ == "__main__":
    unittest.main()
