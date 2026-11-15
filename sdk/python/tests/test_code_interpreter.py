"""The code interpreter: contexts over REST and runs over a WebSocket
(plans/code-interpreter.md, section 4.1), on both clients."""

import asyncio
import json
import queue
import threading
import time
import unittest
import unittest.mock

from microvm import (
    CodeContext,
    CodeResult,
    CodeRunHandle,
    Execution,
    ExecutionError,
    MicroVM,
    MicroVMCodeRunError,
    MicroVMCodeTimeoutError,
    MicroVMError,
    MicroVMHTTPError,
    MicroVMUnsupportedFeatureError,
)
from microvm import client as client_module

try:  # discover -s tests puts tests/ on the path; -m tests.test_... does not
    from test_async import _scripted_server
except ImportError:
    from tests.test_async import _scripted_server

try:
    import httpx
except ImportError:  # the sync-only install
    httpx = None

needs_httpx = unittest.skipIf(httpx is None, "AsyncMicroVM needs the optional httpx")

_FEATURE = "code.interpreter"
_BASE = "/v1/sandboxes/sb-1/toolbox"
_CONTEXT = {"id": "ctx-1", "language": "python", "cwd": "/work", "createdAt": "2026-11-15T10:00:00Z", "active": True}
_TEXT, _CLOSE = 0x1, 0x8


def _close(code=None, reason=""):
    return (_CLOSE, b"" if code is None else code.to_bytes(2, "big") + reason.encode("utf-8"))


def _text(frame):
    return (_TEXT, (frame if isinstance(frame, str) else json.dumps(frame)).encode("utf-8"))


class FakeCodeSocket:
    """websocket-client's socket as a code run uses it: recv_data blocks
    until the test (or on_send) pushes a frame, as a run still going would."""

    def __init__(self, frames=(), on_send=None):
        self.incoming = queue.Queue()
        self.sent = []
        self.on_send = on_send
        self.aborted = threading.Event()
        self.closed = threading.Event()
        for frame in frames:
            self.push(frame)

    def push(self, frame):
        self.incoming.put(frame if isinstance(frame, (tuple, BaseException)) else _text(frame))

    def recv_data(self):
        item = self.incoming.get(timeout=5)
        if isinstance(item, BaseException):
            raise item
        return item

    def send(self, payload, opcode=None):
        self.sent.append(payload)
        if self.on_send is not None:
            self.on_send(self, json.loads(payload))

    def abort(self):
        self.aborted.set()
        self.incoming.put(ConnectionError("socket aborted"))

    def close(self):
        self.closed.set()

    def frames_sent(self):
        return [json.loads(payload) for payload in self.sent]


class FakeModule:
    def __init__(self, ws=None, error=None):
        self.ws = ws
        self.error = error
        self.calls = []

    def create_connection(self, url, header, enable_multithread, **kwargs):
        self.calls.append((url, header))
        if self.error is not None:
            raise self.error
        return self.ws


class FakeBadStatus(Exception):
    def __init__(self, status_code, body):
        super().__init__(f"Handshake status {status_code}")
        self.status_code = status_code
        self.resp_body = body.encode()


def _answer_interrupt(ws, frame):
    """A server that stops the run when asked."""
    if frame.get("type") == "interrupt":
        ws.push({"type": "control", "text": "interrupted", "name": "", "value": "", "traceback": ""})
        ws.push(_close(1000))


def _happy_frames():
    return [
        {"type": "execution_count", "count": 3, "text": "", "name": "", "value": "", "traceback": ""},
        {"type": "stdout", "text": "hello\n", "name": "", "value": "", "traceback": ""},
        {"type": "stderr", "text": "warn\n", "name": "", "value": "", "traceback": ""},
        {"type": "result", "text": "", "png": "iVBORw0K", "is_main_result": False, "name": "", "value": "", "traceback": ""},
        {
            "type": "result",
            "text": "42",
            "html": "<b>42</b>",
            "json": {"answer": 42},
            "data": {"a": [1, 2]},
            "extra": {"application/x-custom": "z"},
            "is_main_result": True,
            "name": "",
            "value": "",
            "traceback": "",
        },
        {"type": "telemetry", "text": "ignored"},
        "not json",
        (0x2, b"\x01binary is ignored"),
        {"type": "control", "text": "completed", "name": "", "value": "", "traceback": ""},
        _close(1000),
    ]


class InterpreterMicroVM(MicroVM):
    """A MicroVM whose HTTP answers come from a table. ``features`` is what
    the agent lists on /version; None plays an agent too old to list any."""

    def __init__(self, features=(_FEATURE,), answers=None):
        super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")
        self.features = features
        self.answers = answers or {}
        self.calls = []
        self.non_idempotent = []

    def _do_json(self, method, path, payload, *, idempotent=True, headers=None):  # type: ignore[override]
        self.calls.append((method, path, payload))
        if not idempotent:
            self.non_idempotent.append((method, path))
        if path.endswith("/toolbox/version"):
            return {"version": "0.7.6"} if self.features is None else {"version": "0.7.6", "features": list(self.features)}
        return self.answers[(method, path)]


def _patched(module):
    return unittest.mock.patch.object(client_module, "_load_websocket_module", lambda: module)


class CodeRunTests(unittest.TestCase):
    def run_code(self, frames, client=None, **kwargs):
        ws = FakeCodeSocket(frames)
        module = FakeModule(ws)
        client = client or InterpreterMicroVM()
        with _patched(module):
            execution = client.run_code("sb-1", "print('hello')", **kwargs)
        return execution, ws, module

    def test_a_run_streams_output_and_returns_the_execution(self):
        seen = []
        execution, ws, module = self.run_code(
            _happy_frames(),
            context=CodeContext(id="ctx-1"),
            envs={"A": "1"},
            timeout_seconds=30,
            on_stdout=lambda text: seen.append(("stdout", text)),
            on_stderr=lambda text: seen.append(("stderr", text)),
            on_result=lambda result: seen.append(("result", result.formats())),
        )
        url, header = module.calls[0]
        self.assertEqual(url, "wss://sandbox.example.com/v1/sandboxes/sb-1/toolbox/process/interpreter/execute")
        self.assertIn("Authorization: Bearer pat-token", header)
        self.assertEqual(
            ws.frames_sent(),
            [{"code": "print('hello')", "contextId": "ctx-1", "envs": {"A": "1"}, "timeout": 30, "richOutput": True}],
        )
        self.assertEqual(
            seen,
            [
                ("stdout", "hello\n"),
                ("stderr", "warn\n"),
                ("result", ["png"]),
                ("result", ["text", "html", "json", "data", "application/x-custom"]),
            ],
        )
        self.assertEqual(execution.logs.stdout, ["hello\n"])
        self.assertEqual(execution.logs.stderr, ["warn\n"])
        self.assertEqual(execution.execution_count, 3)
        self.assertEqual(execution.text, "42")
        self.assertIsNone(execution.results[0].text, "an empty text is no text")
        self.assertEqual(execution.results[1].json, {"answer": 42})
        self.assertEqual(execution.results[1].data, {"a": [1, 2]})
        self.assertIsNone(execution.error)
        self.assertFalse(execution.interrupted)
        self.assertTrue(ws.closed.is_set())

    def test_the_start_message_carries_only_what_was_set(self):
        cases = [
            ({}, {"code": "print('hello')", "richOutput": True}),
            ({"language": "javascript", "timeout_seconds": 0}, {"code": "print('hello')", "language": "javascript", "timeout": 0, "richOutput": True}),
            ({"context": "ctx-9", "envs": {}}, {"code": "print('hello')", "contextId": "ctx-9", "richOutput": True}),
        ]
        for kwargs, want in cases:
            with self.subTest(kwargs=kwargs):
                _, ws, _ = self.run_code([_close(1000)], **kwargs)
                self.assertEqual(ws.frames_sent(), [want])

    def test_context_and_language_together_are_refused_before_anything_is_sent(self):
        client = InterpreterMicroVM()
        module = FakeModule(FakeCodeSocket())
        with _patched(module), self.assertRaisesRegex(MicroVMError, "set context or language, not both"):
            client.run_code("sb-1", "1", context="ctx-1", language="python")
        self.assertEqual((client.calls, module.calls), ([], []))

    def test_an_exception_in_the_code_is_data_not_an_sdk_error(self):
        errors = []
        frames = [
            {"type": "stdout", "text": "before\n", "name": "", "value": "", "traceback": ""},
            {"type": "error", "text": "", "name": "ZeroDivisionError", "value": "division by zero", "traceback": "Traceback ...\nZeroDivisionError"},
            {"type": "control", "text": "completed", "name": "", "value": "", "traceback": ""},
            _close(1000),
        ]
        execution, _, _ = self.run_code(frames, on_error=errors.append)
        want = ExecutionError(name="ZeroDivisionError", value="division by zero", traceback="Traceback ...\nZeroDivisionError")
        self.assertEqual(execution.error, want)
        self.assertEqual(errors, [want])
        self.assertEqual(execution.logs.stdout, ["before\n"])
        self.assertIsNone(execution.text)

    def test_an_interrupted_run_returns_normally(self):
        frames = [{"type": "control", "text": "interrupted", "name": "", "value": "", "traceback": ""}, _close(1000)]
        execution, _, _ = self.run_code(frames)
        self.assertTrue(execution.interrupted)

    def test_a_close_frame_with_no_code_is_a_finished_run(self):
        execution, _, _ = self.run_code([{"type": "stdout", "text": "x", "name": "", "value": "", "traceback": ""}, _close()])
        self.assertEqual(execution.logs.stdout, ["x"])

    def test_the_server_timeout_raises_with_the_partial_execution(self):
        frames = [{"type": "stdout", "text": "working\n", "name": "", "value": "", "traceback": ""}, _close(4008, "timeout after 1s")]
        with self.assertRaises(MicroVMCodeTimeoutError) as ctx:
            self.run_code(frames, timeout_seconds=1)
        err = ctx.exception
        self.assertIsInstance(err, MicroVMCodeRunError)
        self.assertIsInstance(err, TimeoutError)
        self.assertEqual((err.close_code, err.reason), (4008, "timeout after 1s"))
        self.assertEqual(str(err), "code run timed out: timeout after 1s")
        self.assertEqual(err.execution.logs.stdout, ["working\n"])

    def test_other_close_codes_raise_with_the_code_and_reason(self):
        cases = [
            (_close(1008, "context not found: abc"), 1008, "code run failed (close 1008): context not found: abc"),
            (_close(1011, "worker process ended"), 1011, "code run failed (close 1011): worker process ended"),
            (_close(1001), 1001, "code run failed (close 1001)"),
            (ConnectionResetError("reset by peer"), 1006, "code run failed (close 1006): connection lost: reset by peer"),
        ]
        for last, code, message in cases:
            with self.subTest(code=code):
                with self.assertRaises(MicroVMCodeRunError) as ctx:
                    self.run_code([{"type": "stdout", "text": "partial", "name": "", "value": "", "traceback": ""}, last])
                self.assertNotIsInstance(ctx.exception, MicroVMCodeTimeoutError)
                self.assertEqual(ctx.exception.close_code, code)
                self.assertEqual(str(ctx.exception), message)
                self.assertEqual(ctx.exception.execution.logs.stdout, ["partial"])

    def test_a_refused_handshake_is_reported_like_the_exec_stream(self):
        client = InterpreterMicroVM()
        with _patched(FakeModule(error=FakeBadStatus(404, '{"error":"sandbox not found"}'))):
            with self.assertRaises(MicroVMError) as ctx:
                client.run_code("sb-1", "1")
        self.assertIn("code run websocket connect", str(ctx.exception))
        self.assertIn("status=404", str(ctx.exception))

    def test_interrupt_sends_the_interrupt_frame_and_the_run_ends_interrupted(self):
        ws = FakeCodeSocket(on_send=_answer_interrupt)
        client = InterpreterMicroVM()
        with _patched(FakeModule(ws)):
            handle = client.start_code("sb-1", "while True: pass")
        self.assertIsInstance(handle, CodeRunHandle)
        handle.interrupt()
        execution = handle.wait(5)
        self.assertTrue(execution.interrupted)
        self.assertEqual(ws.frames_sent()[1:], [{"type": "interrupt"}])
        self.assertIs(handle.done.result(), execution)

    def test_wait_with_a_timeout_and_close(self):
        ws = FakeCodeSocket()
        with _patched(FakeModule(ws)):
            handle = InterpreterMicroVM().start_code("sb-1", "import time; time.sleep(60)")
        with self.assertRaisesRegex(TimeoutError, "timed out waiting for the code run to end"):
            handle.wait(0.05)
        handle.close()
        self.assertTrue(ws.aborted.is_set())
        with self.assertRaises(MicroVMCodeRunError) as ctx:
            handle.wait(5)
        self.assertEqual(ctx.exception.close_code, 1006)
        self.assertIn("the client closed the connection", ctx.exception.reason)

    def test_a_server_timeout_is_not_read_as_the_wait_timing_out(self):
        ws = FakeCodeSocket([_close(4008)])
        with _patched(FakeModule(ws)):
            handle = InterpreterMicroVM().start_code("sb-1", "1")
        with self.assertRaises(MicroVMCodeTimeoutError):
            handle.wait(5)

    def test_ctrl_c_interrupts_the_run_in_the_sandbox(self):
        for answers, want_aborted in ((True, False), (False, True)):
            with self.subTest(server_answers=answers):
                ws = FakeCodeSocket(on_send=_answer_interrupt if answers else None)
                pressed = []

                def wait(handle, timeout=None, _real=CodeRunHandle.wait):
                    if not pressed:
                        pressed.append(True)
                        raise KeyboardInterrupt
                    return _real(handle, timeout)

                with _patched(FakeModule(ws)), unittest.mock.patch.object(CodeRunHandle, "wait", wait), unittest.mock.patch.object(
                    client_module, "_INTERRUPT_GRACE_SECONDS", 0.2
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        InterpreterMicroVM().run_code("sb-1", "while True: pass")
                self.assertEqual(ws.frames_sent()[1:], [{"type": "interrupt"}])
                self.assertEqual(ws.aborted.is_set(), want_aborted)

    def test_a_callback_that_raises_ends_the_wait_with_its_error(self):
        def boom(text):
            raise ValueError("callback failed")

        with self.assertRaisesRegex(ValueError, "callback failed"):
            self.run_code([{"type": "stdout", "text": "x", "name": "", "value": "", "traceback": ""}, _close(1000)], on_stdout=boom)

    def test_a_failed_start_message_closes_the_socket(self):
        class BrokenSend(FakeCodeSocket):
            def send(self, payload, opcode=None):
                raise ConnectionError("broken pipe")

        ws = BrokenSend()
        with _patched(FakeModule(ws)), self.assertRaisesRegex(MicroVMError, "sending the code failed"):
            InterpreterMicroVM().run_code("sb-1", "1")
        self.assertTrue(ws.closed.is_set())

    def test_the_sandbox_runs_code_too(self):
        client = InterpreterMicroVM()
        sandbox = client_module.Sandbox(client, {"id": "sb-1"})
        ws = FakeCodeSocket(_happy_frames())
        with _patched(FakeModule(ws)):
            execution = sandbox.run_code("x", language="python", timeout=5)
            handle = sandbox.start_code("y", context="ctx-2")
        self.assertEqual(execution.text, "42")
        ws.push(_close(1000))
        handle.wait(5)
        self.assertEqual([frame.get("contextId") for frame in ws.frames_sent()], [None, "ctx-2"])


class CodeResultTests(unittest.TestCase):
    def test_formats_and_the_main_text(self):
        self.assertEqual(CodeResult().formats(), [])
        result = CodeResult(text="t", svg="<svg/>", latex="x^2", javascript="1", markdown="**m**", jpeg="j", pdf="p", extra={"b": 1, "a": 2})
        self.assertEqual(result.formats(), ["text", "markdown", "svg", "jpeg", "pdf", "latex", "javascript", "a", "b"])
        execution = Execution(results=[CodeResult(text="side"), CodeResult(text="main", is_main_result=True)])
        self.assertEqual(execution.text, "main")
        self.assertIsNone(Execution().text)
        self.assertEqual((Execution().logs.stdout, Execution().execution_count), ([], None))


class CodeContextTests(unittest.TestCase):
    def test_context_calls_send_the_right_requests(self):
        answers = {
            ("POST", f"{_BASE}/process/interpreter/context"): _CONTEXT,
            ("GET", f"{_BASE}/process/interpreter/context"): {"contexts": [_CONTEXT, {"id": "ctx-2", "language": "r"}]},
            ("GET", f"{_BASE}/process/interpreter/context/ctx%2F1"): _CONTEXT,
            ("DELETE", f"{_BASE}/process/interpreter/context/ctx-1"): {"message": "Context deleted successfully"},
            ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart"): dict(_CONTEXT, active=True),
        }
        client = InterpreterMicroVM(answers=answers)
        created = client.create_code_context("sb-1", language="python", cwd="/work")
        self.assertEqual(created, CodeContext(id="ctx-1", language="python", cwd="/work", created_at="2026-11-15T10:00:00Z", active=True))
        bare = client.create_code_context("sb-1")
        listed = client.list_code_contexts("sb-1")
        got = client.get_code_context("sb-1", "ctx/1")
        client.delete_code_context("sb-1", created)
        restarted = client.restart_code_context("sb-1", "ctx-1")

        self.assertEqual(bare.id, "ctx-1")
        self.assertEqual([c.id for c in listed], ["ctx-1", "ctx-2"])
        self.assertEqual((listed[1].language, listed[1].active, listed[1].cwd), ("r", False, ""))
        self.assertEqual(got.id, "ctx-1")
        self.assertEqual(restarted.id, "ctx-1")
        self.assertEqual(
            client.calls,
            [
                ("GET", f"{_BASE}/version", None),
                ("POST", f"{_BASE}/process/interpreter/context", {"language": "python", "cwd": "/work"}),
                ("POST", f"{_BASE}/process/interpreter/context", {}),
                ("GET", f"{_BASE}/process/interpreter/context", None),
                ("GET", f"{_BASE}/process/interpreter/context/ctx%2F1", None),
                ("DELETE", f"{_BASE}/process/interpreter/context/ctx-1", None),
                ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart", None),
            ],
            "the /version check runs once per sandbox",
        )
        self.assertEqual(
            client.non_idempotent,
            [
                ("POST", f"{_BASE}/process/interpreter/context"),
                ("POST", f"{_BASE}/process/interpreter/context"),
                ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart"),
            ],
        )

    def test_a_missing_list_is_empty_and_an_empty_id_is_refused(self):
        client = InterpreterMicroVM(answers={("GET", f"{_BASE}/process/interpreter/context"): {"contexts": None}})
        self.assertEqual(client.list_code_contexts("sb-1"), [])
        with self.assertRaisesRegex(MicroVMError, "code context"):
            client.delete_code_context("sb-1", "")

    def test_the_sandbox_has_the_context_calls(self):
        answers = {
            ("POST", f"{_BASE}/process/interpreter/context"): _CONTEXT,
            ("GET", f"{_BASE}/process/interpreter/context"): {"contexts": []},
            ("GET", f"{_BASE}/process/interpreter/context/ctx-1"): _CONTEXT,
            ("DELETE", f"{_BASE}/process/interpreter/context/ctx-1"): {},
            ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart"): _CONTEXT,
        }
        client = InterpreterMicroVM(answers=answers)
        sandbox = client_module.Sandbox(client, {"id": "sb-1"})
        context = sandbox.create_code_context(cwd="/work", timeout=5)
        self.assertEqual(sandbox.list_code_contexts(), [])
        self.assertEqual(sandbox.get_code_context("ctx-1"), context)
        sandbox.delete_code_context(context)
        self.assertEqual(sandbox.restart_code_context(context).id, "ctx-1")
        self.assertEqual(client.calls[1][2], {"cwd": "/work"})

    def test_an_older_agent_fails_closed_and_nothing_is_sent(self):
        for features in ([], None, ["exec.argv"]):
            client = InterpreterMicroVM(features=features)
            module = FakeModule(FakeCodeSocket())
            calls = [
                lambda: client.create_code_context("sb-1"),
                lambda: client.list_code_contexts("sb-1"),
                lambda: client.get_code_context("sb-1", "ctx-1"),
                lambda: client.delete_code_context("sb-1", "ctx-1"),
                lambda: client.restart_code_context("sb-1", "ctx-1"),
                lambda: client.run_code("sb-1", "1"),
                lambda: client.start_code("sb-1", "1"),
            ]
            for call in calls:
                with self.subTest(features=features), _patched(module):
                    with self.assertRaises(MicroVMUnsupportedFeatureError) as ctx:
                        call()
                    self.assertEqual(ctx.exception.features, [_FEATURE])
            self.assertEqual({path for _, path, _ in client.calls}, {f"{_BASE}/version"})
            self.assertEqual(module.calls, [])

    def test_a_wasm_sandbox_is_named_in_the_error(self):
        class Wasm(InterpreterMicroVM):
            def _do_json(self, method, path, payload, *, idempotent=True, headers=None):  # type: ignore[override]
                return {"version": "0.7.6", "features": [], "runtime": "wasm"}

        with self.assertRaisesRegex(MicroVMUnsupportedFeatureError, "WebAssembly"):
            Wasm().list_code_contexts("sb-1")


class CodeContextRetryTests(unittest.TestCase):
    """Create and restart are sent once: a 502 may mean the server did the
    work, and a second create would leave two interpreters running."""

    VERSION = (200, {"version": "0.7.6", "features": [_FEATURE]}, None)

    def test_create_and_restart_are_not_retried_but_get_is(self):
        fast = {"retry": {"maxRetries": 3, "baseDelayMs": 1, "maxDelayMs": 1}}
        cases = [
            ("create", lambda c: c.create_code_context("sb-1"), [self.VERSION, (502, b"<html>bad</html>", None)], 2),
            ("restart", lambda c: c.restart_code_context("sb-1", "ctx-1"), [self.VERSION, (502, b"<html>bad</html>", None)], 2),
            ("get", lambda c: c.get_code_context("sb-1", "ctx-1"), [self.VERSION, (502, b"<html>bad</html>", None), (200, _CONTEXT, None)], 3),
        ]
        for name, call, script, want_hits in cases:
            with self.subTest(name):
                url, hits = _scripted_server(self, script)
                client = MicroVM(url, "pat", config=fast)
                if want_hits == 2:
                    with self.assertRaises(MicroVMHTTPError) as ctx:
                        call(client)
                    self.assertEqual(ctx.exception.status_code, 502)
                else:
                    self.assertEqual(call(client).id, "ctx-1")
                self.assertEqual(len(hits), want_hits)

    def test_the_context_limit_is_an_http_429(self):
        url, _ = _scripted_server(self, [self.VERSION, (429, {"error": "too many contexts", "message": "limit 32"}, {"Retry-After": "0"})])
        client = MicroVM(url, "pat", config={"retry": {"maxRetries": 0}})
        with self.assertRaises(MicroVMHTTPError) as ctx:
            client.create_code_context("sb-1")
        self.assertEqual(ctx.exception.status_code, 429)


@needs_httpx
class AsyncCodeInterpreterTests(unittest.TestCase):
    def client_class(self, features=(_FEATURE,), answers=None):
        from microvm import AsyncMicroVM

        test = self

        class Fake(AsyncMicroVM):
            def __init__(self):
                super().__init__("http://127.0.0.1:9", "pat")
                self.calls = []
                self.non_idempotent = []

            async def _do_json(self, method, path, payload, *, idempotent=True, headers=None):  # type: ignore[override]
                self.calls.append((method, path, payload))
                if not idempotent:
                    self.non_idempotent.append((method, path))
                if path.endswith("/toolbox/version"):
                    return {"version": "0.7.6", "features": list(features)}
                test.assertIn((method, path), answers or {})
                return answers[(method, path)]

        return Fake

    def test_run_code_runs_callbacks_on_the_loop(self):
        from microvm import AsyncCodeRunHandle, AsyncSandbox

        ws = FakeCodeSocket(_happy_frames())
        seen = []

        async def go():
            loop_thread = threading.get_ident()
            async with self.client_class()() as client:
                sandbox = AsyncSandbox(client, {"id": "sb-1"})
                execution = await sandbox.run_code(
                    "x", on_stdout=lambda text: seen.append((text, threading.get_ident() == loop_thread)), timeout_seconds=5
                )
                ws.push(_close(1000))
                handle = await sandbox.start_code("y", context="ctx-1")
                self.assertIsInstance(handle, AsyncCodeRunHandle)
                second = await handle.wait(5)
                return execution, second

        with _patched(FakeModule(ws)):
            execution, second = asyncio.run(go())
        self.assertEqual(execution.text, "42")
        self.assertEqual(seen, [("hello\n", True)])
        self.assertEqual(second.results, [])
        self.assertEqual(ws.frames_sent()[0], {"code": "x", "timeout": 5, "richOutput": True})
        self.assertEqual(ws.frames_sent()[1], {"code": "y", "contextId": "ctx-1", "richOutput": True})

    def test_cancelling_run_code_interrupts_the_run(self):
        for answers, want_aborted in ((True, False), (False, True)):
            with self.subTest(server_answers=answers):
                ws = FakeCodeSocket(on_send=_answer_interrupt if answers else None)

                async def go():
                    async with self.client_class()() as client:
                        task = asyncio.ensure_future(client.run_code("sb-1", "while True: pass"))
                        while not ws.sent:
                            await asyncio.sleep(0.01)
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task

                with _patched(FakeModule(ws)), unittest.mock.patch.object(
                    __import__("microvm.aio", fromlist=["_INTERRUPT_GRACE_SECONDS"]), "_INTERRUPT_GRACE_SECONDS", 0.2
                ):
                    asyncio.run(go())
                self.assertEqual(ws.frames_sent()[1:], [{"type": "interrupt"}])
                self.assertEqual(ws.aborted.is_set(), want_aborted)

    def test_the_handle_interrupts_and_errors_carry_through(self):
        ws = FakeCodeSocket(on_send=_answer_interrupt)
        timed_out = FakeCodeSocket([{"type": "stdout", "text": "a", "name": "", "value": "", "traceback": ""}, _close(4008)])
        sockets = [ws, timed_out]

        class Module(FakeModule):
            def create_connection(self, url, header, enable_multithread, **kwargs):
                return sockets.pop(0)

        async def go():
            async with self.client_class()() as client:
                handle = await client.start_code("sb-1", "while True: pass")
                await handle.interrupt()
                execution = await handle.wait(5)
                with self.assertRaises(MicroVMCodeTimeoutError) as ctx:
                    await client.run_code("sb-1", "slow()", timeout_seconds=1)
                return execution, ctx.exception

        with _patched(Module()):
            execution, err = asyncio.run(go())
        self.assertTrue(execution.interrupted)
        self.assertEqual(err.execution.logs.stdout, ["a"])

    def test_wait_timeout_and_close(self):
        ws = FakeCodeSocket()

        async def go():
            async with self.client_class()() as client:
                handle = await client.start_code("sb-1", "sleep()")
                with self.assertRaisesRegex(TimeoutError, "timed out waiting for the code run to end"):
                    await handle.wait(0.05)
                await handle.close()
                with self.assertRaises(MicroVMCodeRunError):
                    await handle.wait(5)

        with _patched(FakeModule(ws)):
            asyncio.run(go())
        self.assertTrue(ws.aborted.is_set())

    def test_context_calls_and_the_feature_gate(self):
        from microvm import AsyncSandbox

        answers = {
            ("POST", f"{_BASE}/process/interpreter/context"): _CONTEXT,
            ("GET", f"{_BASE}/process/interpreter/context"): {"contexts": [_CONTEXT]},
            ("GET", f"{_BASE}/process/interpreter/context/ctx-1"): _CONTEXT,
            ("DELETE", f"{_BASE}/process/interpreter/context/ctx-1"): {},
            ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart"): _CONTEXT,
        }

        async def go():
            async with self.client_class(answers=answers)() as client:
                sandbox = AsyncSandbox(client, {"id": "sb-1"})
                created = await sandbox.create_code_context(language="python")
                listed = await sandbox.list_code_contexts()
                got = await client.get_code_context("sb-1", "ctx-1")
                await sandbox.delete_code_context(created)
                restarted = await sandbox.restart_code_context("ctx-1")
                await sandbox.get_code_context("ctx-1")
                await client.delete_code_context("sb-1", "ctx-1")
                await client.restart_code_context("sb-1", created)
                await client.list_code_contexts("sb-1")
                await client.create_code_context("sb-1", cwd="/w")
                return client, created, listed, got, restarted

        async def both():
            result = await go()
            await old_agent()
            return result

        async def old_agent():
            module = FakeModule(FakeCodeSocket())
            with _patched(module):
                async with self.client_class(features=())() as old:
                    for make in (lambda: old.create_code_context("sb-1"), lambda: old.run_code("sb-1", "1"), lambda: old.start_code("sb-1", "1")):
                        with self.assertRaises(MicroVMUnsupportedFeatureError):
                            await make()
            self.assertEqual(module.calls, [])

        client, created, listed, got, restarted = asyncio.run(both())
        self.assertEqual(created, got)
        self.assertEqual(listed, [created])
        self.assertEqual(restarted.id, "ctx-1")
        self.assertEqual(client.calls[1], ("POST", f"{_BASE}/process/interpreter/context", {"language": "python"}))
        self.assertEqual(client.calls[-1], ("POST", f"{_BASE}/process/interpreter/context", {"cwd": "/w"}))
        self.assertEqual(
            client.non_idempotent,
            [
                ("POST", f"{_BASE}/process/interpreter/context"),
                ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart"),
                ("POST", f"{_BASE}/process/interpreter/context/ctx-1/restart"),
                ("POST", f"{_BASE}/process/interpreter/context"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
