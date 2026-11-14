"""The asyncio client: AsyncMicroVM (plan section 5.3, S1).

It has the same calls as :class:`~microvm.MicroVM`, as coroutines, and runs
the very same request code: every call is an ``_op_*`` generator on the
shared ``_MicroVMCore``, and only the transport differs. MicroVM moves bytes
with urllib; AsyncMicroVM with httpx, an optional dependency::

    pip install "aerolvm-sdk[async]"

Streams (exec_stream, attach_session, watch_files) use the same
websocket-client connections as the sync client, opened on a worker thread
so the event loop never blocks; their callbacks run on the event loop.
"""

from __future__ import annotations

import asyncio
import inspect
import random
import threading
import time
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Tuple, Union

from .client import (
    _MAX_LIST_PAGES,
    _NOT_STARTED_STATUSES,
    _REPLY_LOST_STATUSES,
    _RETRY_STATUSES,
    DEFAULT_LIST_LIMIT,
    ExecStreamHandle,
    FileWatchHandle,
    MicroVM,
    MicroVMError,
    MicroVMNotFoundError,
    MicroVMTimeoutError,
    SessionAttachHandle,
    Tokens,
    _call_deadline,
    _cell_header,
    _deadline_error,
    _error_code,
    _error_from_answer,
    _json_answer,
    _json_body,
    _MicroVMCore,
    _multipart_body,
    _SandboxBase,
    _time_left,
    _build_sandbox_query,
    _DEFAULT_API_VERSION,
)
from .image import Image
from .types import (
    APITokenList,
    AuditOptions,
    AuditPage,
    BuildImagePushOptions,
    BuildImageResult,
    CloneGeneration,
    CreateAPITokenOptions,
    CreateOptions,
    CreateSessionOptions,
    CreateTemplateOptions,
    CreateWasmModuleOptions,
    CreatedAPIToken,
    CustomDomain,
    CustomDomainDNSRecords,
    EgressProfile,
    EgressProfileList,
    EgressProfileOptions,
    ExecExitInfo,
    ExecRequest,
    ExecResult,
    ExecStreamOptions,
    ExposeProtocol,
    ExposeResult,
    ExposeVisibility,
    FileEventCallback,
    FileInfo,
    FileList,
    FileMatch,
    HealthStatus,
    IdentityRole,
    IdentityRoleList,
    IdentityRoleOptions,
    IngressTarget,
    Lifecycle,
    ListEgressProfilesOptions,
    ListIdentityRolesOptions,
    MicroVMConfig,
    MountSpecRedacted,
    NetworkLearned,
    NetworkPolicy,
    NetworkPolicyCheckOptions,
    NetworkPolicyCheckResult,
    NetworkPolicyOptions,
    NetworkUsage,
    PushWasmModuleOptions,
    PushWasmModuleResult,
    RegisterSnapshotOptions,
    ResizeOptions,
    RevokeSandboxTokensResult,
    SandboxSnapshot,
    SandboxToken,
    Session,
    SessionAttachOptions,
    SetNetworkLimitsOptions,
    SnapshotList,
    TeamQuota,
    TeamQuotaOptions,
    Template,
    WarmPool,
    WarmPoolOptions,
    WasmModule,
    WhoAmI,
)

try:  # the optional [async] extra; the sync client never needs it
    import httpx
except ImportError:  # pragma: no cover - exercised only without the extra
    httpx = None  # type: ignore[assignment]

_INSTALL_HINT = 'AsyncMicroVM needs httpx: pip install "aerolvm-sdk[async]"'


def _transport_timeout(exc: BaseException) -> MicroVMTimeoutError:
    """An httpx timeout from the client's own limit (a caller's http_client
    keeps httpx's 5 s default) as the SDK's timeout error. httpx's timeouts
    are not TimeoutError, so without this `except TimeoutError` and
    `except MicroVMTimeoutError` missed them; the sync client's socket
    timeouts are TimeoutError already."""
    return MicroVMTimeoutError(0, f"the request timed out ({type(exc).__name__}: {exc})")


def _on_loop(loop: asyncio.AbstractEventLoop, callback: Any) -> Any:
    """Wraps a stream callback so it runs on the event loop instead of the
    stream's reader thread. A coroutine function's result is scheduled as a
    task. Order is kept: call_soon_threadsafe runs callbacks first in, first
    out."""
    if callback is None:
        return None

    def run(arg: Any) -> None:
        result = callback(arg)
        if inspect.isawaitable(result):
            asyncio.ensure_future(result)

    def from_thread(arg: Any) -> None:
        loop.call_soon_threadsafe(run, arg)

    return from_thread


def _loop_options(options: Optional[Dict[str, Any]], keys: Tuple[str, ...]) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    wrapped = dict(options or {})
    for key in keys:
        if wrapped.get(key) is not None:
            wrapped[key] = _on_loop(loop, wrapped[key])
    return wrapped


async def _wait(future: "asyncio.Future[Any]", timeout: Optional[float], what: str) -> Any:
    try:
        return await asyncio.wait_for(asyncio.shield(future), timeout)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(f"timed out waiting for {what}") from exc


class AsyncExecStreamHandle:
    """A running exec stream (:meth:`AsyncMicroVM.exec_stream`). The
    ``onStdout``, ``onStderr`` and ``onError`` callbacks run on the event
    loop; a coroutine function is run as a task."""

    def __init__(self, inner: ExecStreamHandle) -> None:
        self._inner = inner
        self._done = asyncio.wrap_future(inner.done)

    @property
    def done(self) -> "asyncio.Future[ExecExitInfo]":
        return self._done

    async def write(self, data: Union[bytes, str]) -> None:
        await asyncio.to_thread(self._inner.write, data)

    async def resize(self, cols: int, rows: int) -> None:
        await asyncio.to_thread(self._inner.resize, cols, rows)

    async def signal(self, name: str) -> None:
        await asyncio.to_thread(self._inner.signal, name)

    async def close(self) -> None:
        await asyncio.to_thread(self._inner.close)

    async def wait(self, timeout: Optional[float] = None) -> ExecExitInfo:
        return await _wait(self._done, timeout, "stream completion")


class AsyncSessionAttachHandle:
    """An attached session (:meth:`AsyncMicroVM.attach_session`). Callbacks
    run on the event loop, as for :class:`AsyncExecStreamHandle`."""

    def __init__(self, inner: SessionAttachHandle) -> None:
        self._inner = inner
        self._done = asyncio.wrap_future(inner.done)

    @property
    def done(self) -> "asyncio.Future[ExecExitInfo]":
        return self._done

    async def write(self, data: Union[bytes, str]) -> None:
        await asyncio.to_thread(self._inner.write, data)

    async def resize(self, cols: int, rows: int) -> None:
        await asyncio.to_thread(self._inner.resize, cols, rows)

    async def signal(self, name: str) -> None:
        await asyncio.to_thread(self._inner.signal, name)

    async def close(self) -> None:
        await asyncio.to_thread(self._inner.close)

    async def wait(self, timeout: Optional[float] = None) -> ExecExitInfo:
        return await _wait(self._done, timeout, "session completion")


class AsyncFileWatchHandle:
    """A running file watch (:meth:`AsyncMicroVM.watch_files`). Events reach
    the callback on the event loop, in order; ``wait()`` raises
    :class:`MicroVMError` when the watch ends any way but ``stop()``."""

    def __init__(self, inner: FileWatchHandle) -> None:
        self._inner = inner
        self._done = asyncio.wrap_future(inner.done)

    @property
    def done(self) -> "asyncio.Future[None]":
        return self._done

    async def stop(self) -> None:
        await asyncio.to_thread(self._inner.stop)

    async def wait(self, timeout: Optional[float] = None) -> None:
        await _wait(self._done, timeout, "the file watch to end")


class _Handoff:
    """A worker thread's result, handed to the task awaiting it under a lock.

    Cancelling the task does not stop its thread. A stream the thread opens
    then (an exec stream whose command already started) would be dropped
    with the result, open, with nothing left to close it. Exactly one side
    closes such a result: the thread, when it finishes after the task stopped
    waiting, or the task, when the thread had already handed it over.
    """

    def __init__(self, fn: Any, args: Tuple[Any, ...]) -> None:
        self._fn = fn
        self._args = args
        self._lock = threading.Lock()
        self._abandoned = False
        self._handed: List[Any] = []

    def run(self) -> Any:
        result = self._fn(*self._args)
        with self._lock:
            orphan = self._abandoned
            if not orphan:
                self._handed.append(result)
        if orphan:
            _close_quietly(result)
        return result

    def abandon(self) -> None:
        with self._lock:
            self._abandoned = True
            handed, self._handed = self._handed, []
        for result in handed:
            # A websocket close waits for the server's reply; not on the loop.
            threading.Thread(target=_close_quietly, args=(result,), daemon=True).start()


def _close_quietly(result: Any) -> None:
    close = getattr(result, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:
        pass


class _SyncBody:
    """A blocking ``read(n)`` over an httpx response streamed on the event
    loop, for the download reader the sync client also uses: the reader runs
    on a worker thread and pulls each chunk from the loop."""

    def __init__(self, loop: asyncio.AbstractEventLoop, response: Any) -> None:
        self._loop = loop
        self._chunks = response.aiter_bytes()
        self._buffer = b""
        self._ended = False

    async def _next(self) -> bytes:
        try:
            return await self._chunks.__anext__()
        except StopAsyncIteration:
            return b""

    def read(self, size: int) -> bytes:
        while len(self._buffer) < size and not self._ended:
            chunk = asyncio.run_coroutine_threadsafe(self._next(), self._loop).result()
            if chunk == b"":
                self._ended = True
            self._buffer += chunk
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data


async def _async_body(body: Iterator[bytes]) -> AsyncIterator[bytes]:
    """A streamed upload body (a generator reading a local file) read on a
    worker thread, chunk by chunk, so the loop never waits on the disk."""
    done = object()
    while True:
        chunk = await asyncio.to_thread(next, body, done)
        if chunk is done:
            return
        yield chunk


def _never_sent(exc: BaseException) -> bool:
    """httpx's form of the sync client's _request_never_sent: the connection
    was refused or never opened, or no connection was free, so the server
    cannot have the request."""
    return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout))


class AsyncTokens:
    """Scoped API tokens, reached as ``client.tokens``; see :class:`Tokens`."""

    def __init__(self, client: "AsyncMicroVM") -> None:
        self._client = client

    async def create(self, options: Optional[CreateAPITokenOptions] = None, *, timeout: Optional[float] = None, **fields: Any) -> CreatedAPIToken:
        with _call_deadline(timeout):
            return await self._client._run(self._client._op_create_api_token(options, **fields))

    async def list(self, *, timeout: Optional[float] = None) -> APITokenList:
        with _call_deadline(timeout):
            return await self._client._run(self._client._op_list_api_tokens())

    async def revoke(self, token_id: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client._run(self._client._op_revoke_api_token(token_id))


class AsyncSandbox(_SandboxBase):
    """A sandbox, as returned by :class:`AsyncMicroVM`. Its calls are those
    of :class:`~microvm.Sandbox`, as coroutines.

    It works with ``async with``: leaving the block deletes the sandbox only
    when ``destroy_on_exit`` is True, as for Sandbox.
    """

    async def __aenter__(self) -> "AsyncSandbox":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc is None:
            await self.close()
            return
        # As Sandbox.__exit__: the block's own error wins; a failed delete
        # is added to it as a note.
        try:
            await self.close()
        except Exception as err:
            if hasattr(exc, "add_note"):
                exc.add_note(f"destroying sandbox {self.id} on exit also failed: {err}")

    async def close(self, *, timeout: Optional[float] = None) -> None:
        if not self.destroy_on_exit or self._closed:
            return
        try:
            await self._client.destroy(self.id, timeout=timeout)
        except MicroVMNotFoundError:
            pass
        self._closed = True

    async def refresh(self, *, timeout: Optional[float] = None) -> "AsyncSandbox":
        updated = await self._client.get(self.id, timeout=timeout)
        self._data = updated.to_dict()
        return self

    async def exec(self, request: Union[str, ExecRequest], *, timeout: Optional[float] = None) -> ExecResult:
        if isinstance(request, str):
            return await self.exec_command(request, timeout=timeout)
        return await self._client.exec(self.id, request, timeout=timeout)

    async def start(self, *, timeout: Optional[float] = None) -> "AsyncSandbox":
        updated = await self._client.start(self.id, timeout=timeout)
        self._data = updated.to_dict()
        return self

    async def stop(self, *, timeout: Optional[float] = None) -> "AsyncSandbox":
        updated = await self._client.stop(self.id, timeout=timeout)
        self._data = updated.to_dict()
        return self

    async def resize(self, options: ResizeOptions, *, timeout: Optional[float] = None) -> "AsyncSandbox":
        updated = await self._client.resize(self.id, options, timeout=timeout)
        self._data = updated.to_dict()
        return self

    async def update_lifecycle(self, lifecycle: Lifecycle, *, timeout: Optional[float] = None) -> "AsyncSandbox":
        updated = await self._client.update_lifecycle(self.id, lifecycle, timeout=timeout)
        self._data = updated.to_dict()
        return self

    async def set_network_policy(self, options: NetworkPolicyOptions, *, timeout: Optional[float] = None) -> NetworkPolicy:
        policy = await self._client.set_network_policy(self.id, options, timeout=timeout)
        self._apply_network_policy(policy)
        return policy

    async def exec_command(self, command: str, *, timeout: Optional[float] = None) -> ExecResult:
        with _call_deadline(timeout):
            return await self._client.exec(self.id, {"command": command})

    async def clone_generation(self, *, timeout: Optional[float] = None) -> CloneGeneration:
        with _call_deadline(timeout):
            return await self._client.clone_generation(self.id)

    async def exec_stream(self, options: ExecStreamOptions, *, timeout: Optional[float] = None) -> AsyncExecStreamHandle:
        with _call_deadline(timeout):
            return await self._client.exec_stream(self.id, options)

    async def create_session(self, options: CreateSessionOptions, *, timeout: Optional[float] = None) -> Session:
        with _call_deadline(timeout):
            return await self._client.create_session(self.id, options)

    async def list_sessions(self, *, timeout: Optional[float] = None) -> List[Session]:
        with _call_deadline(timeout):
            return await self._client.list_sessions(self.id)

    async def get_session(self, session_id: str, *, timeout: Optional[float] = None) -> Session:
        with _call_deadline(timeout):
            return await self._client.get_session(self.id, session_id)

    async def delete_session(self, session_id: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.delete_session(self.id, session_id)

    async def signal_session(self, session_id: str, signal: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.signal_session(self.id, session_id, signal)

    async def resize_session(self, session_id: str, cols: int, rows: int, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.resize_session(self.id, session_id, cols, rows)

    async def session_log(self, session_id: str, *, timeout: Optional[float] = None) -> bytes:
        with _call_deadline(timeout):
            return await self._client.session_log(self.id, session_id)

    async def session_recording(self, session_id: str, *, timeout: Optional[float] = None) -> bytes:
        with _call_deadline(timeout):
            return await self._client.session_recording(self.id, session_id)

    async def attach_session(self, session_id: str, options: Optional[SessionAttachOptions] = None, *, timeout: Optional[float] = None) -> AsyncSessionAttachHandle:
        with _call_deadline(timeout):
            return await self._client.attach_session(self.id, session_id, options)

    async def upload_file(
        self,
        target_path: str,
        data: bytes,
        *,
        append: bool = False,
        create_only: bool = False,
        atomic: bool = False,
        mode: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        with _call_deadline(timeout):
            return await self._client.upload_file(self.id, target_path, data, append=append, create_only=create_only, atomic=atomic, mode=mode)

    async def download_file(self, target_path: str, *, max_bytes: Optional[int] = None, timeout: Optional[float] = None) -> bytes:
        with _call_deadline(timeout):
            return await self._client.download_file(self.id, target_path, max_bytes=max_bytes)

    async def download_file_to(self, target_path: str, dest: Any, *, max_bytes: Optional[int] = None, timeout: Optional[float] = None) -> int:
        with _call_deadline(timeout):
            return await self._client.download_file_to(self.id, target_path, dest, max_bytes=max_bytes)

    async def upload_file_from(
        self,
        target_path: str,
        src: Any,
        *,
        append: bool = False,
        create_only: bool = False,
        atomic: bool = False,
        mode: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        with _call_deadline(timeout):
            return await self._client.upload_file_from(self.id, target_path, src, append=append, create_only=create_only, atomic=atomic, mode=mode)

    async def watch_files(self, path: str, on_event: FileEventCallback, recursive: bool = False, *, timeout: Optional[float] = None) -> AsyncFileWatchHandle:
        with _call_deadline(timeout):
            return await self._client.watch_files(self.id, path, on_event, recursive=recursive)

    async def upload_dir(self, local_dir: str, remote_dir: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.upload_dir(self.id, local_dir, remote_dir)

    async def list_files(self, path: str, *, depth: int = 1, limit: int = DEFAULT_LIST_LIMIT, timeout: Optional[float] = None) -> FileList:
        with _call_deadline(timeout):
            return await self._client.list_files(self.id, path, depth=depth, limit=limit)

    async def get_file_info(self, path: str, *, timeout: Optional[float] = None) -> FileInfo:
        with _call_deadline(timeout):
            return await self._client.get_file_info(self.id, path)

    async def file_exists(self, path: str, *, timeout: Optional[float] = None) -> bool:
        with _call_deadline(timeout):
            return await self._client.file_exists(self.id, path)

    async def delete_file(self, path: str, *, recursive: bool = False, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.delete_file(self.id, path, recursive=recursive)

    async def make_dir(self, path: str, *, parents: bool = False, mode: Optional[int] = None, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.make_dir(self.id, path, parents=parents, mode=mode)

    async def move_file(self, source: str, destination: str, *, overwrite: bool = False, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.move_file(self.id, source, destination, overwrite=overwrite)

    async def copy_file(self, source: str, destination: str, *, overwrite: bool = False, recursive: bool = False, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.copy_file(self.id, source, destination, overwrite=overwrite, recursive=recursive)

    async def search_files(self, path: str, pattern: str, *, timeout: Optional[float] = None) -> List[str]:
        with _call_deadline(timeout):
            return await self._client.search_files(self.id, path, pattern)

    async def find_in_files(self, path: str, text: str, *, timeout: Optional[float] = None) -> List[FileMatch]:
        with _call_deadline(timeout):
            return await self._client.find_in_files(self.id, path, text)

    async def expose_port(
        self, port: int, *, protocol: ExposeProtocol = "http", visibility: Optional[ExposeVisibility] = None, timeout: Optional[float] = None
    ) -> ExposeResult:
        with _call_deadline(timeout):
            return await self._client.expose_port(self.id, port, protocol=protocol, visibility=visibility)

    async def unexpose_port(self, port: int, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.unexpose_port(self.id, port)

    async def create_token(
        self,
        *,
        expires_in: str,
        port: Optional[int] = None,
        path_prefix: Optional[str] = None,
        methods: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> SandboxToken:
        with _call_deadline(timeout):
            return await self._client.create_sandbox_token(
            self.id, expires_in=expires_in, port=port, path_prefix=path_prefix, methods=methods
        )

    async def revoke_tokens(self, *, timeout: Optional[float] = None) -> RevokeSandboxTokensResult:
        with _call_deadline(timeout):
            return await self._client.revoke_sandbox_tokens(self.id)

    async def add_custom_domain(
        self,
        hostname: str,
        *,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> List[CustomDomain]:
        with _call_deadline(timeout):
            return await self._client.add_custom_domain(self.id, hostname, port=port)

    async def list_custom_domains(self, *, timeout: Optional[float] = None) -> List[CustomDomain]:
        with _call_deadline(timeout):
            return await self._client.list_custom_domains(self.id)

    async def remove_custom_domain(self, hostname: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.remove_custom_domain(self.id, hostname)

    async def custom_domain_dns(self, *, timeout: Optional[float] = None) -> CustomDomainDNSRecords:
        with _call_deadline(timeout):
            return await self._client.custom_domain_dns(self.id)

    async def create_snapshot(self, name: str, *, allow_pause: Optional[bool] = None, timeout: Optional[float] = None) -> SandboxSnapshot:
        with _call_deadline(timeout):
            return await self._client.create_snapshot(self.id, name, allow_pause=allow_pause)

    async def destroy(self, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._client.destroy(self.id)

    async def get_network_usage(self, *, timeout: Optional[float] = None) -> NetworkUsage:
        with _call_deadline(timeout):
            return await self._client.get_network_usage(self.id)

    async def set_network_limits(self, options: SetNetworkLimitsOptions, *, timeout: Optional[float] = None) -> NetworkUsage:
        with _call_deadline(timeout):
            return await self._client.set_network_limits(self.id, options)

    async def learned(self, *, timeout: Optional[float] = None) -> NetworkLearned:
        with _call_deadline(timeout):
            return await self._client.get_network_learned(self.id)

    async def audit(self, options: Optional[AuditOptions] = None, *, timeout: Optional[float] = None) -> AuditPage:
        with _call_deadline(timeout):
            return await self._client.get_audit(self.id, options)


class AsyncMicroVM(_MicroVMCore):
    """An asyncio client for an AerolVM server: the calls of
    :class:`~microvm.MicroVM`, as coroutines, built from the same request
    code. Use it with ``async with`` (or call :meth:`close`) to release its
    connection pool.

    ``http_client`` is an optional ``httpx.AsyncClient`` to use instead of
    the one this client makes; its TLS settings then win over ``ca_file``
    and ``client_cert``, and closing it is up to you. Its own timeout
    bounds every call made without ``timeout=`` (httpx's default is 5 s;
    the client made here has none), and running out raises
    :class:`MicroVMTimeoutError`.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        pat_token: Optional[str] = None,
        *,
        api_version: str = _DEFAULT_API_VERSION,
        config: Optional[MicroVMConfig] = None,
        team: Optional[str] = None,
        ca_file: Optional[str] = None,
        client_cert: Union[str, Tuple[str, str], None] = None,
        headers: Optional[Dict[str, str]] = None,
        http_client: Any = None,
    ) -> None:
        if httpx is None:
            raise MicroVMError(_INSTALL_HINT)
        super().__init__(
            api_url,
            pat_token,
            api_version=api_version,
            config=config,
            team=team,
            ca_file=ca_file,
            client_cert=client_cert,
            headers=headers,
        )
        self._owns_http = http_client is None
        # No timeout and no redirects by default, as urllib behaves: a call's
        # own timeout= is the only bound, and the server never redirects.
        self._http = http_client or httpx.AsyncClient(
            verify=self._ssl_context if self._ssl_context is not None else True,
            timeout=None,
            follow_redirects=False,
        )

    async def close(self) -> None:
        """Closes the connection pool (unless it was passed in as
        ``http_client``). Safe to call more than once."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncMicroVM":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _run(self, op: Any) -> Any:
        """Drives an op as MicroVM._run does, awaiting this client's async
        transport for each I/O step."""
        result: Any = None
        error: Optional[BaseException] = None
        while True:
            try:
                call = op.throw(error) if error is not None else op.send(result)
            except StopIteration as done:
                return done.value
            try:
                result, error = await getattr(self, call.name)(*call.args, **call.kwargs), None
            except BaseException as exc:  # handed to the op, which may catch it
                result, error = None, exc

    async def _blocking(self, fn: Any, *args: Any) -> Any:
        # to_thread copies this task's context, so the call's deadline holds
        # in the thread too. A cancelled caller's stream is closed, not lost
        # (see _Handoff).
        handoff = _Handoff(fn, args)
        try:
            return await asyncio.to_thread(handoff.run)
        except BaseException:
            handoff.abandon()
            raise

    # The transport: the sync client's urllib methods, over httpx. Same
    # names and arguments, so the ops' I/O steps mean the same thing here.

    async def _request(
        self,
        method: str,
        url: str,
        body: Any = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        *,
        idempotent: bool = True,
        done_code: Optional[str] = None,
        send_once: bool = False,
    ) -> bytes:
        raw, _ = await self._request_headers(
            method, url, body, content_type, extra_headers, idempotent=idempotent, done_code=done_code, send_once=send_once
        )
        return raw

    async def _request_reader(self, method: str, url: str, reader: Any) -> Any:
        result, _ = await self._request_headers(method, url, reader=reader)
        return result

    async def _do_json(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        *,
        idempotent: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        data, _ = await self._do_json_headers(method, path, payload, idempotent=idempotent, headers=headers)
        return data

    async def _do_json_headers(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        *,
        idempotent: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Any, Any]:
        body, content_type = _json_body(payload)
        raw, response_headers = await self._request_headers(
            method, self._url(path), body, content_type, headers, idempotent=idempotent
        )
        return _json_answer(raw), response_headers

    async def _do_multipart(
        self,
        path: str,
        fields: Dict[str, str],
        file_field: str,
        filename: str,
        data: bytes,
        *,
        idempotent: bool = True,
        send_once: bool = False,
    ) -> None:
        body, content_type = _multipart_body(fields, file_field, filename, data)
        await self._request("POST", self._url(path), body, content_type, idempotent=idempotent, send_once=send_once)

    async def _request_headers(
        self,
        method: str,
        url: str,
        body: Any = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        *,
        idempotent: bool = True,
        done_code: Optional[str] = None,
        send_once: bool = False,
        reader: Any = None,
    ) -> Tuple[Any, Any]:
        """MicroVM._request_headers over httpx, with the same retry rules:
        the same statuses per tier, done_code, Retry-After pacing, send_once,
        the cell redirect and deadline handling. tests/test_async.py runs one
        scenario table against both clients to keep them equal."""
        streamed = body is not None and not isinstance(body, (bytes, bytearray))
        max_retries = 0 if (send_once or streamed) else self._retry_config["maxRetries"]
        retry_statuses = _RETRY_STATUSES if idempotent else _NOT_STARTED_STATUSES
        headers = httpx.Headers()
        for key, value in self._header_items(content_type, extra_headers):
            headers[key] = value
        last_exc: Optional[BaseException] = None
        may_have_run = False  # done_code: see MicroVM._request
        base, path, sandbox_id = self._cell_route(url)
        url = base + path
        followed = False

        attempt = 0
        while attempt <= max_retries:
            retry_after: Optional[str] = None
            left = _time_left()
            if left is not None and left <= 0:
                raise _deadline_error() from last_exc
            content = _async_body(body) if streamed else body
            request = self._http.build_request(
                method, url, content=content, headers=headers, timeout=httpx.USE_CLIENT_DEFAULT if left is None else left
            )
            body_started = False
            try:
                response = await self._http.send(request, stream=True)
            except httpx.TimeoutException as exc:
                last_exc = exc
                if left is not None:
                    raise _deadline_error() from exc
                if attempt >= max_retries or not (idempotent or _never_sent(exc)):
                    raise _transport_timeout(exc) from exc
                may_have_run = may_have_run or not _never_sent(exc)
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt >= max_retries or not (idempotent or _never_sent(exc)):
                    raise
                may_have_run = may_have_run or not _never_sent(exc)
            else:
                try:
                    if response.status_code < 400:
                        if reader is None:
                            return await response.aread(), response.headers
                        body_started = True
                        loop = asyncio.get_running_loop()
                        result = await asyncio.to_thread(reader, _SyncBody(loop, response), response.headers)
                        return result, response.headers
                    payload = await response.aread()
                    cell = _cell_header(response.status_code, response.headers)
                    if cell:
                        # As MicroVM._request_headers: once to the cell named,
                        # never a second hop, never a streamed body again.
                        moved = None if followed else self._learn_cell(sandbox_id, cell)
                        if moved is not None and path and not streamed:
                            base, url, followed = moved, moved + path, True
                            continue
                        raise _error_from_answer(response.status_code, response.reason_phrase, response.headers.get("Retry-After"), payload)
                    if done_code is not None and may_have_run and _error_code(payload) == done_code:
                        return b"", {}
                    if response.status_code == 404:
                        self._cell_not_found(sandbox_id, base, payload)
                    if response.status_code in _REPLY_LOST_STATUSES:
                        may_have_run = True
                    if response.status_code in retry_statuses and attempt < max_retries:
                        if response.status_code in _NOT_STARTED_STATUSES:
                            retry_after = response.headers.get("Retry-After")
                        last_exc = _error_from_answer(response.status_code, response.reason_phrase, response.headers.get("Retry-After"), payload)
                    else:
                        raise _error_from_answer(response.status_code, response.reason_phrase, response.headers.get("Retry-After"), payload)
                except MicroVMError:
                    raise
                except httpx.TimeoutException as exc:
                    last_exc = exc
                    if left is not None:
                        raise _deadline_error() from exc
                    if attempt >= max_retries or not idempotent or body_started:
                        raise _transport_timeout(exc) from exc
                    may_have_run = True
                except httpx.TransportError as exc:
                    # The answer broke off while it was read: the server may
                    # already be acting on the request.
                    last_exc = exc
                    if attempt >= max_retries or not idempotent or body_started:
                        raise
                    may_have_run = True
                finally:
                    await response.aclose()

            delay = self._retry_delay(attempt, retry_after, time.time(), random.random())
            left = _time_left()
            if left is not None and delay >= left:
                raise _deadline_error() from last_exc
            await asyncio.sleep(delay)
            attempt += 1

        assert last_exc is not None
        if isinstance(last_exc, httpx.TimeoutException):
            raise _transport_timeout(last_exc) from last_exc
        raise last_exc

    def _exec_stream_handle(self, websocket_module: Any, ws: Any, options: ExecStreamOptions) -> AsyncExecStreamHandle:
        wrapped = _loop_options(options, ("onStdout", "onStderr", "onError"))
        return AsyncExecStreamHandle(ExecStreamHandle(websocket_module, ws, wrapped))  # type: ignore[arg-type]

    def _session_attach_handle(self, websocket_module: Any, ws: Any, options: SessionAttachOptions) -> AsyncSessionAttachHandle:
        wrapped = _loop_options(options, ("onStdout", "onStderr", "onExit", "onError"))
        return AsyncSessionAttachHandle(SessionAttachHandle(websocket_module, ws, wrapped))  # type: ignore[arg-type]

    def _file_watch_handle(self, ws: Any, on_event: FileEventCallback) -> AsyncFileWatchHandle:
        return AsyncFileWatchHandle(FileWatchHandle(ws, _on_loop(asyncio.get_running_loop(), on_event)))

    async def iter_pages(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        include_env: bool = False,
        name: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[List["AsyncSandbox"]]:
        base_path = self._versioned("/sandboxes") + _build_sandbox_query(tags, include_env, name)
        page_token = ""
        for _ in range(_MAX_LIST_PAGES):
            with _call_deadline(timeout):
                page, page_token = await self._run(self._op_list_page(base_path, page_token))
            yield page
            if page_token == "":
                return
        raise MicroVMError("incomplete cluster list: exceeded max pages")

    async def create(self, options: Optional[CreateOptions] = None, *, timeout: Optional[float] = None, **fields: Any) -> AsyncSandbox:
        with _call_deadline(timeout):
            return await self._run(self._op_create(options, **fields))

    async def build_image(self, image: Image, *, timeout: Optional[float] = None) -> str:
        with _call_deadline(timeout):
            return await self._run(self._op_build_image(image))

    async def build_image_with_push(
        self,
        image: Image,
        *,
        push: Optional[BuildImagePushOptions] = None,
        timeout: Optional[float] = None,
    ) -> BuildImageResult:
        with _call_deadline(timeout):
            return await self._run(self._op_build_image_with_push(image, push=push))

    async def list(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        include_env: bool = False,
        name: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> List[AsyncSandbox]:
        with _call_deadline(timeout):
            return await self._run(self._op_list(tags=tags, include_env=include_env, name=name))

    async def get_by_name(self, name: str, *, include_env: bool = False, timeout: Optional[float] = None) -> Optional[AsyncSandbox]:
        with _call_deadline(timeout):
            return await self._run(self._op_get_by_name(name, include_env=include_env))

    async def get_or_create(self, name: str, options: Optional[CreateOptions] = None, *, timeout: Optional[float] = None, **fields: Any) -> Tuple[AsyncSandbox, bool]:
        with _call_deadline(timeout):
            return await self._run(self._op_get_or_create(name, options, **fields))

    async def get(self, sandbox_id: str, *, include_env: bool = False, timeout: Optional[float] = None) -> AsyncSandbox:
        with _call_deadline(timeout):
            return await self._run(self._op_get(sandbox_id, include_env=include_env))

    async def start(self, sandbox_id: str, *, timeout: Optional[float] = None) -> AsyncSandbox:
        with _call_deadline(timeout):
            return await self._run(self._op_start(sandbox_id))

    async def stop(self, sandbox_id: str, *, timeout: Optional[float] = None) -> AsyncSandbox:
        with _call_deadline(timeout):
            return await self._run(self._op_stop(sandbox_id))

    async def create_snapshot(
        self, sandbox_id: str, name: str, *, allow_pause: Optional[bool] = None, timeout: Optional[float] = None
    ) -> SandboxSnapshot:
        with _call_deadline(timeout):
            return await self._run(self._op_create_snapshot(sandbox_id, name, allow_pause=allow_pause))

    async def register_snapshot(self, options: RegisterSnapshotOptions, *, timeout: Optional[float] = None) -> SandboxSnapshot:
        with _call_deadline(timeout):
            return await self._run(self._op_register_snapshot(options))

    async def register_snapshot_from_image(
        self,
        name: str,
        image: Image,
        options: Optional[RegisterSnapshotOptions] = None,
        *,
        timeout: Optional[float] = None,
    ) -> SandboxSnapshot:
        with _call_deadline(timeout):
            return await self._run(self._op_register_snapshot_from_image(name, image, options))

    async def get_snapshot(self, name: str, *, timeout: Optional[float] = None) -> SandboxSnapshot:
        with _call_deadline(timeout):
            return await self._run(self._op_get_snapshot(name))

    async def list_snapshots(
        self,
        limit: Optional[int] = None,
        starting_after: Optional[str] = None,
        *,
        timeout: Optional[float] = None,
    ) -> SnapshotList:
        with _call_deadline(timeout):
            return await self._run(self._op_list_snapshots(limit, starting_after))

    async def delete_snapshot(self, name: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_snapshot(name))

    async def destroy(self, sandbox_id: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_destroy(sandbox_id))

    async def destroy_all(self, *, tags: Dict[str, str], timeout: Optional[float] = None) -> List[str]:
        with _call_deadline(timeout):
            return await self._run(self._op_destroy_all(tags=tags))

    async def create_template(self, options: CreateTemplateOptions, *, timeout: Optional[float] = None) -> Template:
        with _call_deadline(timeout):
            return await self._run(self._op_create_template(options))

    async def list_templates(self, *, timeout: Optional[float] = None) -> List[Template]:
        with _call_deadline(timeout):
            return await self._run(self._op_list_templates())

    async def get_template(self, template_id: str, *, timeout: Optional[float] = None) -> Template:
        with _call_deadline(timeout):
            return await self._run(self._op_get_template(template_id))

    async def delete_template(self, template_id: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_template(template_id))

    async def create_wasm_module(self, options: CreateWasmModuleOptions, *, timeout: Optional[float] = None) -> WasmModule:
        with _call_deadline(timeout):
            return await self._run(self._op_create_wasm_module(options))

    async def list_wasm_modules(self, *, timeout: Optional[float] = None) -> List[WasmModule]:
        with _call_deadline(timeout):
            return await self._run(self._op_list_wasm_modules())

    async def get_wasm_module(self, module_id: str, *, timeout: Optional[float] = None) -> WasmModule:
        with _call_deadline(timeout):
            return await self._run(self._op_get_wasm_module(module_id))

    async def delete_wasm_module(self, module_id: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_wasm_module(module_id))

    async def push_wasm_module(self, options: PushWasmModuleOptions, *, timeout: Optional[float] = None) -> PushWasmModuleResult:
        with _call_deadline(timeout):
            return await self._run(self._op_push_wasm_module(options))

    async def rebuild_template(self, template_id: str, *, timeout: Optional[float] = None) -> Template:
        with _call_deadline(timeout):
            return await self._run(self._op_rebuild_template(template_id))

    async def resize(self, sandbox_id: str, options: ResizeOptions, *, timeout: Optional[float] = None) -> AsyncSandbox:
        with _call_deadline(timeout):
            return await self._run(self._op_resize(sandbox_id, options))

    async def update_lifecycle(self, sandbox_id: str, lifecycle: Lifecycle, *, timeout: Optional[float] = None) -> AsyncSandbox:
        with _call_deadline(timeout):
            return await self._run(self._op_update_lifecycle(sandbox_id, lifecycle))

    async def reconcile(self, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_reconcile())

    async def health(self, *, timeout: Optional[float] = None) -> HealthStatus:
        with _call_deadline(timeout):
            return await self._run(self._op_health())

    async def mounts(self, sandbox_id: str, *, timeout: Optional[float] = None) -> List[MountSpecRedacted]:
        with _call_deadline(timeout):
            return await self._run(self._op_mounts(sandbox_id))

    async def clone_generation(self, sandbox_id: str, *, timeout: Optional[float] = None) -> CloneGeneration:
        with _call_deadline(timeout):
            return await self._run(self._op_clone_generation(sandbox_id))

    async def get_network_usage(self, sandbox_id: str, *, timeout: Optional[float] = None) -> NetworkUsage:
        with _call_deadline(timeout):
            return await self._run(self._op_get_network_usage(sandbox_id))

    async def check_network_policy(self, options: NetworkPolicyCheckOptions, *, timeout: Optional[float] = None) -> NetworkPolicyCheckResult:
        with _call_deadline(timeout):
            return await self._run(self._op_check_network_policy(options))

    async def get_audit(self, sandbox_id: str, options: Optional[AuditOptions] = None, *, timeout: Optional[float] = None) -> AuditPage:
        with _call_deadline(timeout):
            return await self._run(self._op_get_audit(sandbox_id, options))

    async def set_network_limits(self, sandbox_id: str, options: SetNetworkLimitsOptions, *, timeout: Optional[float] = None) -> NetworkUsage:
        with _call_deadline(timeout):
            return await self._run(self._op_set_network_limits(sandbox_id, options))

    async def set_network_policy(self, sandbox_id: str, options: NetworkPolicyOptions, *, timeout: Optional[float] = None) -> NetworkPolicy:
        with _call_deadline(timeout):
            return await self._run(self._op_set_network_policy(sandbox_id, options))

    async def get_network_learned(self, sandbox_id: str, *, timeout: Optional[float] = None) -> NetworkLearned:
        with _call_deadline(timeout):
            return await self._run(self._op_get_network_learned(sandbox_id))

    async def put_egress_profile(self, name: str, options: EgressProfileOptions, *, timeout: Optional[float] = None) -> EgressProfile:
        with _call_deadline(timeout):
            return await self._run(self._op_put_egress_profile(name, options))

    async def get_egress_profile(self, name: str, *, timeout: Optional[float] = None) -> EgressProfile:
        with _call_deadline(timeout):
            return await self._run(self._op_get_egress_profile(name))

    async def list_egress_profiles(self, options: Optional[ListEgressProfilesOptions] = None, *, timeout: Optional[float] = None) -> EgressProfileList:
        with _call_deadline(timeout):
            return await self._run(self._op_list_egress_profiles(options))

    async def delete_egress_profile(self, name: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_egress_profile(name))

    async def put_identity_role(self, tag: str, options: IdentityRoleOptions, *, timeout: Optional[float] = None) -> IdentityRole:
        with _call_deadline(timeout):
            return await self._run(self._op_put_identity_role(tag, options))

    async def list_identity_roles(
        self, options: Optional[ListIdentityRolesOptions] = None, *, timeout: Optional[float] = None
    ) -> IdentityRoleList:
        with _call_deadline(timeout):
            return await self._run(self._op_list_identity_roles(options))

    async def delete_identity_role(
        self, tag: str, options: Optional[IdentityRoleOptions] = None, *, timeout: Optional[float] = None
    ) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_identity_role(tag, options))

    async def put_team_quota(self, team: str, options: TeamQuotaOptions, *, timeout: Optional[float] = None) -> TeamQuota:
        with _call_deadline(timeout):
            return await self._run(self._op_put_team_quota(team, options))

    async def get_team_quota(self, team: str, *, timeout: Optional[float] = None) -> TeamQuota:
        with _call_deadline(timeout):
            return await self._run(self._op_get_team_quota(team))

    async def delete_team_quota(self, team: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_team_quota(team))

    async def put_warm_pool(self, image: str, options: WarmPoolOptions, *, timeout: Optional[float] = None) -> WarmPool:
        with _call_deadline(timeout):
            return await self._run(self._op_put_warm_pool(image, options))

    async def get_warm_pool(self, image: str, *, timeout: Optional[float] = None) -> WarmPool:
        with _call_deadline(timeout):
            return await self._run(self._op_get_warm_pool(image))

    async def list_warm_pools(self, *, timeout: Optional[float] = None) -> List[WarmPool]:
        with _call_deadline(timeout):
            return await self._run(self._op_list_warm_pools())

    async def delete_warm_pool(self, image: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_warm_pool(image))

    async def whoami(self, *, timeout: Optional[float] = None) -> WhoAmI:
        with _call_deadline(timeout):
            return await self._run(self._op_whoami())

    async def exec(self, sandbox_id: str, request: ExecRequest, *, timeout: Optional[float] = None) -> ExecResult:
        with _call_deadline(timeout):
            return await self._run(self._op_exec(sandbox_id, request))

    async def exec_stream(self, sandbox_id: str, options: ExecStreamOptions, *, timeout: Optional[float] = None) -> AsyncExecStreamHandle:
        with _call_deadline(timeout):
            return await self._run(self._op_exec_stream(sandbox_id, options))

    async def create_session(self, sandbox_id: str, options: CreateSessionOptions, *, timeout: Optional[float] = None) -> Session:
        with _call_deadline(timeout):
            return await self._run(self._op_create_session(sandbox_id, options))

    async def list_sessions(self, sandbox_id: str, *, timeout: Optional[float] = None) -> List[Session]:
        with _call_deadline(timeout):
            return await self._run(self._op_list_sessions(sandbox_id))

    async def get_session(self, sandbox_id: str, session_id: str, *, timeout: Optional[float] = None) -> Session:
        with _call_deadline(timeout):
            return await self._run(self._op_get_session(sandbox_id, session_id))

    async def delete_session(self, sandbox_id: str, session_id: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_session(sandbox_id, session_id))

    async def signal_session(self, sandbox_id: str, session_id: str, signal: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_signal_session(sandbox_id, session_id, signal))

    async def resize_session(self, sandbox_id: str, session_id: str, cols: int, rows: int, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_resize_session(sandbox_id, session_id, cols, rows))

    async def session_log(self, sandbox_id: str, session_id: str, *, timeout: Optional[float] = None) -> bytes:
        with _call_deadline(timeout):
            return await self._run(self._op_session_log(sandbox_id, session_id))

    async def session_recording(self, sandbox_id: str, session_id: str, *, timeout: Optional[float] = None) -> bytes:
        with _call_deadline(timeout):
            return await self._run(self._op_session_recording(sandbox_id, session_id))

    async def attach_session(
        self,
        sandbox_id: str,
        session_id: str,
        options: Optional[SessionAttachOptions] = None,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncSessionAttachHandle:
        with _call_deadline(timeout):
            return await self._run(self._op_attach_session(sandbox_id, session_id, options))

    async def _require_toolbox_features(self, sandbox_id: str, *features: str) -> None:
        await self._run(self._op_require_toolbox_features(sandbox_id, *features))

    async def upload_file(
        self,
        sandbox_id: str,
        target_path: str,
        data: bytes,
        *,
        append: bool = False,
        create_only: bool = False,
        atomic: bool = False,
        mode: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_upload_file(sandbox_id, target_path, data, append=append, create_only=create_only, atomic=atomic, mode=mode))

    async def upload_dir(self, sandbox_id: str, local_dir: str, remote_dir: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_upload_dir(sandbox_id, local_dir, remote_dir))

    async def download_file(self, sandbox_id: str, target_path: str, *, max_bytes: Optional[int] = None, timeout: Optional[float] = None) -> bytes:
        with _call_deadline(timeout):
            return await self._run(self._op_download_file(sandbox_id, target_path, max_bytes=max_bytes))

    async def download_file_to(
        self,
        sandbox_id: str,
        target_path: str,
        dest: Any,
        *,
        max_bytes: Optional[int] = None,
        chunk_size: int = 1 << 20,
        timeout: Optional[float] = None,
    ) -> int:
        with _call_deadline(timeout):
            return await self._run(self._op_download_file_to(sandbox_id, target_path, dest, max_bytes=max_bytes, chunk_size=chunk_size))

    async def upload_file_from(
        self,
        sandbox_id: str,
        target_path: str,
        src: Any,
        *,
        append: bool = False,
        create_only: bool = False,
        atomic: bool = False,
        mode: Optional[int] = None,
        chunk_size: int = 1 << 20,
        timeout: Optional[float] = None,
    ) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_upload_file_from(sandbox_id, target_path, src, append=append, create_only=create_only, atomic=atomic, mode=mode, chunk_size=chunk_size))

    async def watch_files(
        self,
        sandbox_id: str,
        path: str,
        on_event: FileEventCallback,
        recursive: bool = False,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncFileWatchHandle:
        with _call_deadline(timeout):
            return await self._run(self._op_watch_files(sandbox_id, path, on_event, recursive))

    async def list_files(self, sandbox_id: str, path: str, *, depth: int = 1, limit: int = DEFAULT_LIST_LIMIT, timeout: Optional[float] = None) -> FileList:
        with _call_deadline(timeout):
            return await self._run(self._op_list_files(sandbox_id, path, depth=depth, limit=limit))

    async def get_file_info(self, sandbox_id: str, path: str, *, timeout: Optional[float] = None) -> FileInfo:
        with _call_deadline(timeout):
            return await self._run(self._op_get_file_info(sandbox_id, path))

    async def file_exists(self, sandbox_id: str, path: str, *, timeout: Optional[float] = None) -> bool:
        with _call_deadline(timeout):
            return await self._run(self._op_file_exists(sandbox_id, path))

    async def delete_file(self, sandbox_id: str, path: str, *, recursive: bool = False, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_delete_file(sandbox_id, path, recursive=recursive))

    async def make_dir(self, sandbox_id: str, path: str, *, parents: bool = False, mode: Optional[int] = None, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_make_dir(sandbox_id, path, parents=parents, mode=mode))

    async def move_file(self, sandbox_id: str, source: str, destination: str, *, overwrite: bool = False, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_move_file(sandbox_id, source, destination, overwrite=overwrite))

    async def copy_file(self, sandbox_id: str, source: str, destination: str, *, overwrite: bool = False, recursive: bool = False, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_copy_file(sandbox_id, source, destination, overwrite=overwrite, recursive=recursive))

    async def search_files(self, sandbox_id: str, path: str, pattern: str, *, timeout: Optional[float] = None) -> List[str]:
        with _call_deadline(timeout):
            return await self._run(self._op_search_files(sandbox_id, path, pattern))

    async def find_in_files(self, sandbox_id: str, path: str, text: str, *, timeout: Optional[float] = None) -> List[FileMatch]:
        with _call_deadline(timeout):
            return await self._run(self._op_find_in_files(sandbox_id, path, text))

    async def expose_port(
        self,
        sandbox_id: str,
        port: int,
        *,
        protocol: ExposeProtocol = "http",
        visibility: Optional[ExposeVisibility] = None,
        timeout: Optional[float] = None,
    ) -> ExposeResult:
        with _call_deadline(timeout):
            return await self._run(self._op_expose_port(sandbox_id, port, protocol=protocol, visibility=visibility))

    async def unexpose_port(self, sandbox_id: str, port: int, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_unexpose_port(sandbox_id, port))

    async def create_sandbox_token(
        self,
        sandbox_id: str,
        *,
        expires_in: str,
        port: Optional[int] = None,
        path_prefix: Optional[str] = None,
        methods: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> SandboxToken:
        with _call_deadline(timeout):
            return await self._run(self._op_create_sandbox_token(sandbox_id, expires_in=expires_in, port=port, path_prefix=path_prefix, methods=methods))

    async def revoke_sandbox_tokens(self, sandbox_id: str, *, timeout: Optional[float] = None) -> RevokeSandboxTokensResult:
        with _call_deadline(timeout):
            return await self._run(self._op_revoke_sandbox_tokens(sandbox_id))

    async def add_custom_domain(
        self,
        sandbox_id: str,
        hostname: str,
        *,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> List[CustomDomain]:
        with _call_deadline(timeout):
            return await self._run(self._op_add_custom_domain(sandbox_id, hostname, port=port))

    async def list_custom_domains(self, sandbox_id: str, *, timeout: Optional[float] = None) -> List[CustomDomain]:
        with _call_deadline(timeout):
            return await self._run(self._op_list_custom_domains(sandbox_id))

    async def remove_custom_domain(self, sandbox_id: str, hostname: str, *, timeout: Optional[float] = None) -> None:
        with _call_deadline(timeout):
            return await self._run(self._op_remove_custom_domain(sandbox_id, hostname))

    async def dns_target(self, *, timeout: Optional[float] = None) -> IngressTarget:
        with _call_deadline(timeout):
            return await self._run(self._op_dns_target())

    async def custom_domain_dns(self, sandbox_id: str, *, timeout: Optional[float] = None) -> CustomDomainDNSRecords:
        with _call_deadline(timeout):
            return await self._run(self._op_custom_domain_dns(sandbox_id))


AsyncMicroVM._sandbox_class = AsyncSandbox
AsyncMicroVM._tokens_class = AsyncTokens


def _copy_docs(sync_cls: type, async_cls: type) -> None:
    """The async calls carry the sync ones' docstrings: one text, no drift."""
    for name, member in vars(async_cls).items():
        if name.startswith("__") or not callable(member) or getattr(member, "__doc__", None):
            continue
        source = getattr(sync_cls, name, None)
        if source is not None and source.__doc__:
            member.__doc__ = source.__doc__


for _sync_cls, _async_cls in ((MicroVM, AsyncMicroVM), (MicroVM._sandbox_class, AsyncSandbox), (Tokens, AsyncTokens)):
    _copy_docs(_sync_cls, _async_cls)
