from __future__ import annotations

import datetime
import email.utils
import importlib
import json
import os
import random
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import Future, InvalidStateError, TimeoutError as FutureTimeoutError
from io import BytesIO
from typing import Any, Dict, Iterator, List, Optional, Union

from ._internal.api.v1.paths import PATH_PREFIX as _V1_PATH_PREFIX
from .image import Image
from .types import (
    APIToken,
    APITokenList,
    CreateAPITokenOptions,
    CreatedAPIToken,
    WhoAmI,
    BuildImagePushOptions,
    BuildImageResult,
    CloneGeneration,
    CreateOptions,
    CreateSessionOptions,
    CreateTemplateOptions,
    CreateWasmModuleOptions,
    CustomDomain,
    CustomDomainDNSRecords,
    DNSRecord,
    ExecExitInfo,
    ExecRequest,
    ExecResult,
    ExecStreamOptions,
    ExposeProtocol,
    FileEvent,
    FileEventCallback,
    ExposeResult,
    Failover,
    FileInfo,
    FileList,
    FileMatch,
    GPUOptions,
    HealthStatus,
    IngressTarget,
    Lifecycle,
    MicroVMConfig,
    MountSpec,
    MountSpecRedacted,
    NetworkUsage,
    AuditEvent,
    AuditOptions,
    AuditPage,
    EgressProfile,
    EgressProfileList,
    EgressProfileOptions,
    EgressRule,
    ListEgressProfilesOptions,
    NetworkLearned,
    NetworkPolicy,
    NetworkPolicyCheckOptions,
    NetworkPolicyCheckResult,
    NetworkPolicyOptions,
    PlatformVolumeMount,
    RegisterSnapshotOptions,
    ResizeOptions,
    RetryConfig,
    SandboxData,
    SandboxSnapshot,
    Session,
    SessionAttachOptions,
    SetNetworkLimitsOptions,
    SnapshotList,
    Template,
    WasmModule,
    PushWasmModuleOptions,
    PushWasmModuleResult,
)

STREAM_PREFIX_STDOUT = 0x01
STREAM_PREFIX_STDERR = 0x02

# Wire versions of the sandbox daemon API this SDK can call. Today only "v1"
# exists; a new wire version will be added when a breaking change ships on
# the server. The SDK package version and the API wire version evolve
# independently — bumping this SDK does not move the wire version.
_DEFAULT_API_VERSION = "v1"
_PATH_PREFIXES: Dict[str, str] = {
    "v1": _V1_PATH_PREFIX,
}

# Statuses retried on an idempotent request. 421 is a misdirected request (a
# stale route or a coalesced connection): the server closes the connection,
# so the retry reconnects and the ingress re-routes it.
_RETRY_STATUSES = frozenset({421, 429, 502, 503, 504})
# A request that must not run twice (exec) retries only the statuses that say
# the server turned it away before doing any work. A 421, 502 or 504 comes
# from a hop that already read the request, so whether the command started
# is unknown. These are also the statuses whose Retry-After paces clients:
# 429 when this caller is over its share, 503 when the node sheds load. A
# Retry-After on a 421, 502 or 504 is a hop's, so those use the backoff.
_NOT_STARTED_STATUSES = frozenset({429, 503})
# The toolboxd feature (on /version) behind the file verbs' options: list
# depth and cap, the move and copy overwrite guard, mkdir without parents and
# the copy route. An older agent ignores those options (overwrite=false would
# overwrite), so the calls that send them check first.
_FEATURE_FILE_VERBS = "files.verbs"
# The entry cap list_files sends when the caller gives none.
DEFAULT_LIST_LIMIT = 10000
# Error codes toolboxd puts on the file errors a retry acts on: a retried
# delete that finds the path gone, or a retried mkdir that finds its folder,
# means the first attempt did the work and its reply was lost.
_CODE_FILE_NOT_FOUND = "file_not_found"
_CODE_FOLDER_EXISTS = "folder_exists"
# An overloaded node asks for about a second, so the cap only bites on a long
# ask (maintenance, a misconfigured proxy), which should not hold a call for
# minutes per retry.
_DEFAULT_MAX_RETRY_AFTER_MS = 30000
# Longer delta-seconds values are clamped: no cap is that long anyway.
_MAX_RETRY_AFTER_SECONDS = 10**9


def _parse_retry_after(value: Optional[str], now: float) -> Optional[float]:
    """Seconds a ``Retry-After`` value asks for, in either form RFC 9110
    allows: delta-seconds (``"120"``) or an HTTP date. A date already past is
    0. ``None`` for an absent or malformed value. ``now`` is a Unix time."""
    text = (value or "").strip()
    # isascii: str.isdigit alone also takes digits such as "²".
    if text.isascii() and text.isdigit():
        return float(min(int(text), _MAX_RETRY_AFTER_SECONDS))
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        # The asctime form carries no zone; HTTP dates are always GMT.
        when = when.replace(tzinfo=datetime.timezone.utc)
    return max(when.timestamp() - now, 0.0)


def _normalize_url(value: str) -> str:
    return value.rstrip("/")


def _read_env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else None


# The request header that selects which of a credential's teams a request
# acts for. Keep in sync with pkg/api.HeaderTeam on the server.
TEAM_HEADER = "X-AerolVM-Team"

# The header a sandbox create carries so the server can recognise a retry of
# it. Keep in sync with clustercreate.HeaderIdempotencyKey on the server.
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"


def _new_idempotency_key() -> str:
    """A fresh create key: 128 random bits as 32 lowercase hex characters."""
    return secrets.token_hex(16)


class MicroVMError(Exception):
    pass


class MicroVMUnsupportedFeatureError(MicroVMError):
    """The sandbox's agent (toolboxd) is older than an option this call
    needs. An older agent would silently ignore the option (an overwrite
    guard, an output cap), so the SDK refuses instead of sending it.

    Restart the sandbox, or re-create its Firecracker template, to get the
    current agent. ``features`` lists what was missing.
    """

    def __init__(self, sandbox_id: str, features: List[str], agent_version: str = "") -> None:
        self.sandbox_id = sandbox_id
        self.features = features
        self.agent_version = agent_version
        agent = f"toolboxd {agent_version}" if agent_version else "an older toolboxd"
        super().__init__(
            f"sandbox {sandbox_id} runs {agent}, which does not support {', '.join(features)}; "
            "restart the sandbox, or re-create its Firecracker template, to get the current agent"
        )


class MicroVMHTTPError(MicroVMError):
    """An HTTP error response from sandboxd. ``str(err)`` is the server's
    message, or the HTTP reason phrase when the body is not the server's
    JSON (a proxy's error page). ``status_code`` is the HTTP status. The
    other attributes are empty unless the server sent them:

    - ``code``: a stable error code a client can act on, such as
      ``idempotency_key_reused`` or ``overloaded``.
    - ``retry_after``: how many seconds the response's ``Retry-After``
      header asked the caller to wait; ``None`` without a usable header.
    - ``reason``: why an avm_ API token or an OIDC token was refused
      (``expired``, ``unknown_or_revoked``, ``no_binding``, ...).
    - ``required_permission`` and ``role``: on a 403 for an API token or an
      OIDC caller, the permission the route needs and the role held.
    - ``issuer``, ``name`` and ``groups``: on the 403 an OIDC caller gets
      when no role binding matches, the caller's own claims.
    """

    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        code: str = "",
        reason: str = "",
        required_permission: str = "",
        role: str = "",
        issuer: str = "",
        name: str = "",
        groups: Optional[List[str]] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.retry_after = retry_after
        self.reason = reason
        self.required_permission = required_permission
        self.role = role
        self.issuer = issuer
        self.name = name
        self.groups: List[str] = list(groups or [])


def _http_error(status_code: int, data: Any, fallback: str, retry_after: Optional[float] = None) -> MicroVMHTTPError:
    """Builds the error for a decoded JSON error body."""
    if not isinstance(data, dict):
        return MicroVMHTTPError(status_code, fallback, retry_after=retry_after)
    groups = data.get("groups")
    return MicroVMHTTPError(
        status_code,
        str(data.get("error", fallback)),
        retry_after=retry_after,
        code=str(data.get("code") or ""),
        reason=str(data.get("reason") or ""),
        required_permission=str(data.get("required_permission") or ""),
        role=str(data.get("role") or ""),
        issuer=str(data.get("issuer") or ""),
        name=str(data.get("name") or ""),
        groups=[str(g) for g in groups] if isinstance(groups, list) else None,
    )


class ExecStreamHandle:
    def __init__(self, websocket_module: Any, ws: Any, options: ExecStreamOptions) -> None:
        self._websocket_module = websocket_module
        self._ws = ws
        self._options = options
        self._done: Future[ExecExitInfo] = Future()
        self._send_lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    @property
    def done(self) -> Future[ExecExitInfo]:
        return self._done

    def write(self, data: bytes | str) -> None:
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        with self._send_lock:
            self._ws.send(payload, opcode=self._websocket_module.ABNF.OPCODE_BINARY)

    def resize(self, cols: int, rows: int) -> None:
        self._send_json({"type": "resize", "cols": cols, "rows": rows})

    def signal(self, name: str) -> None:
        self._send_json({"type": "signal", "signal": name})

    def close(self) -> None:
        self._send_json({"type": "close"})

    def wait(self, timeout: Optional[float] = None) -> ExecExitInfo:
        try:
            return self._done.result(timeout)
        except FutureTimeoutError as exc:
            raise TimeoutError("timed out waiting for stream completion") from exc

    def _send_json(self, payload: Dict[str, Any]) -> None:
        with self._send_lock:
            self._ws.send(json.dumps(payload))

    def _read_loop(self) -> None:
        try:
            while True:
                message = self._ws.recv()
                if isinstance(message, str):
                    self._handle_text_frame(message)
                    if self._done.done():
                        break
                    continue

                payload = bytes(message)
                if len(payload) == 0:
                    continue

                stream = payload[0]
                chunk = payload[1:]
                if stream == STREAM_PREFIX_STDOUT:
                    callback = self._options.get("onStdout")
                    if callback is not None:
                        callback(chunk)
                elif stream == STREAM_PREFIX_STDERR:
                    callback = self._options.get("onStderr")
                    if callback is not None:
                        callback(chunk)
        except Exception as exc:
            if not self._done.done():
                self._done.set_exception(MicroVMError(f"stream closed before exit: {exc}"))
        finally:
            try:
                self._ws.close()
            except Exception:
                # The peer may already have closed the socket.
                pass

    def _handle_text_frame(self, payload: str) -> None:
        try:
            message = json.loads(payload)
        except json.JSONDecodeError:
            return

        if message.get("type") == "exit":
            if not self._done.done():
                result: ExecExitInfo = {"code": int(message.get("code", 0))}
                signal = message.get("signal")
                if isinstance(signal, str) and signal != "":
                    result["signal"] = signal
                self._done.set_result(result)
            return

        if message.get("type") == "error":
            error_message = str(message.get("message") or "stream error")
            callback = self._options.get("onError")
            if callback is not None:
                callback(error_message)
            if not self._done.done():
                self._done.set_exception(MicroVMError(error_message))


class SessionAttachHandle:
    def __init__(self, websocket_module: Any, ws: Any, options: SessionAttachOptions) -> None:
        self._websocket_module = websocket_module
        self._ws = ws
        self._options = options
        self._done: Future[ExecExitInfo] = Future()
        self._send_lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    @property
    def done(self) -> Future[ExecExitInfo]:
        return self._done

    def write(self, data: bytes | str) -> None:
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        with self._send_lock:
            self._ws.send(payload, opcode=self._websocket_module.ABNF.OPCODE_BINARY)

    def resize(self, cols: int, rows: int) -> None:
        self._send_json({"type": "resize", "cols": cols, "rows": rows})

    def signal(self, name: str) -> None:
        self._send_json({"type": "signal", "signal": name})

    def close(self) -> None:
        try:
            self._send_json({"type": "close"})
        finally:
            self._ws.close()

    def wait(self, timeout: Optional[float] = None) -> ExecExitInfo:
        try:
            return self._done.result(timeout)
        except FutureTimeoutError as exc:
            raise TimeoutError("timed out waiting for session completion") from exc

    def _send_json(self, payload: Dict[str, Any]) -> None:
        with self._send_lock:
            self._ws.send(json.dumps(payload))

    def _read_loop(self) -> None:
        try:
            while True:
                message = self._ws.recv()
                if isinstance(message, str):
                    self._handle_text_frame(message)
                    if self._done.done():
                        break
                    continue

                payload = bytes(message)
                if len(payload) == 0:
                    continue

                stream = payload[0]
                chunk = payload[1:]
                if stream == STREAM_PREFIX_STDOUT:
                    callback = self._options.get("onStdout")
                    if callback is not None:
                        callback(chunk)
                elif stream == STREAM_PREFIX_STDERR:
                    callback = self._options.get("onStderr")
                    if callback is not None:
                        callback(chunk)
        except Exception as exc:
            if not self._done.done():
                self._done.set_exception(MicroVMError(f"session stream closed: {exc}"))
        finally:
            try:
                self._ws.close()
            except Exception:
                # The peer may already have closed the socket.
                pass

    def _handle_text_frame(self, payload: str) -> None:
        try:
            message = json.loads(payload)
        except json.JSONDecodeError:
            return

        if message.get("type") == "exit":
            result: ExecExitInfo = {"code": int(message.get("code", 0))}
            signal = message.get("signal")
            if isinstance(signal, str) and signal != "":
                result["signal"] = signal
            callback = self._options.get("onExit")
            if callback is not None:
                callback(result)
            if not self._done.done():
                self._done.set_result(result)
            return

        if message.get("type") == "error":
            error_message = str(message.get("message") or "session error")
            callback = self._options.get("onError")
            if callback is not None:
                callback(error_message)
            if not self._done.done():
                self._done.set_exception(MicroVMError(error_message))


class FileWatchHandle:
    """A running file watch (:meth:`MicroVM.watch_files`).

    Events reach the callback on a background thread, in order, about every
    250 ms. ``stop()`` ends the watch; ``wait()`` then returns. ``wait()``
    raises :class:`MicroVMError` when the watch ends any other way: the
    sandbox ended it (the watched folder was removed or moved; the message
    says which), the connection dropped, or the callback raised.
    """

    def __init__(self, ws: Any, on_event: FileEventCallback) -> None:
        self._ws = ws
        self._on_event = on_event
        self._done: Future[None] = Future()
        self._stopped = threading.Event()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    @property
    def done(self) -> Future[None]:
        return self._done

    def stop(self) -> None:
        """Ends the watch. Safe to call more than once."""
        self._stopped.set()
        self._finish(None)
        try:
            self._ws.close()
        except Exception:
            # The peer may already have closed the socket.
            pass

    def wait(self, timeout: Optional[float] = None) -> None:
        try:
            self._done.result(timeout)
        except FutureTimeoutError as exc:
            raise TimeoutError("timed out waiting for the file watch to end") from exc

    def _finish(self, error: Optional[BaseException]) -> None:
        # The reader and stop() race to finish; the first one wins.
        try:
            if error is None:
                self._done.set_result(None)
            else:
                self._done.set_exception(error)
        except InvalidStateError:
            pass

    def _read_loop(self) -> None:
        try:
            while True:
                message = self._ws.recv()
                if not isinstance(message, str):
                    # toolboxd sends text frames only.
                    continue
                try:
                    frame = json.loads(message)
                except json.JSONDecodeError:
                    continue
                if not isinstance(frame, dict):
                    continue
                kind = frame.get("type")
                if kind == "events":
                    events = frame.get("events")
                    for item in events if isinstance(events, list) else []:
                        if isinstance(item, dict):
                            self._on_event(_from_api_file_event(item))
                elif kind == "end":
                    reason = str(frame.get("reason") or "the sandbox ended the file watch")
                    self._finish(MicroVMError(reason))
                    break
                # Unknown frame types are ignored: a newer toolboxd may add some.
        except Exception as exc:
            if self._stopped.is_set():
                self._finish(None)
            else:
                self._finish(MicroVMError(f"file watch stream closed: {exc}"))
        finally:
            try:
                self._ws.close()
            except Exception:
                # The peer may already have closed the socket.
                pass


class Sandbox:
    def __init__(self, client: "MicroVM", data: SandboxData) -> None:
        self._client = client
        self._data = data

    def to_dict(self) -> SandboxData:
        return dict(self._data)

    def refresh(self) -> "Sandbox":
        updated = self._client.get(self.id)
        self._data = updated.to_dict()
        return self

    def exec(self, request: Union[str, ExecRequest]) -> ExecResult:
        # A plain string is a shell command, matching exec(string) in the
        # TypeScript and Java SDKs, so the one-line hello world reads the same
        # in every language.
        if isinstance(request, str):
            return self.exec_command(request)
        return self._client.exec(self.id, request)

    def exec_command(self, command: str) -> ExecResult:
        return self._client.exec(self.id, {"command": command})

    def clone_generation(self) -> CloneGeneration:
        """Read this sandbox's clone-generation token (changes on resume-from-snapshot).

        Read-only: does not reseed in-guest PRNGs. See the "Randomness in
        cloned sandboxes" docs page for the in-guest reseed pattern.
        """
        return self._client.clone_generation(self.id)

    def exec_stream(self, options: ExecStreamOptions) -> ExecStreamHandle:
        return self._client.exec_stream(self.id, options)

    def create_session(self, options: CreateSessionOptions) -> Session:
        return self._client.create_session(self.id, options)

    def list_sessions(self) -> List[Session]:
        return self._client.list_sessions(self.id)

    def get_session(self, session_id: str) -> Session:
        return self._client.get_session(self.id, session_id)

    def delete_session(self, session_id: str) -> None:
        self._client.delete_session(self.id, session_id)

    def signal_session(self, session_id: str, signal: str) -> None:
        self._client.signal_session(self.id, session_id, signal)

    def resize_session(self, session_id: str, cols: int, rows: int) -> None:
        self._client.resize_session(self.id, session_id, cols, rows)

    def session_log(self, session_id: str) -> bytes:
        return self._client.session_log(self.id, session_id)

    def session_recording(self, session_id: str) -> bytes:
        return self._client.session_recording(self.id, session_id)

    def attach_session(self, session_id: str, options: Optional[SessionAttachOptions] = None) -> SessionAttachHandle:
        return self._client.attach_session(self.id, session_id, options)

    def upload_file(self, target_path: str, data: bytes) -> None:
        self._client.upload_file(self.id, target_path, data)

    def download_file(self, target_path: str) -> bytes:
        return self._client.download_file(self.id, target_path)

    def watch_files(self, path: str, on_event: FileEventCallback, recursive: bool = False) -> FileWatchHandle:
        return self._client.watch_files(self.id, path, on_event, recursive=recursive)

    def list_files(self, path: str, *, depth: int = 1, limit: int = DEFAULT_LIST_LIMIT) -> FileList:
        return self._client.list_files(self.id, path, depth=depth, limit=limit)

    def get_file_info(self, path: str) -> FileInfo:
        return self._client.get_file_info(self.id, path)

    def file_exists(self, path: str) -> bool:
        return self._client.file_exists(self.id, path)

    def delete_file(self, path: str, *, recursive: bool = False) -> None:
        self._client.delete_file(self.id, path, recursive=recursive)

    def make_dir(self, path: str, *, parents: bool = False, mode: Optional[int] = None) -> None:
        self._client.make_dir(self.id, path, parents=parents, mode=mode)

    def move_file(self, source: str, destination: str, *, overwrite: bool = False) -> None:
        self._client.move_file(self.id, source, destination, overwrite=overwrite)

    def copy_file(self, source: str, destination: str, *, overwrite: bool = False, recursive: bool = False) -> None:
        self._client.copy_file(self.id, source, destination, overwrite=overwrite, recursive=recursive)

    def search_files(self, path: str, pattern: str) -> List[str]:
        return self._client.search_files(self.id, path, pattern)

    def find_in_files(self, path: str, text: str) -> List[FileMatch]:
        return self._client.find_in_files(self.id, path, text)

    def expose_port(self, port: int, *, protocol: ExposeProtocol = "http") -> ExposeResult:
        return self._client.expose_port(self.id, port, protocol=protocol)

    def unexpose_port(self, port: int) -> None:
        self._client.unexpose_port(self.id, port)

    def add_custom_domain(
        self,
        hostname: str,
        *,
        port: Optional[int] = None,
    ) -> List[CustomDomain]:
        return self._client.add_custom_domain(self.id, hostname, port=port)

    def list_custom_domains(self) -> List[CustomDomain]:
        return self._client.list_custom_domains(self.id)

    def remove_custom_domain(self, hostname: str) -> None:
        self._client.remove_custom_domain(self.id, hostname)

    def custom_domain_dns(self) -> CustomDomainDNSRecords:
        return self._client.custom_domain_dns(self.id)

    def start(self) -> "Sandbox":
        updated = self._client.start(self.id)
        self._data = updated.to_dict()
        return self

    def stop(self) -> "Sandbox":
        updated = self._client.stop(self.id)
        self._data = updated.to_dict()
        return self

    def create_snapshot(self, name: str, *, allow_pause: Optional[bool] = None) -> SandboxSnapshot:
        """Save this sandbox's files as a snapshot named ``name``.

        A running sandbox is paused briefly while it is copied (its disk
        writes wait) and keeps running. Pass ``allow_pause=False`` to have a
        sandbox that is not stopped refused (HTTP 409) instead.
        """
        return self._client.create_snapshot(self.id, name, allow_pause=allow_pause)

    def destroy(self) -> None:
        self._client.destroy(self.id)

    def resize(self, options: ResizeOptions) -> "Sandbox":
        updated = self._client.resize(self.id, options)
        self._data = updated.to_dict()
        return self

    def update_lifecycle(self, lifecycle: Lifecycle) -> "Sandbox":
        updated = self._client.update_lifecycle(self.id, lifecycle)
        self._data = updated.to_dict()
        return self

    def get_network_usage(self) -> NetworkUsage:
        return self._client.get_network_usage(self.id)

    def set_network_limits(self, options: SetNetworkLimitsOptions) -> NetworkUsage:
        return self._client.set_network_limits(self.id, options)

    def set_network_policy(self, options: NetworkPolicyOptions) -> NetworkPolicy:
        """Replace this sandbox's egress policy while it runs. Returns once
        the new policy is enforced; the same policy again is a no-op, so it
        is safe to retry."""
        policy = self._client.set_network_policy(self.id, options)
        self._data["networkBlockAll"] = policy["networkBlockAll"]
        if policy.get("networkEgressMode") == "learn":
            self._data["networkEgressMode"] = "learn"
        else:
            self._data.pop("networkEgressMode", None)
        if policy.get("networkEgressRules"):
            self._data["networkEgressRules"] = policy["networkEgressRules"]
        else:
            self._data.pop("networkEgressRules", None)
        if "egressStatus" in policy:
            self._data["egressStatus"] = policy["egressStatus"]
        else:
            self._data.pop("egressStatus", None)
        return policy

    def learned(self) -> NetworkLearned:
        """Read what this sandbox reached in learn mode. A recording stays
        readable after a switch to enforce, until the sandbox is destroyed."""
        return self._client.get_network_learned(self.id)

    def audit(self, options: Optional[AuditOptions] = None) -> AuditPage:
        """Read this sandbox's audit log: outbound connections and egress
        denials (``kind="egress"``) and secret reads."""
        return self._client.get_audit(self.id, options)

    @property
    def id(self) -> str:
        return str(self._data.get("id", ""))

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"Sandbox object has no attribute {name}")


class MicroVM:
    default_api_url = "http://127.0.0.1:21212"
    auth_required_error_message = "PAT token is required. Set pat_token, SB_PAT_TOKEN or SB_API_TOKEN."

    def __init__(
        self,
        api_url: Optional[str] = None,
        pat_token: Optional[str] = None,
        *,
        api_version: str = _DEFAULT_API_VERSION,
        config: Optional[MicroVMConfig] = None,
        team: Optional[str] = None,
    ) -> None:
        """``pat_token`` is the bearer every request carries: the operator
        PAT, an avm_ API token or an OIDC ID token. It defaults to
        ``SB_PAT_TOKEN``, then its alias ``SB_API_TOKEN``; when both are set,
        ``SB_PAT_TOKEN`` wins.

        ``team`` (default ``SB_TEAM``) is sent as the ``X-AerolVM-Team``
        header on every request, WebSocket handshakes included. With
        neither, no header is sent and the server uses the credential's
        first matching binding. The header only chooses among teams the
        credential is already bound to: a team it does not hold is refused
        (403), and the operator PAT ignores it.
        """
        if config is not None:
            api_url = api_url or config.get("apiUrl")
            pat_token = pat_token or config.get("patToken")
            team = team or config.get("team")

        self.api_url = _normalize_url(api_url or _read_env("SB_API_URL") or self.default_api_url)
        self.pat_token = pat_token or _read_env("SB_PAT_TOKEN") or _read_env("SB_API_TOKEN") or ""
        self.team = (team or _read_env("SB_TEAM") or "").strip()

        retry_cfg: RetryConfig = config.get("retry", {}) if config else {}
        self._retry_config = {
            "maxRetries": retry_cfg.get("maxRetries", 3),
            "baseDelayMs": retry_cfg.get("baseDelayMs", 200),
            "maxDelayMs": retry_cfg.get("maxDelayMs", 5000),
            "maxRetryAfterMs": retry_cfg.get("maxRetryAfterMs", _DEFAULT_MAX_RETRY_AFTER_MS),
        }

        if not self.pat_token:
            raise MicroVMError(self.auth_required_error_message)

        if api_version not in _PATH_PREFIXES:
            raise MicroVMError(f"unsupported api_version {api_version!r}; supported: {sorted(_PATH_PREFIXES)}")
        self.api_version = api_version
        self._version_prefix = _PATH_PREFIXES[api_version]
        # Features each sandbox's agent listed on /version (see
        # _require_toolbox_features). Refreshed on a miss, because a restart
        # can bring a newer agent.
        self._toolbox_features: Dict[str, frozenset] = {}

    def _versioned(self, suffix: str) -> str:
        """Build a versioned API path. Pass the suffix beginning with "/" (e.g.
        ``"/sandboxes"``) and the active version's prefix is prepended. Use
        this for every versioned call so a future wire version is selected by
        the ``api_version`` option without touching call sites.
        """
        return f"{self._version_prefix}{suffix}"

    def create(self, options: Optional[CreateOptions] = None, **fields: Any) -> Sandbox:
        # Keyword arguments are the same fields as the options dict, in either
        # spelling (memory_mb or memoryMB), so create(image="python:3.12")
        # and create({"image": "python:3.12"}) send the same request. A
        # keyword replaces the same key in the dict.
        resolved_options: Dict[str, Any] = {**(options or {}), **fields}
        resolved_options["image"] = self._resolve_image(_first_of(resolved_options, "image"))
        # One key per call, sent unchanged on each of its automatic retries: a
        # create retried after a timeout gets back the sandbox the first
        # attempt made instead of making a second one.
        key = str(_first_of(resolved_options, "idempotency_key", "idempotencyKey") or "").strip() or _new_idempotency_key()
        sandbox = self._do_json(
            "POST",
            self._versioned("/sandboxes"),
            _to_api_create_options(resolved_options),
            headers={IDEMPOTENCY_KEY_HEADER: key},
        )
        return self._wrap_sandbox(sandbox)

    def build_image(self, image: Image) -> str:
        result = self.build_image_with_push(image, push=None)
        return result.image

    def build_image_with_push(
        self,
        image: Image,
        *,
        push: Optional[BuildImagePushOptions] = None,
    ) -> BuildImageResult:
        """Build an Image and optionally push the result to a remote registry.

        When ``push`` is ``None``, behavior matches :meth:`build_image`.
        Push credentials are forwarded to the daemon as a one-shot
        ``X-Registry-Auth`` header on the underlying push call and are never
        persisted server-side.
        """
        if not isinstance(image, Image):
            raise TypeError("build_image expects an Image instance")
        body: Dict[str, Any] = {"dockerfile_content": image.dockerfile}
        if push is not None:
            registry = str(push.get("registry", "")).strip()
            username = str(push.get("username", ""))
            password = str(push.get("password", ""))
            if not registry:
                raise ValueError("push.registry is required when push is set")
            if not username or not password:
                raise ValueError("push.username and push.password are required when push is set")
            push_body: Dict[str, Any] = {
                "registry": registry,
                "username": username,
                "password": password,
            }
            tag = str(push.get("tag", "")).strip()
            if tag:
                push_body["tag"] = tag
            server = str(push.get("server", "")).strip()
            if server:
                push_body["server"] = server
            body["push"] = push_body

        path = self._versioned("/images/build")
        try:
            payload = self._do_json("POST", path, body)
        except MicroVMHTTPError as exc:
            if exc.status_code == 404:
                raise MicroVMError(
                    f'this daemon does not support Image builds (POST {path} is not registered) — pass a string image reference (e.g. "ubuntu:22.04") instead, or upgrade the daemon'
                ) from exc
            raise
        image_tag = str(_first_of(payload, "image") or "")
        pushed_value = _first_of(payload, "pushed")
        pushed: Optional[str] = str(pushed_value) if pushed_value else None
        return BuildImageResult(image=image_tag, pushed=pushed)

    def list(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        include_env: bool = False,
        name: Optional[str] = None,
    ) -> List[Sandbox]:
        """List sandboxes. ``name`` filters to the caller's sandbox with exactly
        that name (``?name=``). Servers that predate name lookup ignore the
        filter and return a normal list; prefer :meth:`get_by_name`, which
        checks the reply."""
        items: List[Sandbox] = []
        for page in self.iter_pages(tags=tags, include_env=include_env, name=name):
            items.extend(page)
        return items

    def iter_pages(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        include_env: bool = False,
        name: Optional[str] = None,
    ) -> Iterator[List[Sandbox]]:
        """Yield one server page at a time for bounded-memory fleet scans."""
        base_path = self._versioned("/sandboxes") + _build_sandbox_query(tags, include_env, name)
        page_token = ""
        for _ in range(100000):
            path = _append_query_param(base_path, "page_token", page_token)
            sandboxes, headers = self._do_json_headers("GET", path, None)
            partial = headers.get("X-Cluster-List-Partial", "")
            ready = headers.get("X-Cluster-List-Placement-Ready", "")
            if partial == "true" or ready == "false":
                raise MicroVMError("incomplete cluster list")
            yield [self._wrap_sandbox(item) for item in sandboxes or []]
            page_token = (headers.get("X-Cluster-List-Next-Page-Token") or "").strip()
            if page_token == "":
                return
        raise MicroVMError("incomplete cluster list: exceeded max pages")

    def get_by_name(self, name: str, *, include_env: bool = False) -> Optional[Sandbox]:
        """Return the caller's sandbox with this name, or ``None`` if there is
        none. Names are unique per owner. The reply is only trusted when it holds
        at most one sandbox carrying the requested name: a server that predates
        ``?name=`` ignores the filter and returns an ordinary list page, and
        acting on its first row would target the wrong sandbox."""
        wanted = (name or "").strip()
        if not wanted:
            raise ValueError("sandbox name is required")
        path = self._versioned("/sandboxes") + _build_sandbox_query(None, include_env, wanted)
        sandboxes = self._do_json("GET", path, None) or []
        if not sandboxes:
            return None
        if len(sandboxes) > 1 or str(_first_of(sandboxes[0], "name") or "") != wanted:
            raise MicroVMError(
                f"{self.api_url} does not support sandbox name lookup; use the sandbox ID or upgrade the server"
            )
        return self._wrap_sandbox(sandboxes[0])

    def get(self, sandbox_id: str, *, include_env: bool = False) -> Sandbox:
        path = f"{self._version_prefix}/sandboxes/{sandbox_id}" + _build_sandbox_query(None, include_env)
        sandbox = self._do_json("GET", path, None)
        return self._wrap_sandbox(sandbox)

    def start(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/start", None)
        return self._wrap_sandbox(sandbox)

    def stop(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/stop", None)
        return self._wrap_sandbox(sandbox)

    def create_snapshot(
        self, sandbox_id: str, name: str, *, allow_pause: Optional[bool] = None
    ) -> SandboxSnapshot:
        """Save a sandbox's files as a snapshot named ``name``.

        A running sandbox is paused briefly while it is copied (its disk
        writes wait) and keeps running. Pass ``allow_pause=False`` to have a
        sandbox that is not stopped refused (HTTP 409) instead.
        """
        body: Dict[str, Any] = {"name": name}
        if allow_pause is not None:
            body["allow_pause"] = allow_pause
        response = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/snapshot", body)
        return _from_api_sandbox_snapshot(response)

    def register_snapshot(self, options: RegisterSnapshotOptions) -> SandboxSnapshot:
        name = str(_first_of(options, "name") or "").strip()
        if name == "":
            raise MicroVMError("name is required")

        image = str(_first_of(options, "image") or "").strip()
        dockerfile_content = str(_first_of(options, "dockerfileContent", "dockerfile_content") or "").strip()
        if image == "" and dockerfile_content == "":
            raise MicroVMError("image or dockerfile_content is required")
        if image != "" and dockerfile_content != "":
            raise MicroVMError("image and dockerfile_content are mutually exclusive")

        response = self._do_json(
            "POST",
            self._versioned("/snapshots"),
            _to_api_register_snapshot_options(
                {
                    **options,
                    "name": name,
                    "image": image or None,
                    "dockerfileContent": dockerfile_content or None,
                    "regionID": str(_first_of(options, "regionID", "region_id") or "").strip() or None,
                }
            ),
        )
        return _from_api_sandbox_snapshot(response)

    def register_snapshot_from_image(
        self,
        name: str,
        image: Image,
        options: Optional[RegisterSnapshotOptions] = None,
    ) -> SandboxSnapshot:
        if not isinstance(image, Image):
            raise TypeError("register_snapshot_from_image expects an Image instance")
        resolved_options: RegisterSnapshotOptions = dict(options or {})
        resolved_options["name"] = name
        resolved_options.pop("image", None)
        resolved_options["dockerfileContent"] = image.dockerfile
        return self.register_snapshot(resolved_options)

    def get_snapshot(self, name: str) -> SandboxSnapshot:
        """Look a snapshot up by name. In a cluster the request is routed to
        the node holding the image."""
        return _from_api_sandbox_snapshot(self._do_json("GET", self._snapshot_path(name), None) or {})

    def list_snapshots(
        self,
        limit: Optional[int] = None,
        starting_after: Optional[str] = None,
    ) -> SnapshotList:
        """List the caller's snapshots, one name-ordered page at a time.
        ``starting_after`` is the exclusive name cursor — pass the last name of
        the previous page to fetch the next one."""
        params: Dict[str, str] = {}
        if limit:
            params["limit"] = str(int(limit))
        if starting_after:
            params["starting_after"] = str(starting_after)
        path = self._versioned("/snapshots")
        if params:
            path += "?" + urllib.parse.urlencode(params)
        payload = self._do_json("GET", path, None) or {}
        return {
            "snapshots": [_from_api_sandbox_snapshot(s) for s in payload.get("snapshots") or []],
            "hasMore": bool(payload.get("has_more")),
        }

    def delete_snapshot(self, name: str) -> None:
        """Delete a snapshot by name (idempotent 404 if it does not exist)."""
        self._do_json("DELETE", self._snapshot_path(name), None)

    def _snapshot_path(self, name: str) -> str:
        return f"{self._version_prefix}/snapshots/{urllib.parse.quote(name, safe='')}"

    def destroy(self, sandbox_id: str) -> None:
        self._do_json("DELETE", f"{self._version_prefix}/sandboxes/{sandbox_id}", None)

    def create_template(self, options: CreateTemplateOptions) -> Template:
        """Register a Firecracker rootfs template.

        Returns a row in ``status: "pending"`` and kicks the daemon's
        async build. Poll :meth:`get_template` until ``status`` reaches
        ``"ready"`` (fast-boot available) or ``"ready_no_snapshot"``
        (cold boot only).

        Idempotent when ``options["id"]`` is set: a duplicate ID
        returns 409 so a retried CI step does not create two rows.
        """
        body: Dict[str, Any] = {}
        tpl_id = str(_first_of(options, "id") or "").strip()
        if tpl_id:
            body["id"] = tpl_id
        image = str(_first_of(options, "image") or "").strip()
        if not image:
            raise MicroVMError("image is required")
        body["image"] = image
        min_size = _first_of(options, "minSizeMiB", "min_size_mib")
        if min_size is not None:
            body["min_size_mib"] = int(min_size)
        response = self._do_json("POST", self._versioned("/templates"), body)
        return _from_api_template(response)

    def list_templates(self) -> List[Template]:
        response = self._do_json("GET", self._versioned("/templates"), None)
        if response is None:
            return []
        if not isinstance(response, list):
            raise MicroVMError("expected JSON array from /v1/templates")
        return [_from_api_template(item) for item in response]

    def get_template(self, template_id: str) -> Template:
        response = self._do_json("GET", f"{self._version_prefix}/templates/{template_id}", None)
        return _from_api_template(response)

    def delete_template(self, template_id: str) -> None:
        self._do_json("DELETE", f"{self._version_prefix}/templates/{template_id}", None)

    def create_wasm_module(self, options: CreateWasmModuleOptions) -> WasmModule:
        """Register a WASM module in the host catalogue.

        Resolution is synchronous — the returned row is typically already
        ``ready``. Idempotent when ``options["id"]`` is set and matches the
        same ``moduleRef``.
        """
        body: Dict[str, Any] = {}
        mod_id = str(_first_of(options, "id") or "").strip()
        if mod_id:
            body["id"] = mod_id
        module_ref = str(_first_of(options, "moduleRef", "module_ref") or "").strip()
        if not module_ref:
            raise MicroVMError("moduleRef is required")
        body["module_ref"] = module_ref
        entrypoint = _first_of(options, "entrypoint")
        if entrypoint not in (None, ""):
            body["entrypoint"] = str(entrypoint)
        response = self._do_json("POST", self._versioned("/wasm-modules"), body)
        return _from_api_wasm_module(response)

    def list_wasm_modules(self) -> List[WasmModule]:
        response = self._do_json("GET", self._versioned("/wasm-modules"), None)
        if response is None:
            return []
        if not isinstance(response, list):
            raise MicroVMError("expected JSON array from /v1/wasm-modules")
        return [_from_api_wasm_module(item) for item in response]

    def get_wasm_module(self, module_id: str) -> WasmModule:
        response = self._do_json("GET", f"{self._version_prefix}/wasm-modules/{module_id}", None)
        return _from_api_wasm_module(response)

    def delete_wasm_module(self, module_id: str) -> None:
        self._do_json("DELETE", f"{self._version_prefix}/wasm-modules/{module_id}", None)

    def push_wasm_module(self, options: PushWasmModuleOptions) -> PushWasmModuleResult:
        """Upload a compiled core-wasip1 module to the registry under your own
        credentials, returning the ``oci://`` ref to use as ``moduleRef`` on a
        later ``create``. The daemon validates and forwards the bytes; it never
        stores them.
        """
        name = options.get("name", "")
        query = urllib.parse.urlencode(
            {"name": name, "tag": options["tag"]} if options.get("tag") else {"name": name}
        )
        headers: Dict[str, str] = {"X-Registry-Token": options.get("registryToken", "")}
        username = options.get("registryUsername")
        if username:
            headers["X-Registry-Username"] = username
        url = f"{self._url(self._versioned('/wasm-modules/push'))}?{query}"
        raw = self._request(
            "POST",
            url,
            body=options.get("module", b""),
            content_type="application/octet-stream",
            extra_headers=headers,
        )
        data = json.loads(raw.decode("utf-8")) if raw else {}
        return PushWasmModuleResult(
            moduleRef=data.get("module_ref", ""),
            digest=data.get("digest", ""),
            sizeBytes=data.get("size_bytes", 0),
        )

    def rebuild_template(self, template_id: str) -> Template:
        """Re-run the snapshot phase against an existing template.

        Idempotent under concurrent retry — the daemon's CAS collapses
        N parallel calls for the same ``ready`` template to one rebuild
        kick. Returns the row in its post-transition state (typically
        ``unhealthy``); poll :meth:`get_template` for the transition
        back to ``ready``.

        Raises :class:`MicroVMHTTPError` with status 412 when the
        template is in a state where rebuild is not safe (build in
        flight) or not supported (``ready_no_snapshot``/``failed`` —
        those need delete+recreate today).
        """
        response = self._do_json("POST", f"{self._version_prefix}/templates/{template_id}/rebuild", None)
        return _from_api_template(response)

    def resize(self, sandbox_id: str, options: ResizeOptions) -> Sandbox:
        sandbox = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/resize", _to_api_resize_options(options))
        return self._wrap_sandbox(sandbox)

    def update_lifecycle(self, sandbox_id: str, lifecycle: Lifecycle) -> Sandbox:
        sandbox = self._do_json("PUT", f"{self._version_prefix}/sandboxes/{sandbox_id}/lifecycle", _to_api_lifecycle(lifecycle))
        return self._wrap_sandbox(sandbox)

    def reconcile(self) -> None:
        self._do_json("POST", self._versioned("/admin/reconcile"), None)

    def health(self) -> HealthStatus:
        return _from_api_health_status(self._do_json("GET", "/health", None))

    def mounts(self, sandbox_id: str) -> List[MountSpecRedacted]:
        payload = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/mounts", None)
        mounts = _first_of(payload, "mounts") or []
        if not isinstance(mounts, list):
            return []
        return [_from_api_mount_spec_redacted(item) for item in mounts]

    def clone_generation(self, sandbox_id: str) -> CloneGeneration:
        payload = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/toolbox/clone-generation", None)
        return CloneGeneration(
            generation=str(_first_of(payload, "generation") or ""),
            resumedAt=int(_first_of(payload, "resumed_at", "resumedAt") or 0),
        )

    def get_network_usage(self, sandbox_id: str) -> NetworkUsage:
        payload = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/network/usage", None)
        return _from_api_network_usage(payload)

    def check_network_policy(self, options: NetworkPolicyCheckOptions) -> NetworkPolicyCheckResult:
        """Ask whether a sandbox created with these egress fields would reach
        a destination, with the same matcher the filter enforces. No sandbox
        is needed."""
        body = {
            "network_block_all": bool(options.get("networkBlockAll", False)),
            "network_allow_out": list(options.get("networkAllowOut") or []),
            "network_deny_out": list(options.get("networkDenyOut") or []),
            "destination": options.get("destination", ""),
        }
        payload = self._do_json("POST", f"{self._version_prefix}/network/policy/check", body) or {}
        result: NetworkPolicyCheckResult = {
            "allowed": bool(payload.get("allowed", False)),
            "matchedRule": str(payload.get("matched_rule") or ""),
            "defaultVerdict": str(payload.get("default_verdict") or ""),
        }
        if payload.get("outside_ceiling"):
            result["outsideCeiling"] = str(payload["outside_ceiling"])
        return result

    def get_audit(self, sandbox_id: str, options: Optional[AuditOptions] = None) -> AuditPage:
        opts = options or {}
        params: Dict[str, str] = {}
        if opts.get("kind"):
            params["kind"] = opts["kind"]
        if opts.get("limit") is not None:
            params["limit"] = str(opts["limit"])
        if opts.get("cursor"):
            params["cursor"] = opts["cursor"]
        if opts.get("incarnationID"):
            params["incarnation_id"] = opts["incarnationID"]
        path = f"{self._version_prefix}/sandboxes/{sandbox_id}/audit"
        if params:
            path += "?" + urllib.parse.urlencode(params)
        payload = self._do_json("GET", path, None)
        return _from_api_audit_page(payload or {})

    def set_network_limits(self, sandbox_id: str, options: SetNetworkLimitsOptions) -> NetworkUsage:
        body = _to_api_set_network_limits_options(options)
        payload = self._do_json("PATCH", f"{self._version_prefix}/sandboxes/{sandbox_id}/network/limits", body)
        return _from_api_network_usage(payload)

    def set_network_policy(self, sandbox_id: str, options: NetworkPolicyOptions) -> NetworkPolicy:
        body = {
            "network_block_all": bool(_first_of(options, "networkBlockAll", "network_block_all") or False),
            "network_allow_out": list(_first_of(options, "networkAllowOut", "network_allow_out") or []),
            "network_deny_out": list(_first_of(options, "networkDenyOut", "network_deny_out") or []),
            "egress_profiles": list(_first_of(options, "egressProfiles", "egress_profiles") or []),
        }
        mode = _first_of(options, "networkEgressMode", "network_egress_mode")
        if mode:
            body["network_egress_mode"] = str(mode)
        rules = _first_of(options, "networkEgressRules", "network_egress_rules")
        if rules is not None:
            body["network_egress_rules"] = _egress_rules(rules, wire=True)
        payload = self._do_json("PUT", f"{self._version_prefix}/sandboxes/{sandbox_id}/network/policy", body) or {}
        policy: NetworkPolicy = {
            "networkBlockAll": bool(payload.get("network_block_all", False)),
            "networkAllowOut": list(payload.get("network_allow_out") or []),
            "networkDenyOut": list(payload.get("network_deny_out") or []),
            "egressProfiles": list(payload.get("egress_profiles") or []),
            "networkEgressMode": str(payload.get("network_egress_mode") or "enforce"),
            "networkEgressRules": _egress_rules(payload.get("network_egress_rules")),
            "effectiveHostnameCount": int(payload.get("effective_hostname_count") or 0),
        }
        if payload.get("egress_status"):
            policy["egressStatus"] = str(payload["egress_status"])
        return policy

    def get_network_learned(self, sandbox_id: str) -> NetworkLearned:
        """Read what a sandbox reached in learn mode and the allow list that
        would have allowed it."""
        payload = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/network/learned", None) or {}
        result: NetworkLearned = {
            "mode": str(payload.get("mode") or "enforce"),
            "truncated": bool(payload.get("truncated", False)),
            "entries": [
                {
                    "host": str(e.get("host") or ""),
                    "ports": [int(p) for p in e.get("ports") or []],
                    "firstSeen": str(e.get("first_seen") or ""),
                    "lastSeen": str(e.get("last_seen") or ""),
                    "hits": int(e.get("hits") or 0),
                }
                for e in payload.get("entries") or []
            ],
            "cidrs": list(payload.get("cidrs") or []),
            "suggestedAllowOut": list(payload.get("suggested_allow_out") or []),
        }
        profile = payload.get("suggested_profile")
        if profile:
            result["suggestedProfile"] = {"allowOut": list(profile.get("allow_out") or []), "description": str(profile.get("description") or "")}
        return result

    def put_egress_profile(self, name: str, options: EgressProfileOptions) -> EgressProfile:
        """Create or replace a named egress profile (a full replace: the same
        body twice is a no-op). A change reaches every sandbox using it."""
        body: Dict[str, Any] = {"allow_out": list(_first_of(options, "allowOut", "allow_out") or [])}
        description = _first_of(options, "description")
        if description:
            body["description"] = str(description)
        payload = self._do_json("PUT", self._egress_profile_path(name), body) or {}
        return _from_api_egress_profile(payload)

    def get_egress_profile(self, name: str) -> EgressProfile:
        return _from_api_egress_profile(self._do_json("GET", self._egress_profile_path(name), None) or {})

    def list_egress_profiles(self, options: Optional[ListEgressProfilesOptions] = None) -> EgressProfileList:
        opts = options or {}
        params: Dict[str, str] = {}
        if opts.get("cursor"):
            params["cursor"] = str(opts["cursor"])
        if opts.get("limit"):
            params["limit"] = str(int(opts["limit"]))
        path = f"{self._version_prefix}/egress-profiles"
        if params:
            path += "?" + urllib.parse.urlencode(params)
        payload = self._do_json("GET", path, None) or {}
        result: EgressProfileList = {"profiles": [_from_api_egress_profile(p) for p in payload.get("profiles") or []]}
        if payload.get("next_cursor"):
            result["nextCursor"] = str(payload["next_cursor"])
        return result

    def delete_egress_profile(self, name: str) -> None:
        """Delete a profile; one that sandboxes still reference is refused (409)."""
        self._do_json("DELETE", self._egress_profile_path(name), None)

    def _egress_profile_path(self, name: str) -> str:
        return f"{self._version_prefix}/egress-profiles/{urllib.parse.quote(name, safe='')}"

    def whoami(self) -> WhoAmI:
        """Who the server says the caller is: principal, role, team and when
        the credential expires. Every valid credential may ask."""
        return _from_api_whoami(self._do_json("GET", self._versioned("/whoami"), None) or {})

    @property
    def tokens(self) -> "Tokens":
        """Scoped API tokens (avm_…) for services and CI:
        ``client.tokens.create/list/revoke``."""
        return Tokens(self)

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        # Not idempotent: a re-sent POST runs the user's command again, so a
        # timeout or reset after the request went out surfaces instead of
        # retrying. Sandbox.exec and exec_command both end here.
        payload = _to_api_exec_request(request)
        # An older agent ignores the caps and returns all output, and refuses
        # argv with a confusing "command is required"; check first.
        features = []
        if payload.get("max_stdout_bytes") or payload.get("max_stderr_bytes"):
            features.append("exec.max_output_bytes")
        if payload.get("argv"):
            features.append("exec.argv")
        self._require_toolbox_features(sandbox_id, *features)
        response = self._do_json(
            "POST",
            f"{self._version_prefix}/sandboxes/{sandbox_id}/toolbox/process/execute",
            payload,
            idempotent=False,
        )
        return _from_api_exec_result(response)

    def exec_stream(self, sandbox_id: str, options: ExecStreamOptions) -> ExecStreamHandle:
        command = _first_of(options, "command")
        has_command = isinstance(command, str) and command.strip() != ""
        argv = _first_of(options, "argv")
        if has_command and argv:
            raise MicroVMError("set command or argv, not both")
        if not has_command and not argv:
            raise MicroVMError("command is required")
        if argv:
            # Before the socket opens, so an older agent never gets a start
            # message it cannot run.
            self._require_toolbox_features(sandbox_id, "exec.argv")

        websocket_module = _load_websocket_module()
        ws_url = _to_websocket_url(self.api_url, f"{self._version_prefix}/sandboxes/{urllib.parse.quote(sandbox_id, safe='')}/toolbox/process/exec/stream")
        ws = _connect_websocket(websocket_module, ws_url, self._websocket_headers(), "exec stream")
        ws.send(json.dumps(_to_api_exec_stream_request(options)))
        return ExecStreamHandle(websocket_module, ws, options)

    def create_session(self, sandbox_id: str, options: CreateSessionOptions) -> Session:
        session = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions", _to_api_create_session_options(options))
        return _from_api_session(session)

    def list_sessions(self, sandbox_id: str) -> List[Session]:
        payload = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions", None)
        sessions = _first_of(payload, "sessions") or []
        if not isinstance(sessions, list):
            return []
        return [_from_api_session(item) for item in sessions]

    def get_session(self, sandbox_id: str, session_id: str) -> Session:
        session = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions/{session_id}", None)
        return _from_api_session(session)

    def delete_session(self, sandbox_id: str, session_id: str) -> None:
        self._do_json("DELETE", f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions/{session_id}", None)

    def signal_session(self, sandbox_id: str, session_id: str, signal: str) -> None:
        self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions/{session_id}/signal", {"signal": signal})

    def resize_session(self, sandbox_id: str, session_id: str, cols: int, rows: int) -> None:
        self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions/{session_id}/resize", {"cols": cols, "rows": rows})

    def session_log(self, sandbox_id: str, session_id: str) -> bytes:
        return self._request("GET", self._url(f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions/{session_id}/log"))

    def session_recording(self, sandbox_id: str, session_id: str) -> bytes:
        return self._request("GET", self._url(f"{self._version_prefix}/sandboxes/{sandbox_id}/sessions/{session_id}/recording"))

    def attach_session(
        self,
        sandbox_id: str,
        session_id: str,
        options: Optional[SessionAttachOptions] = None,
    ) -> SessionAttachHandle:
        attach_options: SessionAttachOptions = options or {}
        websocket_module = _load_websocket_module()
        ws_url = _to_websocket_url(
            self.api_url,
            f"{self._version_prefix}/sandboxes/{urllib.parse.quote(sandbox_id, safe='')}/sessions/{urllib.parse.quote(session_id, safe='')}/attach",
        )
        ws = _connect_websocket(websocket_module, ws_url, self._websocket_headers(), "session attach")

        cols = _first_of(attach_options, "cols")
        rows = _first_of(attach_options, "rows")
        if isinstance(cols, int) and isinstance(rows, int) and cols > 0 and rows > 0:
            ws.send(json.dumps({"type": "resize", "cols": cols, "rows": rows}))

        return SessionAttachHandle(websocket_module, ws, attach_options)

    def _require_toolbox_features(self, sandbox_id: str, *features: str) -> None:
        """Fail closed unless the sandbox's agent lists every feature.

        toolboxd ignores request options it does not know, so sending a newer
        option to an older agent would silently skip it. The agent lists the
        options it understands on /version.
        """
        if not features:
            return
        have = self._toolbox_features.get(sandbox_id)
        version = ""
        if have is None or not set(features) <= have:
            info = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}/toolbox/version", None)
            listed = info.get("features") if isinstance(info, dict) else None
            have = frozenset(str(f) for f in listed) if isinstance(listed, list) else frozenset()
            self._toolbox_features[sandbox_id] = have
            version = str(info.get("version") or "") if isinstance(info, dict) else ""
        missing = [f for f in features if f not in have]
        if missing:
            raise MicroVMUnsupportedFeatureError(sandbox_id, missing, version)

    def upload_file(self, sandbox_id: str, target_path: str, data: bytes) -> None:
        self._do_multipart(
            f"{self._version_prefix}/sandboxes/{sandbox_id}/toolbox/files/upload",
            {"path": target_path},
            "file",
            target_path,
            data,
        )

    def download_file(self, sandbox_id: str, target_path: str) -> bytes:
        url = self._url(f"{self._version_prefix}/sandboxes/{sandbox_id}/toolbox/files/download?path={urllib.parse.quote(target_path, safe='')}")
        return self._request("GET", url)

    def watch_files(
        self,
        sandbox_id: str,
        path: str,
        on_event: FileEventCallback,
        recursive: bool = False,
    ) -> FileWatchHandle:
        """Watch a folder in the sandbox for changes.

        Calls ``on_event`` with a :class:`FileEvent` for every create, write,
        remove, rename and chmod under ``path`` (and in every subfolder, new
        ones included, when ``recursive``). Returns once the watch is in
        place, so a change made after this returns is always seen.

        File watching works on gVisor and Firecracker sandboxes only; others
        answer :class:`MicroVMHTTPError` with status 501. A sandbox whose
        agent predates file watching raises
        :class:`MicroVMUnsupportedFeatureError`. The connection is opened
        once and never retried.
        """
        if not isinstance(path, str) or path.strip() == "":
            raise MicroVMError("path is required")
        if on_event is None:
            raise MicroVMError("on_event is required")
        query = {"path": path}
        if recursive:
            query["recursive"] = "true"
        websocket_module = _load_websocket_module()
        ws_url = _to_websocket_url(
            self.api_url,
            f"{self._version_prefix}/sandboxes/{urllib.parse.quote(sandbox_id, safe='')}/toolbox/files/watch",
        ) + "?" + urllib.parse.urlencode(query)
        ws = _connect_watch_websocket(websocket_module, ws_url, self._websocket_headers(), sandbox_id)
        # Return only once toolboxd says the watch is armed, so a change the
        # caller makes right after this returns is never missed. The wait is
        # bounded: a proxy that accepts the upgrade and then goes quiet would
        # otherwise hang the caller forever. The bound is lifted afterwards,
        # because a quiet folder sends nothing for as long as it stays quiet.
        settimeout = getattr(ws, "settimeout", None)
        if callable(settimeout):
            settimeout(_WATCH_START_TIMEOUT_SECONDS)
        try:
            first = ws.recv()
            frame = json.loads(first) if isinstance(first, str) else None
        except Exception as exc:
            _close_quietly(ws)
            if "timeout" in type(exc).__name__.lower():
                raise MicroVMError(
                    f"file watch did not start within {_WATCH_START_TIMEOUT_SECONDS:g}s"
                ) from exc
            raise MicroVMError(f"file watch closed before it started: {exc}") from exc
        if not isinstance(frame, dict) or frame.get("type") != "start":
            _close_quietly(ws)
            raise MicroVMError(f"file watch did not start: unexpected first message {first!r}")
        if callable(settimeout):
            settimeout(None)
        return FileWatchHandle(ws, on_event)

    # File verbs beyond upload and download (plans/agent-sandbox-feature-
    # parity.md, F1). They go through the sandbox's toolbox. A sandbox whose
    # agent predates them fails closed with MicroVMUnsupportedFeatureError
    # instead of ignoring a safety option; WASM and V8 isolate sandboxes
    # answer them with HTTP 501.
    #
    # Retries: list_files, get_file_info, file_exists, search_files,
    # find_in_files, delete_file and make_dir are safe to re-send and retry
    # on 421, 429, 502, 503 and 504 (a retried delete or mkdir whose work is
    # already done counts as success). move_file and copy_file retry only on
    # 429 and 503, because a lost reply may hide a move that happened.

    def _toolbox_path(self, sandbox_id: str, route: str, query: Dict[str, str]) -> str:
        return f"{self._version_prefix}/sandboxes/{urllib.parse.quote(sandbox_id, safe='')}/toolbox{route}?{urllib.parse.urlencode(query)}"

    def list_files(self, sandbox_id: str, path: str, *, depth: int = 1, limit: int = DEFAULT_LIST_LIMIT) -> FileList:
        """List a folder, ``depth`` levels down (1 is the folder's own
        entries), returning at most ``limit`` entries. Symlinked folders are
        listed but never entered. ``truncated`` says more entries exist."""
        if depth < 1 or limit < 1:
            raise MicroVMError("depth and limit must be at least 1")
        self._require_toolbox_features(sandbox_id, _FEATURE_FILE_VERBS)
        query = {"path": path, "depth": str(depth), "limit": str(limit), "extended": "true"}
        data, headers = self._do_json_headers("GET", self._toolbox_path(sandbox_id, "/files", query), None)
        entries = [_from_api_file_info(item, path.rstrip("/") + "/" + str(item.get("name", ""))) for item in (data or []) if isinstance(item, dict)]
        truncated = any(k.lower() == "x-toolbox-truncated" and v == "true" for k, v in headers.items())
        return {"entries": entries, "truncated": truncated}

    def get_file_info(self, sandbox_id: str, path: str) -> FileInfo:
        """Describe one path. A symlink is followed."""
        # extended=true only adds fields; an older agent that ignores it
        # answers fields this still reads, so no /version check.
        data = self._do_json("GET", self._toolbox_path(sandbox_id, "/files/info", {"path": path, "extended": "true"}), None)
        return _from_api_file_info(data if isinstance(data, dict) else {}, path)

    def file_exists(self, sandbox_id: str, path: str) -> bool:
        """Whether ``path`` exists. A missing sandbox raises, it is not False."""
        try:
            self.get_file_info(sandbox_id, path)
        except MicroVMHTTPError as err:
            if _is_missing_file(err):
                return False
            raise
        return True

    def delete_file(self, sandbox_id: str, path: str, *, recursive: bool = False) -> None:
        """Delete a file, or a folder and everything in it with
        ``recursive=True``. A folder without it is refused (HTTP 409)."""
        query = {"path": path}
        if recursive:
            query["recursive"] = "true"
        self._request("DELETE", self._url(self._toolbox_path(sandbox_id, "/files", query)), done_code=_CODE_FILE_NOT_FOUND)

    def make_dir(self, sandbox_id: str, path: str, *, parents: bool = False, mode: Optional[int] = None) -> None:
        """Make a folder. ``parents=True`` also makes missing parents and
        accepts an existing folder (``mkdir -p``). ``mode`` (such as
        ``0o750``) defaults to 0755."""
        if not parents:
            # An older agent ignores parents=false and makes them anyway.
            self._require_toolbox_features(sandbox_id, _FEATURE_FILE_VERBS)
        query = {"path": path, "parents": "true" if parents else "false"}
        if mode is not None:
            query["mode"] = format(mode, "o")
        self._request("POST", self._url(self._toolbox_path(sandbox_id, "/files/folder", query)), done_code=_CODE_FOLDER_EXISTS)

    def move_file(self, sandbox_id: str, source: str, destination: str, *, overwrite: bool = False) -> None:
        """Move or rename a file or folder. Without ``overwrite`` an existing
        destination is refused (HTTP 409)."""
        if not overwrite:
            # An older agent ignores overwrite=false and replaces the file.
            self._require_toolbox_features(sandbox_id, _FEATURE_FILE_VERBS)
        query = {"source": source, "destination": destination, "overwrite": "true" if overwrite else "false"}
        self._request("POST", self._url(self._toolbox_path(sandbox_id, "/files/move", query)), idempotent=False)

    def copy_file(self, sandbox_id: str, source: str, destination: str, *, overwrite: bool = False, recursive: bool = False) -> None:
        """Copy a file, or a folder with ``recursive=True`` (keeping modes
        and symlinks). Without ``overwrite`` an existing destination is
        refused (HTTP 409)."""
        self._require_toolbox_features(sandbox_id, _FEATURE_FILE_VERBS)
        query = {
            "source": source,
            "destination": destination,
            "overwrite": "true" if overwrite else "false",
            "recursive": "true" if recursive else "false",
        }
        self._request("POST", self._url(self._toolbox_path(sandbox_id, "/files/copy", query)), idempotent=False)

    def search_files(self, sandbox_id: str, path: str, pattern: str) -> List[str]:
        """Paths under ``path`` whose name matches a glob such as ``*.py``."""
        data = self._do_json("GET", self._toolbox_path(sandbox_id, "/files/search", {"path": path, "pattern": pattern}), None)
        files = data.get("files") if isinstance(data, dict) else None
        return [str(f) for f in files] if isinstance(files, list) else []

    def find_in_files(self, sandbox_id: str, path: str, text: str) -> List[FileMatch]:
        """Each line under ``path`` that contains ``text`` (plain text)."""
        data = self._do_json("GET", self._toolbox_path(sandbox_id, "/files/find", {"path": path, "pattern": text}), None)
        if not isinstance(data, list):
            return []
        return [
            {"file": str(m.get("file", "")), "line": int(m.get("line") or 0), "content": str(m.get("content", ""))}
            for m in data
            if isinstance(m, dict)
        ]

    def expose_port(self, sandbox_id: str, port: int, *, protocol: ExposeProtocol = "http") -> ExposeResult:
        """Publish a sandbox container port.

        ``protocol`` selects the wire surface and defaults to ``"http"``:

        - ``"http"``: Caddy HTTP reverse proxy at ``https://<id>-<port>.<domain>``.
        - ``"tcp"``:  raw caddy-l4 listener on a parent-host port. Pair with
                      native protocol clients (psql, redis-cli, mysql, mongosh).
        - ``"tls"``:  caddy-l4 TLS-SNI route on the shared listener. Requires
                      the daemon to have a domain configured AND
                      ``SB_L4_TLS_LISTEN`` set.

        Returns an :class:`ExposeResult`. ``host`` and ``host_port`` are
        populated only on the ``"tcp"`` path.
        """
        body: Optional[Dict[str, Any]] = {"protocol": protocol} if protocol and protocol != "http" else None
        response = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/ports/{port}", body)
        return _from_api_expose_port_response(response)

    def unexpose_port(self, sandbox_id: str, port: int) -> None:
        self._do_json("DELETE", f"{self._version_prefix}/sandboxes/{sandbox_id}/ports/{port}", None)

    def add_custom_domain(
        self,
        sandbox_id: str,
        hostname: str,
        *,
        port: Optional[int] = None,
    ) -> List[CustomDomain]:
        """Attach a public hostname to a sandbox.

        Returns the post-attach list of :class:`CustomDomain` rows so callers
        can read the initial ``status`` (typically ``"pending_dns"``) without
        a follow-up GET. Server lowercases the hostname; case is preserved
        as-passed.

        ``port`` pins the container port traffic to this hostname dials. Omit
        (or pass ``0``) to route to the sandbox's toolbox port (the default).
        Re-adding the same hostname with a different ``port`` returns 409 —
        detach first.
        """
        body: Dict[str, Any] = {"hostname": hostname}
        if port is not None and port != 0:
            body["target_port"] = port
        response = self._do_json(
            "POST",
            self._versioned(f"/sandboxes/{sandbox_id}/custom-domains"),
            body,
        )
        return _from_api_custom_domains_response(response)

    def list_custom_domains(self, sandbox_id: str) -> List[CustomDomain]:
        response = self._do_json(
            "GET",
            self._versioned(f"/sandboxes/{sandbox_id}/custom-domains"),
            None,
        )
        return _from_api_custom_domains_response(response)

    def remove_custom_domain(self, sandbox_id: str, hostname: str) -> None:
        # URL-encode the hostname segment — DNS labels never need it in
        # practice, but IDN/punycode hosts ("xn--…") and any operator-supplied
        # garbage we still want to send must survive an exact round-trip.
        encoded = urllib.parse.quote(hostname, safe="")
        self._do_json(
            "DELETE",
            self._versioned(f"/sandboxes/{sandbox_id}/custom-domains/{encoded}"),
            None,
        )

    def dns_target(self) -> IngressTarget:
        """Return the DNS target operators should point custom hostnames at.

        Surfaces the daemon's resolved ingress identity — typically a single
        ``hostname`` (CNAME) or a list of ``ips`` (A/AAAA), plus a ``source``
        tag describing how it was resolved. Use this when rendering generic
        setup instructions; for per-sandbox per-hostname records call
        :meth:`custom_domain_dns` instead.
        """
        response = self._do_json("GET", self._versioned("/ingress/dns"), None)
        return _from_api_ingress_target(response)

    def custom_domain_dns(self, sandbox_id: str) -> CustomDomainDNSRecords:
        """Return the DNS records to publish for this sandbox's custom domains.

        Returns one :class:`DNSRecord` per attached hostname (empty list if
        no domains are attached) bundled with the underlying
        :class:`IngressTarget`, so callers can render full DNS setup
        instructions without a follow-up :meth:`dns_target` call.
        """
        response = self._do_json(
            "GET",
            self._versioned(f"/sandboxes/{sandbox_id}/custom-domains/dns"),
            None,
        )
        return _from_api_custom_domain_dns_response(response)

    def _resolve_image(self, image: Any) -> str:
        if isinstance(image, Image):
            return self.build_image(image)
        if isinstance(image, str) and image.strip() != "":
            return image
        raise TypeError("CreateOptions.image must be a non-empty string or Image")

    def _wrap_sandbox(self, response: Dict[str, Any]) -> Sandbox:
        return Sandbox(self, _from_api_sandbox(response))

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def _websocket_headers(self) -> List[str]:
        headers = [f"Authorization: Bearer {self.pat_token}"]
        if self.team:
            headers.append(f"{TEAM_HEADER}: {self.team}")
        return headers

    def _request(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        *,
        idempotent: bool = True,
        done_code: Optional[str] = None,
    ) -> bytes:
        raw, _ = self._request_headers(method, url, body, content_type, extra_headers, idempotent=idempotent, done_code=done_code)
        return raw

    def _request_headers(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        *,
        idempotent: bool = True,
        done_code: Optional[str] = None,
    ) -> tuple[bytes, Dict[str, str]]:
        """Send one request, retrying transient failures with backoff.

        ``done_code`` is for a call whose retry can find its own work done
        (a delete finds the path gone, a mkdir its folder): when a re-sent
        attempt, never the first, gets an error carrying that toolbox error
        code, the first attempt's reply was lost and the call succeeds.

        ``idempotent=True`` (every endpoint but exec; the daemon designs them
        for duplicate calls) retries any transport failure and the statuses
        in ``_RETRY_STATUSES``. ``idempotent=False`` retries only failures
        that prove the server never got the request, plus 429 and 503: a
        timeout or reset after the request was written leaves it unknown
        whether the command ran, and a retry would run it again.

        A 429 or 503 waits as long as its ``Retry-After`` asks (see
        :meth:`_retry_delay`). The wait is a plain ``time.sleep``, so a
        signal handler that raises (Ctrl-C, a ``signal.alarm`` timeout) ends
        it at once.
        """
        max_retries = self._retry_config["maxRetries"]
        retry_statuses = _RETRY_STATUSES if idempotent else _NOT_STARTED_STATUSES

        last_exc: Optional[Exception] = None

        for attempt in range(max_retries + 1):
            retry_after: Optional[str] = None
            request = urllib.request.Request(url, data=body, method=method)
            request.add_header("Authorization", f"Bearer {self.pat_token}")
            if self.team:
                request.add_header(TEAM_HEADER, self.team)
            if content_type is not None:
                request.add_header("Content-Type", content_type)
            for header_key, header_val in (extra_headers or {}).items():
                request.add_header(header_key, header_val)

            try:
                with urllib.request.urlopen(request) as response:
                    headers = {k: v for k, v in response.headers.items()}
                    return response.read(), headers
            except urllib.error.HTTPError as exc:
                last_exc = exc
                payload: Optional[bytes] = None
                if done_code is not None and attempt > 0:
                    try:
                        payload = exc.read()
                    finally:
                        exc.close()
                    if _error_code(payload) == done_code:
                        return b"", {}
                if exc.code in retry_statuses and attempt < max_retries:
                    if exc.code in _NOT_STARTED_STATUSES and exc.headers is not None:
                        retry_after = exc.headers.get("Retry-After")
                    # Free the socket before the backoff sleep.
                    exc.close()
                else:
                    wait = _parse_retry_after(exc.headers.get("Retry-After"), time.time()) if exc.headers is not None else None
                    if payload is None:
                        try:
                            payload = exc.read()
                        finally:
                            exc.close()
                    try:
                        data = json.loads(payload.decode("utf-8"))
                    except (ValueError, TypeError):
                        raise MicroVMHTTPError(exc.code, str(exc.reason), retry_after=wait) from exc
                    raise _http_error(exc.code, data, str(exc.reason), wait) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                if attempt >= max_retries or not (idempotent or _request_never_sent(exc)):
                    raise
            except Exception as exc:
                # Raised while waiting for or reading the response (a read
                # timeout, a reset, the server closing without a reply): the
                # server may already be acting on the request.
                last_exc = exc
                if attempt >= max_retries or not idempotent:
                    raise

            time.sleep(self._retry_delay(attempt, retry_after, time.time(), random.random()))

        assert last_exc is not None
        raise last_exc

    def _retry_delay(self, attempt: int, retry_after: Optional[str], now: float, rand: float) -> float:
        """Seconds to wait before re-sending. ``attempt`` counts from 0,
        ``retry_after`` is a 429/503's header (``None`` otherwise) and
        ``rand`` is uniform in [0, 1).

        Without a usable header it is the exponential backoff ±25%. With one,
        it never retries sooner than the server asked (nor sooner than the
        backoff) and adds up to a fifth so clients told the same value spread
        out. ``maxRetryAfterMs`` is a hard ceiling: when the server asks for
        at least that long the client is early anyway, so the spread goes
        below it instead.
        """
        backoff = min(self._retry_config["baseDelayMs"] * (2 ** attempt), self._retry_config["maxDelayMs"]) / 1000.0
        limit = self._retry_config["maxRetryAfterMs"] / 1000.0
        hint = _parse_retry_after(retry_after, now) if limit > 0 else None
        if hint is None:
            return backoff * (0.75 + 0.5 * rand)
        target = max(hint, backoff)
        if target >= limit:
            return limit - limit * 0.2 * rand
        upper = min(target * 1.2, limit)
        return target + (upper - target) * rand

    def _do_json(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        *,
        idempotent: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """``headers`` are extra request headers, sent unchanged on every retry."""
        data, _ = self._do_json_headers(method, path, payload, idempotent=idempotent, headers=headers)
        return data

    def _do_json_headers(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        *,
        idempotent: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> tuple[Any, Dict[str, str]]:
        body = None
        content_type = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            content_type = "application/json"
        raw, response_headers = self._request_headers(
            method, self._url(path), body, content_type, headers, idempotent=idempotent
        )
        if raw == b"":
            return {}, response_headers
        return json.loads(raw.decode("utf-8")), response_headers

    def _do_multipart(
        self,
        path: str,
        fields: Dict[str, str],
        file_field: str,
        filename: str,
        data: bytes,
    ) -> None:
        boundary = uuid.uuid4().hex
        body = BytesIO()
        encoder = body.write

        for name, value in fields.items():
            encoder(f"--{boundary}\r\n".encode("utf-8"))
            encoder(f"Content-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode("utf-8"))
            encoder(value.encode("utf-8"))
            encoder(b"\r\n")

        encoder(f"--{boundary}\r\n".encode("utf-8"))
        encoder(f"Content-Disposition: form-data; name=\"{file_field}\"; filename=\"{os.path.basename(filename)}\"\r\n".encode("utf-8"))
        encoder(b"Content-Type: application/octet-stream\r\n\r\n")
        encoder(data)
        encoder(b"\r\n")
        encoder(f"--{boundary}--\r\n".encode("utf-8"))

        self._request("POST", self._url(path), body.getvalue(), f"multipart/form-data; boundary={boundary}")


class Tokens:
    """Scoped API tokens (avm_…) for services and CI, reached as
    ``client.tokens``. Creating and revoking needs an admin credential;
    listing needs an auditor or an admin."""

    def __init__(self, client: MicroVM) -> None:
        self._client = client

    def create(self, options: Optional[CreateAPITokenOptions] = None, **fields: Any) -> CreatedAPIToken:
        """Mint a token. Takes ``name``, ``role``, ``team`` and ``expiresIn``
        (or ``expires_in``) as a dict or as keywords. The result's ``token``
        is the secret, returned this once and never again.

        A 409 means the name is taken, possibly by an earlier attempt whose
        reply was lost; that secret cannot be recovered, so revoke the token
        and create it again.
        """
        resolved: Dict[str, Any] = {**(options or {}), **fields}
        body = {
            "name": str(_first_of(resolved, "name") or ""),
            "role": str(_first_of(resolved, "role") or ""),
            "team": str(_first_of(resolved, "team") or ""),
            "expires_in": str(_first_of(resolved, "expiresIn", "expires_in") or ""),
        }
        payload = self._client._do_json("POST", self._client._versioned("/tokens"), body) or {}
        created: CreatedAPIToken = {**_from_api_api_token(payload), "token": str(payload.get("token") or "")}  # type: ignore[typeddict-item]
        return created

    def list(self) -> APITokenList:
        """Every token, expired ones included (``expired`` is True) until the
        server removes them 30 days after expiry. Never a secret."""
        payload = self._client._do_json("GET", self._client._versioned("/tokens"), None) or {}
        tokens = payload.get("tokens") if isinstance(payload, dict) else None
        return {"tokens": [_from_api_api_token(t) for t in tokens or [] if isinstance(t, dict)]}

    def revoke(self, token_id: str) -> None:
        """Revoke a token by id (tok_…). Revoking one that is already gone
        succeeds, so a retried revoke is safe."""
        trimmed = (token_id or "").strip()
        if not trimmed:
            raise ValueError("token id is required")
        self._client._do_json("DELETE", self._client._versioned(f"/tokens/{urllib.parse.quote(trimmed, safe='')}"), None)


def _from_api_whoami(payload: Dict[str, Any]) -> WhoAmI:
    principal = payload.get("principal") or {}
    result: WhoAmI = {
        "principal": {"kind": str(principal.get("kind") or ""), "id": str(principal.get("id") or "")},
        "role": str(payload.get("role") or ""),
    }
    if principal.get("name"):
        result["principal"]["name"] = str(principal["name"])
    if payload.get("team"):
        result["team"] = str(payload["team"])
    if payload.get("expires_at"):
        result["expiresAt"] = str(payload["expires_at"])
    return result


def _from_api_api_token(payload: Dict[str, Any]) -> APIToken:
    return {
        "id": str(payload.get("id") or ""),
        "name": str(payload.get("name") or ""),
        "role": str(payload.get("role") or ""),
        "team": str(payload.get("team") or ""),
        "createdBy": str(payload.get("created_by") or ""),
        "createdAt": str(payload.get("created_at") or ""),
        "expiresAt": str(payload.get("expires_at") or ""),
        "expired": bool(payload.get("expired", False)),
    }


def _load_websocket_module() -> Any:
    return importlib.import_module("websocket")


def _connect_websocket(websocket_module: Any, ws_url: str, headers: List[str], label: str) -> Any:
    """create_connection wrapper that surfaces HTTP status/body on bad
    handshake. websocket-client raises WebSocketBadStatusException for non-101
    responses, which carries .status_code and .resp_body but stringifies as
    "Handshake status 401 Unauthorized" — we want the body too so 502s from
    the toolbox proxy ("toolbox unavailable") and 401s with JSON error bodies
    are decipherable without a packet capture.
    """
    try:
        return websocket_module.create_connection(
            ws_url,
            header=headers,
            enable_multithread=True,
        )
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        body = getattr(exc, "resp_body", None)
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", errors="replace").strip()
        elif isinstance(body, str):
            body = body.strip()
        parts = [f"{label} websocket connect to {ws_url} failed: {exc}"]
        if status is not None:
            parts.append(f"status={status}")
        if body:
            parts.append(f"body={body!r}")
        raise MicroVMError(" | ".join(parts)) from exc


def _close_quietly(ws: Any) -> None:
    try:
        ws.close()
    except Exception:
        pass


# How long watch_files waits for toolboxd to say the watch is armed.
_WATCH_START_TIMEOUT_SECONDS = 60.0


def _connect_watch_websocket(websocket_module: Any, ws_url: str, headers: List[str], sandbox_id: str) -> Any:
    """Opens the file-watch WebSocket, turning a refused handshake into the
    error a caller can act on. websocket-client raises
    WebSocketBadStatusException for a non-101 answer, with the status, the
    headers (lowercased) and the body."""
    try:
        return websocket_module.create_connection(ws_url, header=headers, enable_multithread=True)
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if not isinstance(status, int):
            raise MicroVMError(f"file watch websocket connect to {ws_url} failed: {exc}") from exc
        body = getattr(exc, "resp_body", None)
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", errors="replace")
        text = body.strip() if isinstance(body, str) else ""
        try:
            data = json.loads(text) if text else None
        except json.JSONDecodeError:
            data = None
        resp_headers = getattr(exc, "resp_headers", None)
        lowered = {str(k).lower(): str(v) for k, v in resp_headers.items()} if isinstance(resp_headers, dict) else {}
        # An agent built before file watching has no such route. toolboxd marks
        # that 404 with X-Toolbox-Route: none; one older still says only
        # "not found". sandboxd's own 404 says "sandbox not found", and a
        # missing folder "path not found: ...", so neither matches.
        if status == 404 and (
            lowered.get("x-toolbox-route") == "none" or (isinstance(data, dict) and data.get("error") == "not found")
        ):
            raise MicroVMUnsupportedFeatureError(sandbox_id, ["files.watch"]) from exc
        retry_after = _parse_retry_after(lowered.get("retry-after"), time.time())
        raise _http_error(status, data, text or f"file watch failed with status {status}", retry_after) from exc


def _to_websocket_url(base_url: str, path: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    scheme = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}.get(parsed.scheme)
    if scheme is None:
        raise MicroVMError(f"unsupported API URL scheme: {parsed.scheme}")
    return urllib.parse.urlunparse((scheme, parsed.netloc, path, "", "", ""))


def _request_never_sent(exc: urllib.error.URLError) -> bool:
    """Whether a transport failure proves the server never got the request.

    urlopen wraps only connect- and send-phase OSErrors in URLError; a
    failure while waiting for or reading the response is raised unwrapped.
    Of the wrapped ones, a refused connection and a failed DNS lookup happen
    before any byte is sent. A timeout fires while connecting or before the
    request was fully written, and a request whose body never fully arrived
    fails to decode on the server, so nothing runs. A reset or broken pipe
    is not taken as that proof, so it surfaces to the caller.
    """
    # socket.timeout is TimeoutError from 3.10; listed apart for 3.9.
    return isinstance(exc.reason, (ConnectionRefusedError, socket.gaierror, socket.timeout, TimeoutError))


def _error_code(payload: Optional[bytes]) -> str:
    """The ``code`` of a JSON error body, or "" when there is none."""
    try:
        data = json.loads((payload or b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ""
    return str(data.get("code") or "") if isinstance(data, dict) else ""


def _is_missing_file(err: MicroVMHTTPError) -> bool:
    """A missing file, not a missing sandbox (also a 404). Current agents say
    file_not_found; older ones send no code, but their message is the OS
    error, which ends "no such file or directory"."""
    if err.status_code != 404:
        return False
    return err.code == _CODE_FILE_NOT_FOUND or (not err.code and str(err).endswith("no such file or directory"))


def _from_api_file_info(data: Dict[str, Any], fallback_path: str) -> FileInfo:
    """toolboxd's file info with extended=true. An older agent sends only
    Daytona's fields (a 32-bit size, no path), so each extended field falls
    back."""
    size = data.get("size_bytes")
    info: FileInfo = {
        "name": str(data.get("name", "")),
        "path": str(data.get("path") or fallback_path),
        "isDir": bool(data.get("isDir", False)),
        "size": int(size if size is not None else data.get("size") or 0),
        "mode": str(data.get("mode", "")),
        "permissions": str(data.get("permissions", "")),
        "owner": str(data.get("owner", "")),
        "group": str(data.get("group", "")),
        "modTime": str(data.get("modTime", "")),
    }
    if data.get("symlink_target") is not None:
        info["symlinkTarget"] = str(data["symlink_target"])
    return info


def _first_of(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        # Callers pass string field names. Skip anything else so a dict
        # never reaches the subscript, which would raise TypeError.
        if not isinstance(key, str):
            continue
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _compact(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


def _build_sandbox_query(
    tags: Optional[Dict[str, str]], include_env: bool = False, name: Optional[str] = None
) -> str:
    # Renders tag filters and optional include_env as the server's wire format.
    # The `tag.` prefix is literal — the server's parseTagFilter inspects the
    # decoded query key — so only the user-supplied key and value get
    # percent-encoded. An empty query returns "" so the request URL is
    # byte-identical to the pre-filter call (no stray trailing "?").
    parts: List[str] = []
    if tags:
        parts.extend(
            f"tag.{urllib.parse.quote(str(key), safe='')}={urllib.parse.quote(str(value), safe='')}"
            for key, value in tags.items()
        )
    if include_env:
        parts.append("include_env=true")
    wanted = (name or "").strip()
    if wanted:
        parts.append(f"name={urllib.parse.quote(wanted, safe='')}")
    if not parts:
        return ""
    return "?" + "&".join(parts)


def _append_query_param(path: str, key: str, value: str) -> str:
    if not value:
        return path
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}{urllib.parse.quote(key, safe='')}={urllib.parse.quote(value, safe='')}"


def _to_api_create_options(options: CreateOptions) -> Dict[str, Any]:
    lifecycle = _first_of(options, "lifecycle")
    failover = _first_of(options, "failover")
    gpus = _first_of(options, "gpus")
    return _compact(
        {
            "name": _first_of(options, "name"),
            "tags": _first_of(options, "tags"),
            "image": _first_of(options, "image"),
            "cpu": _first_of(options, "cpu"),
            "memory_mb": _first_of(options, "memoryMB", "memory_mb"),
            "disk_gb": _first_of(options, "diskGB", "disk_gb"),
            "env": _first_of(options, "env"),
            "os_user": _first_of(options, "osUser", "os_user"),
            "network_block_all": _first_of(options, "networkBlockAll", "network_block_all"),
            "network_allow_out": _first_of(options, "networkAllowOut", "network_allow_out"),
            "network_deny_out": _first_of(options, "networkDenyOut", "network_deny_out"),
            "egress_profiles": _first_of(options, "egressProfiles", "egress_profiles"),
            "network_egress_mode": _first_of(options, "networkEgressMode", "network_egress_mode"),
            "network_egress_rules": _egress_rules_or_none(_first_of(options, "networkEgressRules", "network_egress_rules")),
            "allow_public_traffic": _first_of(options, "allowPublicTraffic", "allow_public_traffic"),
            "mask_request_host": _first_of(options, "maskRequestHost", "mask_request_host"),
            "network_bytes_in_limit": _first_of(options, "networkBytesInLimit", "network_bytes_in_limit"),
            "network_bytes_out_limit": _first_of(options, "networkBytesOutLimit", "network_bytes_out_limit"),
            "registry": _first_of(options, "registry"),
            "container_command": _first_of(options, "containerCommand", "container_command"),
            "mounts": [_to_api_mount_spec(item) for item in (_first_of(options, "mounts") or [])],
            "platform_volumes": [
                _to_api_platform_volume(item)
                for item in (_first_of(options, "platformVolumes", "platform_volumes") or [])
            ],
            "lifecycle": _to_api_lifecycle(lifecycle) if isinstance(lifecycle, dict) else None,
            "failover": _to_api_failover(failover) if isinstance(failover, dict) else None,
            "runtime": _first_of(options, "runtime"),
            "durability": _first_of(options, "durability"),
            "module_ref": _first_of(options, "moduleRef", "module_ref"),
            "tenant_id": _first_of(options, "tenantId", "tenant_id"),
            "custom_domains": _first_of(options, "customDomains", "custom_domains"),
            "gpus": _to_api_gpus(gpus) if isinstance(gpus, dict) else None,
            "template_id": _first_of(options, "templateId", "template_id"),
        }
    )


def _to_api_gpus(gpus: GPUOptions) -> Dict[str, Any]:
    return _compact(
        {
            "vendor": _first_of(gpus, "vendor"),
            "count": _first_of(gpus, "count"),
            "device_ids": _first_of(gpus, "deviceIDs", "device_ids"),
        }
    )


def _to_api_register_snapshot_options(options: RegisterSnapshotOptions) -> Dict[str, Any]:
    return _compact(
        {
            "name": _first_of(options, "name"),
            "image": _first_of(options, "image"),
            "dockerfile_content": _first_of(options, "dockerfileContent", "dockerfile_content"),
            "context_hashes": _first_of(options, "contextHashes", "context_hashes"),
            "entrypoint": _first_of(options, "entrypoint"),
            "region_id": _first_of(options, "regionID", "region_id"),
            "cpu": _first_of(options, "cpu"),
            "gpu": _first_of(options, "gpu"),
            "memory_mb": _first_of(options, "memoryMB", "memory_mb"),
            "disk_gb": _first_of(options, "diskGB", "disk_gb"),
        }
    )


def _to_api_resize_options(options: ResizeOptions) -> Dict[str, Any]:
    return _compact(
        {
            "cpu": _first_of(options, "cpu"),
            "memory_mb": _first_of(options, "memoryMB", "memory_mb"),
            "disk_gb": _first_of(options, "diskGB", "disk_gb"),
        }
    )


def _to_api_exec_request(request: ExecRequest) -> Dict[str, Any]:
    return _compact(
        {
            "command": _first_of(request, "command"),
            "argv": _first_of(request, "argv"),
            "workdir": _first_of(request, "workDir", "workdir"),
            "env": _first_of(request, "env"),
            "timeout_seconds": _first_of(request, "timeoutSeconds", "timeout_seconds"),
            "max_stdout_bytes": _first_of(request, "maxStdoutBytes", "max_stdout_bytes"),
            "max_stderr_bytes": _first_of(request, "maxStderrBytes", "max_stderr_bytes"),
        }
    )


def _from_api_file_event(payload: Dict[str, Any]) -> FileEvent:
    reason = payload.get("reason")
    return FileEvent(
        type=str(payload.get("type") or ""),
        path=str(payload.get("path") or ""),
        is_dir=bool(payload.get("is_dir", False)),
        reason=str(reason) if isinstance(reason, str) and reason != "" else None,
    )


def _to_api_exec_stream_request(options: ExecStreamOptions) -> Dict[str, Any]:
    return _compact(
        {
            "command": _first_of(options, "command"),
            "argv": _first_of(options, "argv"),
            "workdir": _first_of(options, "workdir", "workDir"),
            "env": _first_of(options, "env"),
            "tty": _first_of(options, "tty"),
            "cols": _first_of(options, "cols"),
            "rows": _first_of(options, "rows"),
        }
    )


def _to_api_create_session_options(options: CreateSessionOptions) -> Dict[str, Any]:
    return _compact(
        {
            "name": _first_of(options, "name"),
            "argv": _first_of(options, "argv"),
            "command": _first_of(options, "command"),
            "workdir": _first_of(options, "workdir", "workDir"),
            "env": _first_of(options, "env"),
            "pty": _first_of(options, "pty"),
            "cols": _first_of(options, "cols"),
            "rows": _first_of(options, "rows"),
        }
    )


def _to_api_lifecycle(lifecycle: Lifecycle) -> Dict[str, Any]:
    return _compact(
        {
            "stop_if_idle_for": _first_of(lifecycle, "stopIfIdleFor", "stop_if_idle_for"),
            "destroy_if_idle_for": _first_of(lifecycle, "destroyIfIdleFor", "destroy_if_idle_for"),
            "stop_at_age": _first_of(lifecycle, "stopAtAge", "stop_at_age"),
            "destroy_at_age": _first_of(lifecycle, "destroyAtAge", "destroy_at_age"),
            "serverless": _first_of(lifecycle, "serverless"),
        }
    )


def _to_api_failover(failover: Failover) -> Dict[str, Any]:
    return _compact({"policy": _first_of(failover, "policy")})


def _from_api_exec_result(result: Dict[str, Any]) -> ExecResult:
    return {
        "stdout": str(_first_of(result, "stdout") or ""),
        "stderr": str(_first_of(result, "stderr") or ""),
        "exitCode": int(_first_of(result, "exit_code", "exitCode") or 0),
        "durationMS": int(_first_of(result, "duration_ms", "durationMS") or 0),
        "timedOut": bool(_first_of(result, "timed_out", "timedOut") or False),
        "stdoutTruncated": bool(_first_of(result, "stdout_truncated", "stdoutTruncated") or False),
        "stderrTruncated": bool(_first_of(result, "stderr_truncated", "stderrTruncated") or False),
        "signal": str(_first_of(result, "signal") or ""),
    }


def _from_api_custom_domain(domain: Dict[str, Any]) -> CustomDomain:
    result: CustomDomain = {
        "hostname": str(_first_of(domain, "hostname") or ""),
        "status": str(_first_of(domain, "status") or "pending_dns"),  # type: ignore[typeddict-item]
        "createdAt": str(_first_of(domain, "created_at", "createdAt") or ""),
        "updatedAt": str(_first_of(domain, "updated_at", "updatedAt") or ""),
    }
    last_error = _first_of(domain, "last_error", "lastError")
    if last_error not in (None, ""):
        result["lastError"] = str(last_error)
    target_port = _first_of(domain, "target_port", "targetPort")
    if isinstance(target_port, int) and target_port > 0:
        result["targetPort"] = target_port
    return result


def _from_api_custom_domains_response(response: Any) -> List[CustomDomain]:
    if not isinstance(response, dict):
        return []
    domains = _first_of(response, "custom_domains", "customDomains") or []
    if not isinstance(domains, list):
        return []
    return [_from_api_custom_domain(item) for item in domains if isinstance(item, dict)]


_INGRESS_TARGET_SOURCES = {"hostname", "ips", "mixed", "unknown"}


def _from_api_ingress_target(payload: Any) -> IngressTarget:
    # Wire contract: source ∈ {"hostname", "ips", "mixed", "unknown"}.
    # Anything missing/unrecognized collapses to "unknown" so callers can
    # branch on the documented enum without seeing "" or server typos.
    if not isinstance(payload, dict):
        return {"source": "unknown"}
    raw_source = _first_of(payload, "source")
    source = str(raw_source) if raw_source else ""
    if source not in _INGRESS_TARGET_SOURCES:
        source = "unknown"
    result: IngressTarget = {"source": source}
    hostname = _first_of(payload, "hostname")
    if hostname not in (None, ""):
        result["hostname"] = str(hostname)
    ips = _first_of(payload, "ips")
    if isinstance(ips, list) and len(ips) > 0:
        result["ips"] = [str(item) for item in ips]
    return result


def _from_api_dns_record(record: Dict[str, Any]) -> DNSRecord:
    result: DNSRecord = {
        "hostname": str(_first_of(record, "hostname") or ""),
        "type": str(_first_of(record, "type") or ""),
        "name": str(_first_of(record, "name") or ""),
        "value": str(_first_of(record, "value") or ""),
    }
    notes = _first_of(record, "notes")
    if notes not in (None, ""):
        result["notes"] = str(notes)
    return result


def _from_api_custom_domain_dns_response(response: Any) -> CustomDomainDNSRecords:
    if not isinstance(response, dict):
        return {"records": [], "target": {"source": "unknown"}}
    records_raw = _first_of(response, "records") or []
    records: List[DNSRecord] = (
        [_from_api_dns_record(item) for item in records_raw if isinstance(item, dict)]
        if isinstance(records_raw, list)
        else []
    )
    target_raw = _first_of(response, "target")
    target = _from_api_ingress_target(target_raw) if isinstance(target_raw, dict) else {"source": "unknown"}
    return {"records": records, "target": target}


def _from_api_exposed_port(port: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sandboxID": str(_first_of(port, "sandbox_id", "sandboxID") or ""),
        "port": int(_first_of(port, "port") or 0),
        "publicURL": str(_first_of(port, "public_url", "publicURL") or ""),
        "createdAt": str(_first_of(port, "created_at", "createdAt") or ""),
    }


def _from_api_template(template: Any) -> Template:
    if not isinstance(template, dict):
        raise MicroVMError("expected JSON object for template")
    result: Template = {
        "id": str(_first_of(template, "id") or ""),
        "image": str(_first_of(template, "image") or ""),
        "status": str(_first_of(template, "status") or ""),  # type: ignore[typeddict-item]
        "createdAt": str(_first_of(template, "created_at", "createdAt") or ""),
        "updatedAt": str(_first_of(template, "updated_at", "updatedAt") or ""),
        "hasSnapshot": bool(_first_of(template, "has_snapshot", "hasSnapshot") or False),
        "hasOverlay": bool(_first_of(template, "has_overlay", "hasOverlay") or False),
    }
    rootfs_size = _first_of(template, "rootfs_size_bytes", "rootfsSizeBytes")
    if rootfs_size is not None:
        result["rootfsSizeBytes"] = int(rootfs_size)
    min_size = _first_of(template, "min_size_mib", "minSizeMiB")
    if min_size is not None:
        result["minSizeMiB"] = int(min_size)
    last_error = _first_of(template, "last_error", "lastError")
    if last_error not in (None, ""):
        result["lastError"] = str(last_error)
    ready_at = _first_of(template, "ready_at", "readyAt")
    if ready_at not in (None, ""):
        result["readyAt"] = str(ready_at)
    snap_size = _first_of(template, "snapshot_size_bytes", "snapshotSizeBytes")
    if snap_size is not None:
        result["snapshotSizeBytes"] = int(snap_size)
    snap_err = _first_of(template, "snapshot_error", "snapshotError")
    if snap_err not in (None, ""):
        result["snapshotError"] = str(snap_err)
    push_state = _first_of(template, "push_state", "pushState")
    if push_state not in (None, ""):
        result["pushState"] = str(push_state)  # type: ignore[typeddict-item]
    push_err = _first_of(template, "push_error", "pushError")
    if push_err not in (None, ""):
        result["pushError"] = str(push_err)
    return result


def _from_api_wasm_module(module: Any) -> WasmModule:
    if not isinstance(module, dict):
        raise MicroVMError("expected JSON object for wasm module")
    result: WasmModule = {
        "id": str(_first_of(module, "id") or ""),
        "moduleRef": str(_first_of(module, "module_ref", "moduleRef") or ""),
        "status": str(_first_of(module, "status") or ""),  # type: ignore[typeddict-item]
        "createdAt": str(_first_of(module, "created_at", "createdAt") or ""),
        "updatedAt": str(_first_of(module, "updated_at", "updatedAt") or ""),
        "hasWarm": bool(_first_of(module, "has_warm", "hasWarm") or False),
    }
    size = _first_of(module, "module_size_bytes", "moduleSizeBytes")
    if size is not None:
        result["moduleSizeBytes"] = int(size)
    digest = _first_of(module, "digest")
    if digest not in (None, ""):
        result["digest"] = str(digest)
    entrypoint = _first_of(module, "entrypoint")
    if entrypoint not in (None, ""):
        result["entrypoint"] = str(entrypoint)
    last_error = _first_of(module, "last_error", "lastError")
    if last_error not in (None, ""):
        result["lastError"] = str(last_error)
    ready_at = _first_of(module, "ready_at", "readyAt")
    if ready_at not in (None, ""):
        result["readyAt"] = str(ready_at)
    return result


def _from_api_sandbox_snapshot(snapshot: Dict[str, Any]) -> SandboxSnapshot:
    result: SandboxSnapshot = {
        "name": str(_first_of(snapshot, "name") or ""),
        "image": str(_first_of(snapshot, "image") or ""),
        "sourceSandboxID": str(_first_of(snapshot, "source_sandbox_id", "sourceSandboxID") or ""),
        "createdAt": str(_first_of(snapshot, "created_at", "createdAt") or ""),
    }
    image_id = _first_of(snapshot, "image_id", "imageID")
    if image_id not in (None, ""):
        result["imageID"] = str(image_id)
    entrypoint = _first_of(snapshot, "entrypoint")
    if isinstance(entrypoint, list):
        result["entrypoint"] = [str(item) for item in entrypoint]
    region_id = _first_of(snapshot, "region_id", "regionID")
    if region_id not in (None, ""):
        result["regionID"] = str(region_id)
    cpu = _first_of(snapshot, "cpu")
    if cpu is not None:
        result["cpu"] = float(cpu)
    gpu = _first_of(snapshot, "gpu")
    if gpu is not None:
        result["gpu"] = float(gpu)
    memory_mb = _first_of(snapshot, "memory_mb", "memoryMB")
    if memory_mb is not None:
        result["memoryMB"] = int(memory_mb)
    disk_gb = _first_of(snapshot, "disk_gb", "diskGB")
    if disk_gb is not None:
        result["diskGB"] = int(disk_gb)
    return result


def _from_api_expose_port_response(response: Dict[str, Any]) -> ExposeResult:
    protocol_raw = str(_first_of(response, "protocol") or "http")
    if protocol_raw not in ("http", "tcp", "tls"):
        protocol_raw = "http"
    protocol: ExposeProtocol = protocol_raw  # type: ignore[assignment]
    url = str(_first_of(response, "public_url", "publicURL") or "")
    if protocol == "tcp":
        host_raw = _first_of(response, "host")
        host_port_raw = _first_of(response, "host_port", "hostPort")
        return ExposeResult(
            protocol=protocol,
            url=url,
            host=str(host_raw) if host_raw is not None else None,
            host_port=int(host_port_raw) if host_port_raw is not None else None,
        )
    return ExposeResult(protocol=protocol, url=url)


def _to_api_mount_spec(mount: MountSpec) -> Dict[str, Any]:
    return _compact(
        {
            "type": _first_of(mount, "type"),
            "target": _first_of(mount, "target"),
            "source": _first_of(mount, "source"),
            "options": _first_of(mount, "options"),
            "credentials": _first_of(mount, "credentials"),
            "read_only": _first_of(mount, "readOnly", "read_only"),
        }
    )


def _to_api_platform_volume(volume: "PlatformVolumeMount") -> Dict[str, Any]:
    return _compact(
        {
            "name": _first_of(volume, "name"),
            "path": _first_of(volume, "path"),
            "read_only": _first_of(volume, "readOnly", "read_only"),
        }
    )


def _to_api_set_network_limits_options(options: SetNetworkLimitsOptions) -> Dict[str, Any]:
    # Omitted keys mean "leave unchanged" on the server. 0 means unlimited.
    return _compact(
        {
            "network_bytes_in_limit": _first_of(options, "networkBytesInLimit", "network_bytes_in_limit"),
            "network_bytes_out_limit": _first_of(options, "networkBytesOutLimit", "network_bytes_out_limit"),
        }
    )


_AUDIT_EVENT_FIELDS = (
    ("time", "time"),
    ("kind", "kind"),
    ("result", "result"),
    ("reason", "reason"),
    ("destination", "destination"),
    ("network", "network"),
    ("actor", "actor"),
    ("ref", "ref"),
    ("event_id", "eventID"),
    ("incarnation_id", "incarnationID"),
)


def _from_api_audit_page(payload: Dict[str, Any]) -> AuditPage:
    events: List[AuditEvent] = []
    for raw in payload.get("events") or []:
        event: AuditEvent = {}
        for api_key, key in _AUDIT_EVENT_FIELDS:
            value = raw.get(api_key)
            if value not in (None, ""):
                event[key] = str(value)  # type: ignore[literal-required]
        if raw.get("dropped"):
            event["dropped"] = int(raw["dropped"])
        events.append(event)
    coverage = payload.get("coverage") or {}
    page: AuditPage = {
        "events": events,
        "coverage": {
            "answered": list(coverage.get("answered") or []),
            "missing": list(coverage.get("missing") or []),
            "partial": bool(coverage.get("partial") or False),
        },
    }
    if payload.get("next_cursor"):
        page["nextCursor"] = str(payload["next_cursor"])
    return page


def _from_api_network_usage(payload: Dict[str, Any]) -> NetworkUsage:
    result: NetworkUsage = {
        "sandboxID": str(_first_of(payload, "sandbox_id", "sandboxID") or ""),
        "bytesIn": int(_first_of(payload, "bytes_in", "bytesIn") or 0),
        "bytesOut": int(_first_of(payload, "bytes_out", "bytesOut") or 0),
        "bytesInLimit": int(_first_of(payload, "bytes_in_limit", "bytesInLimit") or 0),
        "bytesOutLimit": int(_first_of(payload, "bytes_out_limit", "bytesOutLimit") or 0),
        "quotaExceeded": bool(_first_of(payload, "quota_exceeded", "quotaExceeded") or False),
    }
    quota_exceeded_at = _first_of(payload, "quota_exceeded_at", "quotaExceededAt")
    if quota_exceeded_at not in (None, ""):
        result["quotaExceededAt"] = str(quota_exceeded_at)
    last_sampled_at = _first_of(payload, "last_sampled_at", "lastSampledAt")
    if last_sampled_at not in (None, ""):
        result["lastSampledAt"] = str(last_sampled_at)
    return result


def _from_api_mount_spec_redacted(mount: Dict[str, Any]) -> MountSpecRedacted:
    result: MountSpecRedacted = {
        "type": str(_first_of(mount, "type") or "s3"),
        "target": str(_first_of(mount, "target") or ""),
        "source": str(_first_of(mount, "source") or ""),
        "readOnly": bool(_first_of(mount, "read_only", "readOnly") or False),
        "hasCredentials": bool(_first_of(mount, "has_credentials", "hasCredentials") or False),
    }
    options = _first_of(mount, "options")
    if isinstance(options, dict) and len(options) > 0:
        result["options"] = {str(key): str(value) for key, value in options.items()}
    return result


def _from_api_session(session: Dict[str, Any]) -> Session:
    result: Session = {
        "id": str(_first_of(session, "id") or ""),
        "name": str(_first_of(session, "name") or ""),
        "argv": [str(item) for item in (_first_of(session, "argv") or [])],
        "pty": bool(_first_of(session, "pty") or False),
        "status": str(_first_of(session, "status") or "running"),
        "exitCode": int(_first_of(session, "exit_code", "exitCode") or 0),
        "createdAt": str(_first_of(session, "created_at", "createdAt") or ""),
        "startedAt": str(_first_of(session, "started_at", "startedAt") or ""),
        "recording": bool(_first_of(session, "recording") or False),
        "bytes": int(_first_of(session, "bytes") or 0),
        "attached": int(_first_of(session, "attached") or 0),
    }

    work_dir = _first_of(session, "workdir", "workDir")
    if work_dir not in (None, ""):
        result["workDir"] = str(work_dir)
    exit_signal = _first_of(session, "exit_signal", "exitSignal")
    if exit_signal not in (None, ""):
        result["exitSignal"] = str(exit_signal)
    exited_at = _first_of(session, "exited_at", "exitedAt")
    if exited_at not in (None, ""):
        result["exitedAt"] = str(exited_at)
    return result


def _from_api_egress_profile(payload: Dict[str, Any]) -> EgressProfile:
    result: EgressProfile = {
        "name": str(payload.get("name") or ""),
        "allowOut": list(payload.get("allow_out") or []),
        "generation": int(payload.get("generation") or 0),
        "createdAt": str(payload.get("created_at") or ""),
        "updatedAt": str(payload.get("updated_at") or ""),
    }
    if payload.get("description"):
        result["description"] = str(payload["description"])
    return result


def _egress_rules(rules: Optional[List[Dict[str, Any]]], wire: bool = False) -> List[EgressRule]:
    # The wire and SDK keys are the same words except inject's secretRef
    # (secret_ref on the wire), so this drops unset keys, pins the types and
    # reads either spelling; wire picks the one it writes.
    result: List[EgressRule] = []
    for r in rules or []:
        rule: EgressRule = {"host": str(r.get("host") or "")}
        if r.get("ports"):
            rule["ports"] = [int(p) for p in r["ports"]]
        if r.get("methods"):
            rule["methods"] = [str(m) for m in r["methods"]]
        if r.get("paths"):
            rule["paths"] = [str(p) for p in r["paths"]]
        if r.get("inspect"):
            rule["inspect"] = True
        if r.get("binaries"):
            rule["binaries"] = [str(b) for b in r["binaries"]]
        inject = r.get("inject")
        if inject:
            ref = str(_first_of(inject, "secretRef", "secret_ref") or "")
            rule["inject"] = {"header": str(inject.get("header") or ""), ("secret_ref" if wire else "secretRef"): ref}  # type: ignore[typeddict-item]
        result.append(rule)
    return result


def _egress_rules_or_none(rules: Optional[List[Dict[str, Any]]]) -> Optional[List[EgressRule]]:
    return None if rules is None else _egress_rules(rules, wire=True)


def _from_api_sandbox(sandbox: Dict[str, Any]) -> SandboxData:
    exposed_ports = _first_of(sandbox, "exposed_ports", "exposedPorts") or []
    lifecycle = _first_of(sandbox, "lifecycle")
    failover = _first_of(sandbox, "failover")
    result: SandboxData = {
        "id": str(_first_of(sandbox, "id") or ""),
        "image": str(_first_of(sandbox, "image") or ""),
        "status": str(_first_of(sandbox, "status") or ""),
        "publicURL": str(_first_of(sandbox, "public_url", "publicURL") or ""),
        "cpu": float(_first_of(sandbox, "cpu") or 0),
        "memoryMB": int(_first_of(sandbox, "memory_mb", "memoryMB") or 0),
        "diskGB": int(_first_of(sandbox, "disk_gb", "diskGB") or 0),
        "osUser": str(_first_of(sandbox, "os_user", "osUser") or ""),
        "networkBlockAll": bool(_first_of(sandbox, "network_block_all", "networkBlockAll") or False),
        "toolboxEnabled": bool(_first_of(sandbox, "toolbox_enabled", "toolboxEnabled") or False),
        "exposedPorts": [_from_api_exposed_port(item) for item in exposed_ports],
        "createdAt": str(_first_of(sandbox, "created_at", "createdAt") or ""),
        "updatedAt": str(_first_of(sandbox, "updated_at", "updatedAt") or ""),
        "lastActiveAt": str(_first_of(sandbox, "last_active_at", "lastActiveAt") or ""),
        "lifecycle": _from_api_lifecycle(lifecycle) if isinstance(lifecycle, dict) else {},
    }
    if isinstance(failover, dict):
        mapped_failover = _from_api_failover(failover)
        if mapped_failover:
            result["failover"] = mapped_failover

    name = _first_of(sandbox, "name")
    if name not in (None, ""):
        result["name"] = str(name)
    tags = _first_of(sandbox, "tags")
    if isinstance(tags, dict) and len(tags) > 0:
        result["tags"] = {str(key): str(value) for key, value in tags.items()}
    container_id = _first_of(sandbox, "container_id", "containerID")
    if container_id not in (None, ""):
        result["containerID"] = str(container_id)
    container_ip = _first_of(sandbox, "container_ip", "containerIP")
    if container_ip not in (None, ""):
        result["containerIP"] = str(container_ip)
    egress_status = _first_of(sandbox, "egress_status", "egressStatus")
    if egress_status not in (None, ""):
        result["egressStatus"] = str(egress_status)
    egress_profiles = _first_of(sandbox, "egress_profiles", "egressProfiles")
    if egress_profiles:
        result["egressProfiles"] = [str(p) for p in egress_profiles]
    egress_mode = _first_of(sandbox, "network_egress_mode", "networkEgressMode")
    if egress_mode:
        result["networkEgressMode"] = str(egress_mode)
    egress_rules = _first_of(sandbox, "network_egress_rules", "networkEgressRules")
    if egress_rules:
        result["networkEgressRules"] = _egress_rules(egress_rules)
    applied = _first_of(sandbox, "egress_profiles_applied", "egressProfilesApplied")
    if applied:
        result["egressProfilesApplied"] = [{"name": str(r.get("name", "")), "generation": int(r.get("generation", 0))} for r in applied]
    env = _first_of(sandbox, "env")
    if isinstance(env, dict) and len(env) > 0:
        result["env"] = {str(key): str(value) for key, value in env.items()}
    ssh_public_key = _first_of(sandbox, "ssh_public_key", "sshPublicKey")
    if ssh_public_key not in (None, ""):
        result["sshPublicKey"] = str(ssh_public_key)
    ssh_private_key = _first_of(sandbox, "ssh_private_key", "sshPrivateKey")
    if ssh_private_key not in (None, ""):
        result["sshPrivateKey"] = str(ssh_private_key)
    last_error = _first_of(sandbox, "last_error", "lastError")
    if last_error not in (None, ""):
        result["lastError"] = str(last_error)
    container_command = _first_of(sandbox, "container_command", "containerCommand")
    if isinstance(container_command, list) and len(container_command) > 0:
        result["containerCommand"] = [str(item) for item in container_command]
    custom_domains = _first_of(sandbox, "custom_domains", "customDomains")
    if isinstance(custom_domains, list) and len(custom_domains) > 0:
        result["customDomains"] = [_from_api_custom_domain(item) for item in custom_domains if isinstance(item, dict)]
    runtime = _first_of(sandbox, "runtime")
    if runtime not in (None,):
        result["runtime"] = str(runtime)  # type: ignore[typeddict-item]
    durability = _first_of(sandbox, "durability")
    if durability not in (None, ""):
        result["durability"] = str(durability)  # type: ignore[typeddict-item]
    module_ref = _first_of(sandbox, "module_ref", "moduleRef")
    if module_ref not in (None, ""):
        result["module_ref"] = str(module_ref)
    module_digest = _first_of(sandbox, "module_digest", "moduleDigest")
    if module_digest not in (None, ""):
        result["module_digest"] = str(module_digest)
    tenant_id = _first_of(sandbox, "tenant_id", "tenantId")
    if tenant_id not in (None, ""):
        result["tenant_id"] = str(tenant_id)
    return result


def _from_api_lifecycle(lifecycle: Dict[str, Any]) -> Lifecycle:
    result: Lifecycle = {}

    stop_if_idle_for = _first_of(lifecycle, "stop_if_idle_for", "stopIfIdleFor")
    if stop_if_idle_for is not None:
        result["stopIfIdleFor"] = int(stop_if_idle_for)

    destroy_if_idle_for = _first_of(lifecycle, "destroy_if_idle_for", "destroyIfIdleFor")
    if destroy_if_idle_for is not None:
        result["destroyIfIdleFor"] = int(destroy_if_idle_for)

    stop_at_age = _first_of(lifecycle, "stop_at_age", "stopAtAge")
    if stop_at_age is not None:
        result["stopAtAge"] = int(stop_at_age)

    destroy_at_age = _first_of(lifecycle, "destroy_at_age", "destroyAtAge")
    if destroy_at_age is not None:
        result["destroyAtAge"] = int(destroy_at_age)

    serverless = _first_of(lifecycle, "serverless")
    if serverless:
        result["serverless"] = True

    return result


def _from_api_failover(failover: Dict[str, Any]) -> Failover:
    policy = _first_of(failover, "policy")
    if policy not in ("none", "recreate"):
        return {}
    return {"policy": policy}


def _from_api_health_status(status: Dict[str, Any]) -> HealthStatus:
    return {
        "status": str(_first_of(status, "status") or ""),
        "sandboxes": int(_first_of(status, "sandboxes") or 0),
        "docker": str(_first_of(status, "docker") or ""),
        "caddy": str(_first_of(status, "caddy") or ""),
        "sshGateway": str(_first_of(status, "ssh_gateway", "sshGateway") or ""),
        "version": str(_first_of(status, "version") or ""),
    }
