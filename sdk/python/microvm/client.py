from __future__ import annotations

import importlib
import json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from io import BytesIO
from typing import Any, Dict, List, Optional

from ._internal.api.v1.paths import PATH_PREFIX as _V1_PATH_PREFIX
from .image import Image
from .types import (
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
    ExposeResult,
    Failover,
    HealthStatus,
    IngressTarget,
    Lifecycle,
    MicroVMConfig,
    MountSpec,
    MountSpecRedacted,
    NetworkUsage,
    RegisterSnapshotOptions,
    ResizeOptions,
    RetryConfig,
    SandboxData,
    SandboxSnapshot,
    Session,
    SessionAttachOptions,
    SetNetworkLimitsOptions,
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


def _normalize_url(value: str) -> str:
    return value.rstrip("/")


def _read_env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else None


class MicroVMError(Exception):
    pass


class MicroVMHTTPError(MicroVMError):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


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

    def exec(self, request: ExecRequest) -> ExecResult:
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

    def create_snapshot(self, name: str) -> SandboxSnapshot:
        return self._client.create_snapshot(self.id, name)

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

    @property
    def id(self) -> str:
        return str(self._data.get("id", ""))

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"Sandbox object has no attribute {name}")


class MicroVM:
    default_api_url = "http://127.0.0.1:21212"
    auth_required_error_message = "PAT token is required. Set pat_token or SB_PAT_TOKEN."

    def __init__(
        self,
        api_url: Optional[str] = None,
        pat_token: Optional[str] = None,
        *,
        api_version: str = _DEFAULT_API_VERSION,
        config: Optional[MicroVMConfig] = None,
    ) -> None:
        if config is not None:
            api_url = api_url or config.get("apiUrl")
            pat_token = pat_token or config.get("patToken")
        
        self.api_url = _normalize_url(api_url or _read_env("SB_API_URL") or self.default_api_url)
        self.pat_token = pat_token or _read_env("SB_PAT_TOKEN") or ""

        retry_cfg: RetryConfig = config.get("retry", {}) if config else {}
        self._retry_config = {
            "maxRetries": retry_cfg.get("maxRetries", 3),
            "baseDelayMs": retry_cfg.get("baseDelayMs", 200),
            "maxDelayMs": retry_cfg.get("maxDelayMs", 5000),
        }

        if not self.pat_token:
            raise MicroVMError(self.auth_required_error_message)

        if api_version not in _PATH_PREFIXES:
            raise MicroVMError(f"unsupported api_version {api_version!r}; supported: {sorted(_PATH_PREFIXES)}")
        self.api_version = api_version
        self._version_prefix = _PATH_PREFIXES[api_version]

    def _versioned(self, suffix: str) -> str:
        """Build a versioned API path. Pass the suffix beginning with "/" (e.g.
        ``"/sandboxes"``) and the active version's prefix is prepended. Use
        this for every versioned call so a future wire version is selected by
        the ``api_version`` option without touching call sites.
        """
        return f"{self._version_prefix}{suffix}"

    def create(self, options: CreateOptions) -> Sandbox:
        resolved_options = dict(options)
        resolved_options["image"] = self._resolve_image(_first_of(options, "image"))
        sandbox = self._do_json("POST", self._versioned("/sandboxes"), _to_api_create_options(resolved_options))
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

    def list(self, *, tags: Optional[Dict[str, str]] = None) -> List[Sandbox]:
        path = self._versioned("/sandboxes") + _build_tag_query(tags)
        sandboxes = self._do_json("GET", path, None)
        return [self._wrap_sandbox(item) for item in sandboxes]

    def get(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("GET", f"{self._version_prefix}/sandboxes/{sandbox_id}", None)
        return self._wrap_sandbox(sandbox)

    def start(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/start", None)
        return self._wrap_sandbox(sandbox)

    def stop(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/stop", None)
        return self._wrap_sandbox(sandbox)

    def create_snapshot(self, sandbox_id: str, name: str) -> SandboxSnapshot:
        response = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/snapshot", {"name": name})
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

    def set_network_limits(self, sandbox_id: str, options: SetNetworkLimitsOptions) -> NetworkUsage:
        body = _to_api_set_network_limits_options(options)
        payload = self._do_json("PATCH", f"{self._version_prefix}/sandboxes/{sandbox_id}/network/limits", body)
        return _from_api_network_usage(payload)

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        response = self._do_json("POST", f"{self._version_prefix}/sandboxes/{sandbox_id}/toolbox/process/execute", _to_api_exec_request(request))
        return _from_api_exec_result(response)

    def exec_stream(self, sandbox_id: str, options: ExecStreamOptions) -> ExecStreamHandle:
        command = _first_of(options, "command")
        if not isinstance(command, str) or command.strip() == "":
            raise MicroVMError("command is required")

        websocket_module = _load_websocket_module()
        ws_url = _to_websocket_url(self.api_url, f"{self._version_prefix}/sandboxes/{urllib.parse.quote(sandbox_id, safe='')}/toolbox/process/exec/stream")
        ws = _connect_websocket(websocket_module, ws_url, self.pat_token, "exec stream")
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
        ws = _connect_websocket(websocket_module, ws_url, self.pat_token, "session attach")

        cols = _first_of(attach_options, "cols")
        rows = _first_of(attach_options, "rows")
        if isinstance(cols, int) and isinstance(rows, int) and cols > 0 and rows > 0:
            ws.send(json.dumps({"type": "resize", "cols": cols, "rows": rows}))

        return SessionAttachHandle(websocket_module, ws, attach_options)

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

    def _request(self, method: str, url: str, body: Optional[bytes] = None, content_type: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None) -> bytes:
        max_retries = self._retry_config["maxRetries"]
        base_delay_ms = self._retry_config["baseDelayMs"]
        max_delay_ms = self._retry_config["maxDelayMs"]

        last_exc: Optional[Exception] = None

        for attempt in range(max_retries + 1):
            request = urllib.request.Request(url, data=body, method=method)
            request.add_header("Authorization", f"Bearer {self.pat_token}")
            if content_type is not None:
                request.add_header("Content-Type", content_type)
            for header_key, header_val in (extra_headers or {}).items():
                request.add_header(header_key, header_val)

            try:
                with urllib.request.urlopen(request) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code in (429, 502, 503, 504) and attempt < max_retries:
                    pass # Handled by the retry logic below
                else:
                    payload = exc.read()
                    try:
                        data = json.loads(payload.decode("utf-8"))
                        raise MicroVMHTTPError(exc.code, str(data.get("error", exc.reason))) from exc
                    except (ValueError, TypeError):
                        raise MicroVMHTTPError(exc.code, str(exc.reason)) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                if attempt >= max_retries:
                    raise
            except Exception as exc:
                last_exc = exc
                if attempt >= max_retries:
                    raise
            
            # Compute delay with exponential backoff and jitter
            delay_ms = min(base_delay_ms * (2 ** attempt), max_delay_ms)
            jitter = 1.0 + (random.random() - 0.5) * 0.5
            time.sleep((delay_ms * jitter) / 1000.0)

        assert last_exc is not None
        raise last_exc

    def _do_json(self, method: str, path: str, payload: Optional[Dict[str, Any]]) -> Any:
        body = None
        content_type = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            content_type = "application/json"
        raw = self._request(method, self._url(path), body, content_type)
        if raw == b"":
            return {}
        return json.loads(raw.decode("utf-8"))

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


def _load_websocket_module() -> Any:
    return importlib.import_module("websocket")


def _connect_websocket(websocket_module: Any, ws_url: str, pat_token: str, label: str) -> Any:
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
            header=[f"Authorization: Bearer {pat_token}"],
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


def _to_websocket_url(base_url: str, path: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    scheme = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}.get(parsed.scheme)
    if scheme is None:
        raise MicroVMError(f"unsupported API URL scheme: {parsed.scheme}")
    return urllib.parse.urlunparse((scheme, parsed.netloc, path, "", "", ""))


def _first_of(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _compact(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


def _build_tag_query(tags: Optional[Dict[str, str]]) -> str:
    # Renders the tag filter as the server's `?tag.<key>=<value>` wire format.
    # The `tag.` prefix is literal — the server's parseTagFilter inspects the
    # decoded query key — so only the user-supplied key and value get
    # percent-encoded. An empty or missing map returns "" so the request URL is
    # byte-identical to the pre-filter call (no stray trailing "?").
    if not tags:
        return ""
    parts = [
        f"tag.{urllib.parse.quote(str(key), safe='')}={urllib.parse.quote(str(value), safe='')}"
        for key, value in tags.items()
    ]
    return "?" + "&".join(parts)


def _to_api_create_options(options: CreateOptions) -> Dict[str, Any]:
    lifecycle = _first_of(options, "lifecycle")
    failover = _first_of(options, "failover")
    return _compact(
        {
            "image": _first_of(options, "image"),
            "cpu": _first_of(options, "cpu"),
            "memory_mb": _first_of(options, "memoryMB", "memory_mb"),
            "disk_gb": _first_of(options, "diskGB", "disk_gb"),
            "env": _first_of(options, "env"),
            "os_user": _first_of(options, "osUser", "os_user"),
            "network_block_all": _first_of(options, "networkBlockAll", "network_block_all"),
            "network_allow_out": _first_of(options, "networkAllowOut", "network_allow_out"),
            "network_deny_out": _first_of(options, "networkDenyOut", "network_deny_out"),
            "allow_public_traffic": _first_of(options, "allowPublicTraffic", "allow_public_traffic"),
            "network_bytes_in_limit": _first_of(options, "networkBytesInLimit", "network_bytes_in_limit"),
            "network_bytes_out_limit": _first_of(options, "networkBytesOutLimit", "network_bytes_out_limit"),
            "registry": _first_of(options, "registry"),
            "container_command": _first_of(options, "containerCommand", "container_command"),
            "mounts": [_to_api_mount_spec(item) for item in (_first_of(options, "mounts") or [])],
            "lifecycle": _to_api_lifecycle(lifecycle) if isinstance(lifecycle, dict) else None,
            "failover": _to_api_failover(failover) if isinstance(failover, dict) else None,
            "custom_domains": _first_of(options, "customDomains", "custom_domains"),
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
            "workdir": _first_of(request, "workDir", "workdir"),
            "env": _first_of(request, "env"),
            "timeout_seconds": _first_of(request, "timeoutSeconds", "timeout_seconds"),
        }
    )


def _to_api_exec_stream_request(options: ExecStreamOptions) -> Dict[str, Any]:
    return _compact(
        {
            "command": _first_of(options, "command"),
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


def _to_api_set_network_limits_options(options: SetNetworkLimitsOptions) -> Dict[str, Any]:
    # Omitted keys mean "leave unchanged" on the server. 0 means unlimited.
    return _compact(
        {
            "network_bytes_in_limit": _first_of(options, "networkBytesInLimit", "network_bytes_in_limit"),
            "network_bytes_out_limit": _first_of(options, "networkBytesOutLimit", "network_bytes_out_limit"),
        }
    )


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

    container_id = _first_of(sandbox, "container_id", "containerID")
    if container_id not in (None, ""):
        result["containerID"] = str(container_id)
    container_ip = _first_of(sandbox, "container_ip", "containerIP")
    if container_ip not in (None, ""):
        result["containerIP"] = str(container_ip)
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
