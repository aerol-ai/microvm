from __future__ import annotations

import importlib
import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from io import BytesIO
from typing import Any, Dict, List, Optional

from .types import (
    CreateOptions,
    ExecExitInfo,
    ExecRequest,
    ExecResult,
    ExecStreamOptions,
    HealthStatus,
    ResizeOptions,
    SandboxData,
)

STREAM_PREFIX_STDOUT = 0x01
STREAM_PREFIX_STDERR = 0x02


def _normalize_url(value: str) -> str:
    return value.rstrip("/")


def _read_env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else None


class MicroVMError(Exception):
    pass


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

    def exec_stream(self, options: ExecStreamOptions) -> ExecStreamHandle:
        return self._client.exec_stream(self.id, options)

    def upload_file(self, target_path: str, data: bytes) -> None:
        self._client.upload_file(self.id, target_path, data)

    def download_file(self, target_path: str) -> bytes:
        return self._client.download_file(self.id, target_path)

    def expose_port(self, port: int) -> str:
        return self._client.expose_port(self.id, port)

    def unexpose_port(self, port: int) -> None:
        self._client.unexpose_port(self.id, port)

    def start(self) -> "Sandbox":
        updated = self._client.start(self.id)
        self._data = updated.to_dict()
        return self

    def stop(self) -> "Sandbox":
        updated = self._client.stop(self.id)
        self._data = updated.to_dict()
        return self

    def destroy(self) -> None:
        self._client.destroy(self.id)

    def resize(self, options: ResizeOptions) -> "Sandbox":
        updated = self._client.resize(self.id, options)
        self._data = updated.to_dict()
        return self

    @property
    def id(self) -> str:
        return str(self._data.get("id", ""))

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"Sandbox object has no attribute {name}")


class MicroVM:
    default_api_url = "http://127.0.0.1:8080"
    auth_required_error_message = "PAT token is required. Set pat_token or SB_PAT_TOKEN."

    def __init__(self, api_url: Optional[str] = None, pat_token: Optional[str] = None) -> None:
        self.api_url = _normalize_url(api_url or _read_env("SB_API_URL") or self.default_api_url)
        self.pat_token = pat_token or _read_env("SB_PAT_TOKEN") or ""

        if not self.pat_token:
            raise MicroVMError(self.auth_required_error_message)

    def create(self, options: CreateOptions) -> Sandbox:
        sandbox = self._do_json("POST", "/v1/sandboxes", _to_api_create_options(options))
        return self._wrap_sandbox(sandbox)

    def list(self) -> List[Sandbox]:
        sandboxes = self._do_json("GET", "/v1/sandboxes", None)
        return [self._wrap_sandbox(item) for item in sandboxes]

    def get(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("GET", f"/v1/sandboxes/{sandbox_id}", None)
        return self._wrap_sandbox(sandbox)

    def start(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/start", None)
        return self._wrap_sandbox(sandbox)

    def stop(self, sandbox_id: str) -> Sandbox:
        sandbox = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/stop", None)
        return self._wrap_sandbox(sandbox)

    def destroy(self, sandbox_id: str) -> None:
        self._do_json("DELETE", f"/v1/sandboxes/{sandbox_id}", None)

    def resize(self, sandbox_id: str, options: ResizeOptions) -> Sandbox:
        sandbox = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/resize", _to_api_resize_options(options))
        return self._wrap_sandbox(sandbox)

    def health(self) -> HealthStatus:
        return _from_api_health_status(self._do_json("GET", "/health", None))

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        response = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/toolbox/process/execute", _to_api_exec_request(request))
        return _from_api_exec_result(response)

    def exec_stream(self, sandbox_id: str, options: ExecStreamOptions) -> ExecStreamHandle:
        command = _first_of(options, "command")
        if not isinstance(command, str) or command.strip() == "":
            raise MicroVMError("command is required")

        websocket_module = _load_websocket_module()
        ws = websocket_module.create_connection(
            _to_websocket_url(self.api_url, f"/v1/sandboxes/{urllib.parse.quote(sandbox_id, safe='')}/toolbox/process/exec/stream"),
            header=[f"Authorization: Bearer {self.pat_token}"],
            enable_multithread=True,
        )
        ws.send(json.dumps(_to_api_exec_stream_request(options)))
        return ExecStreamHandle(websocket_module, ws, options)

    def upload_file(self, sandbox_id: str, target_path: str, data: bytes) -> None:
        self._do_multipart(
            f"/v1/sandboxes/{sandbox_id}/toolbox/files/upload",
            {"path": target_path},
            "file",
            target_path,
            data,
        )

    def download_file(self, sandbox_id: str, target_path: str) -> bytes:
        url = self._url(f"/v1/sandboxes/{sandbox_id}/toolbox/files/download?path={urllib.parse.quote(target_path, safe='')}")
        return self._request("GET", url)

    def expose_port(self, sandbox_id: str, port: int) -> str:
        response = self._do_json("POST", f"/v1/sandboxes/{sandbox_id}/ports/{port}", None)
        return str(_first_of(response, "public_url", "publicURL") or "")

    def unexpose_port(self, sandbox_id: str, port: int) -> None:
        self._do_json("DELETE", f"/v1/sandboxes/{sandbox_id}/ports/{port}", None)

    def _wrap_sandbox(self, response: Dict[str, Any]) -> Sandbox:
        return Sandbox(self, _from_api_sandbox(response))

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def _request(self, method: str, url: str, body: Optional[bytes] = None, content_type: Optional[str] = None) -> bytes:
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", f"Bearer {self.pat_token}")
        if content_type is not None:
            request.add_header("Content-Type", content_type)

        try:
            with urllib.request.urlopen(request) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                data = json.loads(payload.decode("utf-8"))
                raise MicroVMError(str(data.get("error", exc.reason))) from exc
            except (ValueError, TypeError):
                raise MicroVMError(exc.reason) from exc

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


def _to_api_create_options(options: CreateOptions) -> Dict[str, Any]:
    return _compact(
        {
            "image": _first_of(options, "image"),
            "cpu": _first_of(options, "cpu"),
            "memory_mb": _first_of(options, "memoryMB", "memory_mb"),
            "disk_gb": _first_of(options, "diskGB", "disk_gb"),
            "env": _first_of(options, "env"),
            "os_user": _first_of(options, "osUser", "os_user"),
            "network_block_all": _first_of(options, "networkBlockAll", "network_block_all"),
            "registry": _first_of(options, "registry"),
            "container_command": _first_of(options, "containerCommand", "container_command"),
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


def _from_api_exec_result(result: Dict[str, Any]) -> ExecResult:
    return {
        "stdout": str(_first_of(result, "stdout") or ""),
        "stderr": str(_first_of(result, "stderr") or ""),
        "exitCode": int(_first_of(result, "exit_code", "exitCode") or 0),
        "durationMS": int(_first_of(result, "duration_ms", "durationMS") or 0),
    }


def _from_api_exposed_port(port: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sandboxID": str(_first_of(port, "sandbox_id", "sandboxID") or ""),
        "port": int(_first_of(port, "port") or 0),
        "publicURL": str(_first_of(port, "public_url", "publicURL") or ""),
        "createdAt": str(_first_of(port, "created_at", "createdAt") or ""),
    }


def _from_api_sandbox(sandbox: Dict[str, Any]) -> SandboxData:
    exposed_ports = _first_of(sandbox, "exposed_ports", "exposedPorts") or []
    result: SandboxData = {
        "id": str(_first_of(sandbox, "id") or ""),
        "image": str(_first_of(sandbox, "image") or ""),
        "status": str(_first_of(sandbox, "status") or ""),
        "publicURL": str(_first_of(sandbox, "public_url", "publicURL") or ""),
        "cpu": int(_first_of(sandbox, "cpu") or 0),
        "memoryMB": int(_first_of(sandbox, "memory_mb", "memoryMB") or 0),
        "diskGB": int(_first_of(sandbox, "disk_gb", "diskGB") or 0),
        "osUser": str(_first_of(sandbox, "os_user", "osUser") or ""),
        "networkBlockAll": bool(_first_of(sandbox, "network_block_all", "networkBlockAll") or False),
        "toolboxEnabled": bool(_first_of(sandbox, "toolbox_enabled", "toolboxEnabled") or False),
        "exposedPorts": [_from_api_exposed_port(item) for item in exposed_ports],
        "createdAt": str(_first_of(sandbox, "created_at", "createdAt") or ""),
        "updatedAt": str(_first_of(sandbox, "updated_at", "updatedAt") or ""),
        "lastActiveAt": str(_first_of(sandbox, "last_active_at", "lastActiveAt") or ""),
    }

    container_id = _first_of(sandbox, "container_id", "containerID")
    if container_id not in (None, ""):
        result["containerID"] = str(container_id)
    container_ip = _first_of(sandbox, "container_ip", "containerIP")
    if container_ip not in (None, ""):
        result["containerIP"] = str(container_ip)
    env = _first_of(sandbox, "env")
    if isinstance(env, dict) and len(env) > 0:
        result["env"] = {str(key): str(value) for key, value in env.items()}
    last_error = _first_of(sandbox, "last_error", "lastError")
    if last_error not in (None, ""):
        result["lastError"] = str(last_error)
    container_command = _first_of(sandbox, "container_command", "containerCommand")
    if isinstance(container_command, list) and len(container_command) > 0:
        result["containerCommand"] = [str(item) for item in container_command]
    return result


def _from_api_health_status(status: Dict[str, Any]) -> HealthStatus:
    return {
        "status": str(_first_of(status, "status") or ""),
        "sandboxes": int(_first_of(status, "sandboxes") or 0),
        "docker": str(_first_of(status, "docker") or ""),
        "caddy": str(_first_of(status, "caddy") or ""),
        "version": str(_first_of(status, "version") or ""),
    }
