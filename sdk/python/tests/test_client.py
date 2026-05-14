import json
import unittest

from microvm import client as client_module
from microvm.client import MicroVM


class RecordingMicroVM(MicroVM):
    def __init__(self) -> None:
        super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")
        self.calls = []
        self.raw_calls = []

    def _do_json(self, method, path, payload):  # type: ignore[override]
        self.calls.append((method, path, payload))
        if method == "POST" and path == "/v1/sandboxes":
            return {
                "id": "sb-1",
                "image": "ubuntu:22.04",
                "status": "started",
                "public_url": "https://sb-1.example.com",
                "cpu": 2,
                "memory_mb": 2048,
                "disk_gb": 20,
                "os_user": "root",
                "network_block_all": True,
                "toolbox_enabled": True,
                "ssh_public_key": "ssh-ed25519 AAAA sandbox",
                "ssh_private_key": "PRIVATE",
                "exposed_ports": [],
                "created_at": "2026-05-07T10:00:00Z",
                "updated_at": "2026-05-07T10:00:00Z",
                "last_active_at": "2026-05-07T10:00:00Z",
                "lifecycle": payload.get("lifecycle", {}),
            }
        if method == "PUT" and path == "/v1/sandboxes/sb-1/lifecycle":
            return {
                "id": "sb-1",
                "image": "ubuntu:22.04",
                "status": "started",
                "public_url": "https://sb-1.example.com",
                "cpu": 2,
                "memory_mb": 2048,
                "disk_gb": 20,
                "os_user": "root",
                "network_block_all": True,
                "toolbox_enabled": True,
                "ssh_public_key": "ssh-ed25519 AAAA sandbox",
                "exposed_ports": [],
                "created_at": "2026-05-07T10:00:00Z",
                "updated_at": "2026-05-07T11:00:00Z",
                "last_active_at": "2026-05-07T10:30:00Z",
                "lifecycle": payload,
            }
        if method == "POST" and path == "/v1/sandboxes/sb-1/snapshot":
            return {
                "name": payload.get("name", "snapshots/default:v1"),
                "image": payload.get("name", "snapshots/default:v1"),
                "image_id": "sha256:snap-1",
                "source_sandbox_id": "sb-1",
                "created_at": "2026-05-14T10:00:00Z",
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/mounts":
            return {
                "mounts": [
                    {
                        "type": "s3",
                        "target": "/workspace",
                        "source": "s3://bucket/prefix",
                        "options": {"region": "us-east-1"},
                        "read_only": True,
                        "has_credentials": True,
                    }
                ]
            }
        if method == "POST" and path == "/v1/sandboxes/sb-1/sessions":
            return {
                "id": "ses-1",
                "name": payload.get("name", "default"),
                "argv": payload.get("argv") or ["sh", "-c", payload.get("command", "")],
                "workdir": payload.get("workdir"),
                "pty": bool(payload.get("pty", False)),
                "status": "running",
                "exit_code": 0,
                "created_at": "2026-05-07T10:05:00Z",
                "started_at": "2026-05-07T10:05:01Z",
                "recording": True,
                "bytes": 0,
                "attached": 1,
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions":
            return {
                "sessions": [
                    {
                        "id": "ses-1",
                        "name": "default",
                        "argv": ["bash"],
                        "pty": True,
                        "status": "running",
                        "exit_code": 0,
                        "created_at": "2026-05-07T10:05:00Z",
                        "started_at": "2026-05-07T10:05:01Z",
                        "recording": True,
                        "bytes": 12,
                        "attached": 1,
                    }
                ]
            }
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions/ses-1":
            return {
                "id": "ses-1",
                "name": "default",
                "argv": ["bash"],
                "workdir": "/workspace",
                "pty": True,
                "status": "running",
                "exit_code": 0,
                "created_at": "2026-05-07T10:05:00Z",
                "started_at": "2026-05-07T10:05:01Z",
                "recording": True,
                "bytes": 99,
                "attached": 2,
            }
        if method == "POST" and path == "/v1/sandboxes/sb-1/sessions/ses-1/signal":
            return {}
        if method == "POST" and path == "/v1/sandboxes/sb-1/sessions/ses-1/resize":
            return {}
        if method == "DELETE" and path == "/v1/sandboxes/sb-1/sessions/ses-1":
            return {}
        if method == "POST" and path.endswith("/process/execute"):
            return {
                "stdout": "ok",
                "stderr": "",
                "exit_code": 0,
                "duration_ms": 5,
            }
        if method == "GET" and path == "/health":
            return {
                "status": "ok",
                "sandboxes": 1,
                "docker": "ok",
                "caddy": "ok",
                "ssh_gateway": "disabled",
                "version": "dev",
            }
        raise AssertionError(f"unexpected call: {method} {path} {payload}")

    def _request(self, method, url, body=None, content_type=None):  # type: ignore[override]
        path = url.replace(self.api_url, "")
        self.raw_calls.append((method, path, body, content_type))
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions/ses-1/log":
            return b"session log"
        if method == "GET" and path == "/v1/sandboxes/sb-1/sessions/ses-1/recording":
            return b'{"version":2}'
        raise AssertionError(f"unexpected raw call: {method} {path}")


class FakeABNF:
    OPCODE_BINARY = 2


class FakeWebSocket:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []
        self.closed = False

    def send(self, payload, opcode=None):
        self.sent.append((payload, opcode))

    def recv(self):
        if not self.responses:
            raise RuntimeError("socket exhausted")
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class FakeWebSocketModule:
    ABNF = FakeABNF

    def __init__(self, ws):
        self.ws = ws
        self.calls = []

    def create_connection(self, url, header, enable_multithread):
        self.calls.append((url, header, enable_multithread))
        return self.ws


class ClientTests(unittest.TestCase):
    def test_create_maps_request_and_response_shapes(self):
        client = RecordingMicroVM()
        sandbox = client.create(
            {
                "image": "ubuntu:22.04",
                "memoryMB": 2048,
                "diskGB": 20,
                "networkBlockAll": True,
                "containerCommand": ["bash", "-lc", "echo hi"],
                "mounts": [
                    {
                        "type": "s3",
                        "target": "/workspace",
                        "source": "s3://bucket/prefix",
                        "options": {"region": "us-east-1"},
                        "credentials": {"access_key_id": "AKIA", "secret_access_key": "SECRET"},
                        "readOnly": True,
                    }
                ],
                "lifecycle": {
                    "stopIfIdleFor": 3_600_000_000_000,
                    "destroyAtAge": 86_400_000_000_000,
                },
            }
        )

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes",
                {
                    "image": "ubuntu:22.04",
                    "memory_mb": 2048,
                    "disk_gb": 20,
                    "network_block_all": True,
                    "container_command": ["bash", "-lc", "echo hi"],
                    "mounts": [
                        {
                            "type": "s3",
                            "target": "/workspace",
                            "source": "s3://bucket/prefix",
                            "options": {"region": "us-east-1"},
                            "credentials": {"access_key_id": "AKIA", "secret_access_key": "SECRET"},
                            "read_only": True,
                        }
                    ],
                    "lifecycle": {
                        "stop_if_idle_for": 3_600_000_000_000,
                        "destroy_at_age": 86_400_000_000_000,
                    },
                },
            ),
        )
        self.assertEqual(sandbox.publicURL, "https://sb-1.example.com")
        self.assertEqual(sandbox.memoryMB, 2048)
        self.assertTrue(sandbox.networkBlockAll)
        self.assertEqual(sandbox.sshPublicKey, "ssh-ed25519 AAAA sandbox")
        self.assertEqual(sandbox.sshPrivateKey, "PRIVATE")
        self.assertEqual(
            sandbox.lifecycle,
            {
                "stopIfIdleFor": 3_600_000_000_000,
                "destroyAtAge": 86_400_000_000_000,
            },
        )

    def test_update_lifecycle_maps_request_and_updates_sandbox_state(self):
        client = RecordingMicroVM()

        sandbox = client.create({"image": "ubuntu:22.04"})
        updated = client.update_lifecycle(
            "sb-1",
            {
                "stopIfIdleFor": 7_200_000_000_000,
                "destroyAtAge": 172_800_000_000_000,
            },
        )
        sandbox.update_lifecycle(
            {
                "stopIfIdleFor": 10_800_000_000_000,
                "destroyIfIdleFor": 14_400_000_000_000,
            }
        )

        self.assertEqual(
            client.calls[1],
            (
                "PUT",
                "/v1/sandboxes/sb-1/lifecycle",
                {
                    "stop_if_idle_for": 7_200_000_000_000,
                    "destroy_at_age": 172_800_000_000_000,
                },
            ),
        )
        self.assertEqual(
            client.calls[2],
            (
                "PUT",
                "/v1/sandboxes/sb-1/lifecycle",
                {
                    "stop_if_idle_for": 10_800_000_000_000,
                    "destroy_if_idle_for": 14_400_000_000_000,
                },
            ),
        )
        self.assertEqual(
            updated.lifecycle,
            {
                "stopIfIdleFor": 7_200_000_000_000,
                "destroyAtAge": 172_800_000_000_000,
            },
        )
        self.assertEqual(
            sandbox.lifecycle,
            {
                "stopIfIdleFor": 10_800_000_000_000,
                "destroyIfIdleFor": 14_400_000_000_000,
            },
        )

    def test_create_snapshot_maps_request_and_response_shapes(self):
        client = RecordingMicroVM()
        snapshot = client.create_snapshot("sb-1", "snapshots/demo:v1")
        sandbox = client.create({"image": "ubuntu:22.04"})
        sandbox_snapshot = sandbox.create_snapshot("snapshots/from-sandbox:v1")

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes/sb-1/snapshot",
                {"name": "snapshots/demo:v1"},
            ),
        )
        self.assertEqual(snapshot["imageID"], "sha256:snap-1")
        self.assertEqual(snapshot["sourceSandboxID"], "sb-1")
        self.assertEqual(sandbox_snapshot["name"], "snapshots/from-sandbox:v1")

    def test_exec_and_health_map_api_shapes(self):
        client = RecordingMicroVM()

        result = client.exec("sb-1", {"command": "echo ok", "workDir": "/workspace", "timeoutSeconds": 2})
        health = client.health()

        self.assertEqual(
            client.calls[0],
            (
                "POST",
                "/v1/sandboxes/sb-1/toolbox/process/execute",
                {"command": "echo ok", "workdir": "/workspace", "timeout_seconds": 2},
            ),
        )
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["durationMS"], 5)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["sshGateway"], "disabled")

    def test_mounts_maps_redacted_mount_shapes(self):
        client = RecordingMicroVM()

        mounts = client.mounts("sb-1")

        self.assertEqual(client.calls[0], ("GET", "/v1/sandboxes/sb-1/mounts", None))
        self.assertEqual(
            mounts,
            [
                {
                    "type": "s3",
                    "target": "/workspace",
                    "source": "s3://bucket/prefix",
                    "options": {"region": "us-east-1"},
                    "readOnly": True,
                    "hasCredentials": True,
                }
            ],
        )

    def test_exec_stream_sends_handshake_and_control_frames(self):
        stdout_chunks = []
        stderr_chunks = []
        errors = []
        fake_ws = FakeWebSocket(
            [
                bytes([1]) + b"hello",
                bytes([2]) + b"warn",
                json.dumps({"type": "exit", "code": 0}),
            ]
        )
        fake_module = FakeWebSocketModule(fake_ws)
        original_loader = client_module._load_websocket_module
        client_module._load_websocket_module = lambda: fake_module
        try:
            client = RecordingMicroVM()
            handle = client.exec_stream(
                "sb-1",
                {
                    "command": "bash",
                    "tty": True,
                    "cols": 120,
                    "rows": 40,
                    "onStdout": stdout_chunks.append,
                    "onStderr": stderr_chunks.append,
                    "onError": errors.append,
                },
            )

            handle.write("pwd\n")
            handle.resize(120, 40)
            handle.signal("INT")
            result = handle.wait(1)

            self.assertEqual(result["code"], 0)
            self.assertEqual(stdout_chunks, [b"hello"])
            self.assertEqual(stderr_chunks, [b"warn"])
            self.assertEqual(errors, [])
            self.assertEqual(fake_module.calls[0][0], "wss://sandbox.example.com/v1/sandboxes/sb-1/toolbox/process/exec/stream")
            self.assertEqual(fake_module.calls[0][1], ["Authorization: Bearer pat-token"])
            self.assertTrue(fake_module.calls[0][2])
            self.assertEqual(json.loads(fake_ws.sent[0][0]), {"command": "bash", "tty": True, "cols": 120, "rows": 40})
            self.assertEqual(fake_ws.sent[1], (b"pwd\n", 2))
            self.assertEqual(json.loads(fake_ws.sent[2][0]), {"type": "resize", "cols": 120, "rows": 40})
            self.assertEqual(json.loads(fake_ws.sent[3][0]), {"type": "signal", "signal": "INT"})
        finally:
            client_module._load_websocket_module = original_loader

    def test_session_methods_map_api_shapes(self):
        client = RecordingMicroVM()
        sandbox = client.create({"image": "ubuntu:22.04"})

        created = sandbox.create_session(
            {"name": "default", "command": "bash", "workDir": "/workspace", "pty": True, "cols": 120, "rows": 40}
        )
        listed = sandbox.list_sessions()
        loaded = sandbox.get_session("ses-1")
        sandbox.signal_session("ses-1", "TERM")
        sandbox.resize_session("ses-1", 120, 40)
        log = sandbox.session_log("ses-1")
        recording = sandbox.session_recording("ses-1")
        sandbox.delete_session("ses-1")

        self.assertEqual(
            client.calls[1],
            (
                "POST",
                "/v1/sandboxes/sb-1/sessions",
                {
                    "name": "default",
                    "command": "bash",
                    "workdir": "/workspace",
                    "pty": True,
                    "cols": 120,
                    "rows": 40,
                },
            ),
        )
        self.assertEqual(client.calls[2], ("GET", "/v1/sandboxes/sb-1/sessions", None))
        self.assertEqual(client.calls[3], ("GET", "/v1/sandboxes/sb-1/sessions/ses-1", None))
        self.assertEqual(client.calls[4], ("POST", "/v1/sandboxes/sb-1/sessions/ses-1/signal", {"signal": "TERM"}))
        self.assertEqual(client.calls[5], ("POST", "/v1/sandboxes/sb-1/sessions/ses-1/resize", {"cols": 120, "rows": 40}))
        self.assertEqual(client.calls[6], ("DELETE", "/v1/sandboxes/sb-1/sessions/ses-1", None))
        self.assertEqual(client.raw_calls[0][:2], ("GET", "/v1/sandboxes/sb-1/sessions/ses-1/log"))
        self.assertEqual(client.raw_calls[1][:2], ("GET", "/v1/sandboxes/sb-1/sessions/ses-1/recording"))

        self.assertEqual(created["argv"], ["sh", "-c", "bash"])
        self.assertEqual(listed[0]["status"], "running")
        self.assertEqual(loaded["bytes"], 99)
        self.assertEqual(log, b"session log")
        self.assertEqual(recording, b'{"version":2}')

    def test_attach_session_sends_control_frames_and_waits_for_exit(self):
        stdout_chunks = []
        stderr_chunks = []
        errors = []
        exits = []
        fake_ws = FakeWebSocket(
            [
                bytes([1]) + b"hello",
                bytes([2]) + b"warn",
                json.dumps({"type": "exit", "code": 0, "signal": "TERM"}),
            ]
        )
        fake_module = FakeWebSocketModule(fake_ws)
        original_loader = client_module._load_websocket_module
        client_module._load_websocket_module = lambda: fake_module
        try:
            client = RecordingMicroVM()
            handle = client.attach_session(
                "sb-1",
                "ses-1",
                {
                    "cols": 120,
                    "rows": 40,
                    "onStdout": stdout_chunks.append,
                    "onStderr": stderr_chunks.append,
                    "onError": errors.append,
                    "onExit": exits.append,
                },
            )

            handle.write("pwd\n")
            handle.resize(100, 30)
            handle.signal("INT")
            result = handle.wait(1)

            self.assertEqual(result, {"code": 0, "signal": "TERM"})
            self.assertEqual(stdout_chunks, [b"hello"])
            self.assertEqual(stderr_chunks, [b"warn"])
            self.assertEqual(errors, [])
            self.assertEqual(exits, [{"code": 0, "signal": "TERM"}])
            self.assertEqual(fake_module.calls[0][0], "wss://sandbox.example.com/v1/sandboxes/sb-1/sessions/ses-1/attach")
            self.assertEqual(fake_module.calls[0][1], ["Authorization: Bearer pat-token"])
            self.assertTrue(fake_module.calls[0][2])
            self.assertEqual(json.loads(fake_ws.sent[0][0]), {"type": "resize", "cols": 120, "rows": 40})
            self.assertEqual(fake_ws.sent[1], (b"pwd\n", 2))
            self.assertEqual(json.loads(fake_ws.sent[2][0]), {"type": "resize", "cols": 100, "rows": 30})
            self.assertEqual(json.loads(fake_ws.sent[3][0]), {"type": "signal", "signal": "INT"})
        finally:
            client_module._load_websocket_module = original_loader


if __name__ == "__main__":
    unittest.main()