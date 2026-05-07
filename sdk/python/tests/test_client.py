import json
import unittest

from microvm import client as client_module
from microvm.client import MicroVM


class RecordingMicroVM(MicroVM):
    def __init__(self) -> None:
        super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")
        self.calls = []

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
                "exposed_ports": [],
                "created_at": "2026-05-07T10:00:00Z",
                "updated_at": "2026-05-07T10:00:00Z",
                "last_active_at": "2026-05-07T10:00:00Z",
            }
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
                "version": "dev",
            }
        raise AssertionError(f"unexpected call: {method} {path} {payload}")


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
                },
            ),
        )
        self.assertEqual(sandbox.publicURL, "https://sb-1.example.com")
        self.assertEqual(sandbox.memoryMB, 2048)
        self.assertTrue(sandbox.networkBlockAll)

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


if __name__ == "__main__":
    unittest.main()