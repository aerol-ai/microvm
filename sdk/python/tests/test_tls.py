"""Custom CA, client certificate and extra headers (plan S7)."""

import http.server
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import unittest.mock

from microvm import MicroVM, MicroVMError
from microvm import client as client_module

_SANDBOX = {"id": "sb-1", "name": "a", "image": "alpine", "status": "started", "lifecycle": {}}


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


class _Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        # The Message itself: its get() ignores case, as HTTP does.
        type(self).seen.append(self.headers)
        body = json.dumps(_SANDBOX).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@unittest.skipIf(shutil.which("openssl") is None, "needs the openssl command to make test certificates")
class TLSOptionTests(unittest.TestCase):
    """An https server with its own CA, which also asks for a client
    certificate signed by that CA, the way a company proxy can."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        d = cls.dir
        # Key usage on every certificate: Python 3.13+ verifies strictly.
        _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=test-ca",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", "ca.key", "-out", "ca.pem", cwd=d)
        for name, extra in (("server", ["-addext", "subjectAltName=IP:127.0.0.1"]), ("client", [])):
            _openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", f"{name}.key",
                     "-out", f"{name}.csr", *extra, cwd=d)
            ext = os.path.join(d, f"{name}.ext")
            with open(ext, "w") as f:
                f.write("keyUsage=critical,digitalSignature,keyEncipherment\n")
                f.write("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" if name == "server" else "extendedKeyUsage=clientAuth\n")
            _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                     "-days", "2", "-out", f"{name}.pem", "-extfile", ext, cwd=d)
        with open(os.path.join(d, "client-bundle.pem"), "w") as out:
            for part in ("client.pem", "client.key"):
                with open(os.path.join(d, part)) as f:
                    out.write(f.read())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def serve(self, require_client_cert):
        _Handler.seen = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.path("server.pem"), self.path("server.key"))
        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(self.path("ca.pem"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "https://127.0.0.1:%d" % server.server_port

    def client(self, url, **kwargs):
        return MicroVM(url, "pat", config={"retry": {"maxRetries": 0}}, **kwargs)

    def test_an_unknown_ca_is_refused_and_ca_file_trusts_it(self):
        url = self.serve(require_client_cert=False)
        with self.assertRaises(Exception) as ctx:
            self.client(url).get("sb-1")
        self.assertIn("CERTIFICATE_VERIFY_FAILED", str(ctx.exception))
        self.assertEqual(self.client(url, ca_file=self.path("ca.pem")).get("sb-1").id, "sb-1")

    def test_client_cert_in_one_file_or_as_a_pair(self):
        url = self.serve(require_client_cert=True)
        with self.assertRaises(Exception):
            self.client(url, ca_file=self.path("ca.pem")).get("sb-1")
        for cert in (self.path("client-bundle.pem"), (self.path("client.pem"), self.path("client.key"))):
            with self.subTest(cert=cert):
                client = self.client(url, ca_file=self.path("ca.pem"), client_cert=cert)
                self.assertEqual(client.get("sb-1").id, "sb-1")

    def test_the_options_also_come_from_config(self):
        url = self.serve(require_client_cert=True)
        config = {
            "retry": {"maxRetries": 0},
            "caFile": self.path("ca.pem"),
            "clientCert": [self.path("client.pem"), self.path("client.key")],
            "headers": {"X-Proxy-Auth": "abc"},
        }
        client = MicroVM(url, "pat", config=config)
        self.assertEqual(client.get("sb-1").id, "sb-1")
        self.assertEqual(_Handler.seen[-1].get("X-Proxy-Auth"), "abc")

    def test_a_bad_file_fails_when_the_client_is_made(self):
        with self.assertRaises((OSError, ssl.SSLError)):
            MicroVM("https://127.0.0.1:9", "pat", ca_file=self.path("missing.pem"))
        with self.assertRaises(ValueError):
            MicroVM("https://127.0.0.1:9", "pat", client_cert=("a", "b", "c"))


class ExtraHeaderTests(unittest.TestCase):
    def serve(self):
        _Handler.seen = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d" % server.server_port

    def test_headers_go_on_every_request_beside_the_sdk_headers(self):
        url = self.serve()
        client = MicroVM(url, "pat", team="red", headers={"X-Proxy-Auth": "abc", "User-Agent": "my-app/1"})
        client.get("sb-1")
        seen = _Handler.seen[-1]
        self.assertEqual(seen.get("X-Proxy-Auth"), "abc")
        self.assertEqual(seen.get("User-Agent"), "my-app/1")
        self.assertEqual(seen.get("Authorization"), "Bearer pat")
        self.assertEqual(seen.get("X-AerolVM-Team"), "red")

    def test_the_sdk_headers_cannot_be_replaced_and_bad_ones_are_refused(self):
        for headers in (
            {"Authorization": "Bearer other"},
            {"x-aerolvm-team": "blue"},
            {"Content-Type": "text/plain"},
            {"Idempotency-Key": "k"},
            {"Host": "other.example"},
            {"Content-Length": "0"},
            {"Transfer-Encoding": "chunked"},
            {"X-Bad": "a\r\nInjected: yes"},
            {"X-Bad\n": "a"},
            {"": "a"},
            {"X-Num": 5},
        ):
            with self.subTest(headers=headers):
                with self.assertRaises(ValueError):
                    MicroVM("http://127.0.0.1:9", "pat", headers=headers)

    def test_websocket_handshakes_carry_the_headers_and_the_tls_context(self):
        calls = []

        class FakeWS:
            def settimeout(self, value):
                pass

            def send(self, payload, opcode=None):
                pass

            def recv(self):
                return json.dumps({"type": "exit", "code": 0})

            def close(self):
                pass

        class FakeModule:
            class ABNF:
                OPCODE_BINARY = 2

            @staticmethod
            def create_connection(url, **kwargs):
                calls.append(kwargs)
                return FakeWS()

        with unittest.mock.patch.object(client_module, "_load_websocket_module", lambda: FakeModule):
            plain = MicroVM("http://127.0.0.1:9", "pat", headers={"X-Proxy-Auth": "abc"})
            plain.exec_stream("sb-1", {"command": "true"}).wait(5)
            self.assertIn("X-Proxy-Auth: abc", calls[-1]["header"])
            self.assertIn("Authorization: Bearer pat", calls[-1]["header"])
            self.assertNotIn("sslopt", calls[-1])
            with unittest.mock.patch.object(client_module, "_build_ssl_context", lambda *a: "CTX"):
                tls = MicroVM("https://127.0.0.1:9", "pat", ca_file="ca.pem")
            tls.exec_stream("sb-1", {"command": "true"}).wait(5)
            self.assertEqual(calls[-1]["sslopt"], {"context": "CTX"})

    def test_no_options_change_nothing(self):
        url = self.serve()
        client = MicroVM(url, "pat")
        self.assertIsNone(client._ssl_context)
        with unittest.mock.patch("urllib.request.urlopen", wraps=__import__("urllib.request").request.urlopen) as opened:
            client.get("sb-1")
            self.assertNotIn("context", opened.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
