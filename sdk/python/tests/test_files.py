"""File verbs beyond upload and download (plans/agent-sandbox-feature-
parity.md, F1): the toolbox routes they call, the /version check before an
option an older agent would ignore, and each verb's retry rule."""

import http.server
import json
import threading
import unittest
import urllib.parse

from microvm import DEFAULT_LIST_LIMIT, MicroVM, MicroVMError, MicroVMHTTPError, MicroVMUnsupportedFeatureError

_FAST_RETRY = {"retry": {"maxRetries": 3, "baseDelayMs": 1, "maxDelayMs": 1}}


class FakeToolbox:
    """A local server standing in for sandboxd's toolbox pass-through.
    ``reply(method, path, query, n)`` answers call ``n`` (from 0) of one
    method and path with ``(status, body, headers)``."""

    def __init__(self, features, reply):
        self.features = features
        self.reply = reply
        self.calls = []
        counts = {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                parsed = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parsed.query))
                if parsed.path.endswith("/toolbox/version"):
                    self._send(200, {"version": "test", "features": outer.features}, {})
                    return
                key = (self.command, parsed.path)
                n = counts.get(key, 0)
                counts[key] = n + 1
                outer.calls.append((self.command, parsed.path, query))
                status, body, headers = outer.reply(self.command, parsed.path, query, n)
                self._send(status, body, headers)

            def _send(self, status, body, headers):
                data = b"" if body is None else json.dumps(body).encode("utf-8")
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                if data:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _handle

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = MicroVM(f"http://127.0.0.1:{self.server.server_address[1]}", "pat", config=_FAST_RETRY)

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def routes(self):
        return [(method, path.split("/toolbox", 1)[1]) for method, path, _ in self.calls]


def _err(message, code=""):
    body = {"error": message}
    if code:
        body["code"] = code
    return body


class FileVerbTests(unittest.TestCase):
    def serve(self, reply, features=("files.verbs",)):
        fake = FakeToolbox(list(features), reply)
        self.addCleanup(fake.close)
        return fake

    def test_list_files_sends_depth_and_cap_and_reads_extended_info(self):
        def reply(method, path, query, n):
            entries = [
                {"name": "a", "isDir": True, "size": 64, "path": "/w/a", "size_bytes": 64, "mode": "drwxr-xr-x"},
                {"name": "big", "size": 2147483647, "path": "/w/big", "size_bytes": 5 << 30},
                {"name": "link", "size": 4, "path": "/w/link", "size_bytes": 4, "symlink_target": "a"},
                {"name": "old"},
            ]
            return 200, entries, {"X-Toolbox-Truncated": "true"}

        fake = self.serve(reply)
        listing = fake.client.list_files("sb-1", "/w")
        _, _, query = fake.calls[0]
        self.assertEqual(query, {"path": "/w", "depth": "1", "limit": str(DEFAULT_LIST_LIMIT), "extended": "true"})
        self.assertTrue(listing["truncated"])
        self.assertEqual([e["path"] for e in listing["entries"]], ["/w/a", "/w/big", "/w/link", "/w/old"])
        self.assertEqual(listing["entries"][1]["size"], 5 << 30)
        self.assertEqual(listing["entries"][2]["symlinkTarget"], "a")
        self.assertTrue(listing["entries"][0]["isDir"])
        self.assertNotIn("symlinkTarget", listing["entries"][0])

        fake.client.list_files("sb-1", "/w", depth=3, limit=5)
        self.assertEqual(fake.calls[1][2]["depth"], "3")
        self.assertEqual(fake.calls[1][2]["limit"], "5")
        with self.assertRaises(MicroVMError):
            fake.client.list_files("sb-1", "/w", depth=0)

    def test_untruncated_listing(self):
        fake = self.serve(lambda method, path, query, n: (200, [], {}))
        self.assertEqual(fake.client.list_files("sb-1", "/"), {"entries": [], "truncated": False})

    def test_older_agent_fails_closed_before_any_file_call(self):
        fake = self.serve(lambda method, path, query, n: (204, None, {}), features=())
        calls = {
            "list_files": lambda: fake.client.list_files("sb-1", "/"),
            "move_file": lambda: fake.client.move_file("sb-1", "/a", "/b"),
            "copy_file": lambda: fake.client.copy_file("sb-1", "/a", "/b"),
            "make_dir": lambda: fake.client.make_dir("sb-1", "/d"),
        }
        for name, call in calls.items():
            with self.subTest(name):
                with self.assertRaises(MicroVMUnsupportedFeatureError) as ctx:
                    call()
                self.assertEqual(ctx.exception.features, ["files.verbs"])
        self.assertEqual(fake.calls, [])
        # An older agent does what these ask anyway, so no check is needed.
        fake.client.move_file("sb-1", "/a", "/b", overwrite=True)
        fake.client.make_dir("sb-1", "/d", parents=True)
        self.assertEqual(fake.calls[0][2]["overwrite"], "true")
        self.assertEqual(fake.calls[1][2]["parents"], "true")

    def test_get_file_info_and_exists(self):
        answers = {
            "/new": (200, {"name": "new", "size": 2147483647, "size_bytes": 3 << 30, "path": "/new", "isDir": False}),
            "/old": (200, {"name": "old", "size": 12}),
            "/gone": (404, _err("stat /gone: no such file or directory", "file_not_found")),
            "/gone-old": (404, _err("stat /gone-old: no such file or directory")),
            "/no-sandbox": (404, _err("sandbox not found")),
            "/broken": (403, _err("permission denied")),
        }
        fake = self.serve(lambda method, path, query, n: (*answers[query["path"]], {}))
        info = fake.client.get_file_info("sb-1", "/new")
        self.assertEqual((info["size"], info["path"]), (3 << 30, "/new"))
        self.assertEqual(fake.calls[0][2]["extended"], "true")
        old = fake.client.get_file_info("sb-1", "/old")
        self.assertEqual((old["size"], old["path"]), (12, "/old"))
        self.assertTrue(fake.client.file_exists("sb-1", "/new"))
        self.assertFalse(fake.client.file_exists("sb-1", "/gone"))
        self.assertFalse(fake.client.file_exists("sb-1", "/gone-old"))
        for path in ("/no-sandbox", "/broken"):
            with self.assertRaises(MicroVMHTTPError):
                fake.client.file_exists("sb-1", path)
        # No /version round trip: extended only adds fields.
        self.assertTrue(all(not p.endswith("/version") for _, p, _ in fake.calls))

    def test_retried_delete_and_mkdir_count_work_already_done(self):
        def reply(method, path, query, n):
            target = query.get("path", "")
            if target.startswith("/lost"):
                if n == 0:
                    return 502, None, {}
                if method == "DELETE":
                    return 404, _err("lstat: no such file or directory", "file_not_found"), {}
                return 409, _err(target + " already exists", "folder_exists"), {}
            if target == "/route-missing":
                return (503, None, {}) if n == 0 else (404, _err("not found"), {})
            if target == "/missing":
                return 404, _err("lstat /missing: no such file or directory", "file_not_found"), {}
            if target == "/a-file":
                return 409, _err("mkdir /a-file: file exists"), {}
            return 204, None, {}

        fake = self.serve(reply)
        fake.client.delete_file("sb-1", "/lost-del", recursive=True)
        self.assertEqual(fake.calls[0][2]["recursive"], "true")
        fake.client.make_dir("sb-1", "/lost-dir", mode=0o1750)
        self.assertEqual(fake.calls[2][2], {"path": "/lost-dir", "parents": "false", "mode": "1750"})
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake.client.delete_file("sb-1", "/missing")
        self.assertEqual((ctx.exception.status_code, ctx.exception.code), (404, "file_not_found"))
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake.client.make_dir("sb-1", "/a-file")
        self.assertEqual(ctx.exception.status_code, 409)
        # An uncoded 404 on a retry may be an agent without the route.
        with self.assertRaises(MicroVMHTTPError):
            fake.client.delete_file("sb-1", "/route-missing")

    def test_move_and_copy_retry_only_refusals(self):
        def reply(method, path, query, n):
            source = query.get("source")
            if source == "/refused-once" and n == 0:
                return 503, None, {}
            if source == "/bad-gateway":
                return 502, None, {}
            if source == "/taken":
                return 409, _err("rename /taken /b: file exists"), {}
            return 204, None, {}

        fake = self.serve(reply)
        fake.client.move_file("sb-1", "/refused-once", "/b")
        self.assertEqual(len(fake.calls), 2)
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake.client.move_file("sb-1", "/bad-gateway", "/b")
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(len(fake.calls), 3, "a 502 on a move was re-sent")
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake.client.move_file("sb-1", "/taken", "/b")
        self.assertEqual(ctx.exception.status_code, 409)
        with self.assertRaises(MicroVMHTTPError):
            fake.client.copy_file("sb-1", "/bad-gateway", "/c", recursive=True)
        self.assertEqual(fake.calls[-1][2], {"source": "/bad-gateway", "destination": "/c", "overwrite": "false", "recursive": "true"})
        self.assertEqual(fake.routes()[-1], ("POST", "/files/copy"))

    def test_search_and_find(self):
        def reply(method, path, query, n):
            if query.get("pattern") == "none":
                return 200, ({"files": None} if path.endswith("/search") else None), {}
            if path.endswith("/search"):
                return 200, {"files": ["/w/a.py"]}, {}
            return 200, [{"file": "/w/a.py", "line": 2, "content": "import os"}], {}

        fake = self.serve(reply)
        self.assertEqual(fake.client.search_files("sb-1", "/w", "*.py"), ["/w/a.py"])
        self.assertEqual(fake.client.find_in_files("sb-1", "/w", "import"), [{"file": "/w/a.py", "line": 2, "content": "import os"}])
        self.assertEqual(fake.client.search_files("sb-1", "/w", "none"), [])
        self.assertEqual(fake.client.find_in_files("sb-1", "/w", "none"), [])

    def test_sandbox_methods_delegate(self):
        from microvm.client import Sandbox

        fake = self.serve(lambda method, path, query, n: (200, {"name": "x"} if path.endswith("/info") else [] if method == "GET" else None, {}))
        sandbox = Sandbox(fake.client, {"id": "sb-1"})
        sandbox.list_files("/")
        sandbox.get_file_info("/x")
        self.assertTrue(sandbox.file_exists("/x"))
        sandbox.delete_file("/x")
        sandbox.make_dir("/d", parents=True)
        sandbox.move_file("/a", "/b", overwrite=True)
        sandbox.copy_file("/a", "/b")
        sandbox.search_files("/", "*")
        sandbox.find_in_files("/", "x")
        self.assertEqual(
            [route for _, route in fake.routes()],
            ["/files", "/files/info", "/files/info", "/files", "/files/folder", "/files/move", "/files/copy", "/files/search", "/files/find"],
        )


if __name__ == "__main__":
    unittest.main()


class UploadOptionTests(unittest.TestCase):
    """Upload write options (plan F2) and their retry tiers (section 10)."""

    def serve(self, reply, features=("files.write_options",)):
        fake = FakeToolbox(list(features), reply)
        self.addCleanup(fake.close)
        return fake

    def test_options_are_sent_after_the_version_check(self):
        fake = self.serve(lambda method, path, query, n: (201, {"path": "/a"}, {}))
        fake.client.upload_file("sb-1", "/w/a.txt", b"x", create_only=True, atomic=True, mode=0o600)
        self.assertEqual(fake.calls[0][2], {"create_only": "true", "atomic": "true", "mode": "600"})
        fake.client.upload_file("sb-1", "/w/a.txt", b"x")
        self.assertEqual(fake.calls[1][2], {})

    def test_older_agent_fails_closed(self):
        fake = self.serve(lambda method, path, query, n: (201, {}, {}), features=())
        for kwargs in ({"append": True}, {"create_only": True}, {"atomic": True}, {"mode": 0o644}):
            with self.subTest(kwargs):
                with self.assertRaises(MicroVMUnsupportedFeatureError):
                    fake.client.upload_file("sb-1", "/a", b"x", **kwargs)
        self.assertEqual(fake.calls, [])
        fake.client.upload_file("sb-1", "/a", b"x")
        self.assertEqual(len(fake.calls), 1)

    def test_retry_tiers(self):
        def reply(method, path, query, n):
            return (502, None, {}) if n == 0 else (201, {}, {})

        fake = self.serve(reply)
        # A plain upload re-sends after a 502.
        fake.client.upload_file("sb-1", "/a", b"x")
        self.assertEqual(len(fake.calls), 2)
        # create_only does not: the first send may have made the file.
        fake2 = self.serve(reply)
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake2.client.upload_file("sb-1", "/a", b"x", create_only=True)
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(len(fake2.calls), 1)

    def test_create_only_conflict_is_412(self):
        fake = self.serve(lambda method, path, query, n: (412, _err("/a already exists and create_only is set", "file_exists"), {}))
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake.client.upload_file("sb-1", "/a", b"x", create_only=True)
        self.assertEqual((ctx.exception.status_code, ctx.exception.code), (412, "file_exists"))

    def test_sandbox_upload_passes_options(self):
        from microvm.client import Sandbox

        fake = self.serve(lambda method, path, query, n: (201, {}, {}))
        Sandbox(fake.client, {"id": "sb-1"}).upload_file("/a", b"x", append=True)
        self.assertEqual(fake.calls[0][2], {"append": "true"})
