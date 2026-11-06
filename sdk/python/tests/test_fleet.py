"""get_or_create and destroy_all against a fake sandboxd that keeps sandboxes by name, the
way the real one does (names unique per owner, a second create of a name is
a 409)."""

import http.server
import json
import threading
import unittest
import urllib.parse

from microvm import MicroVM, MicroVMConflictError, MicroVMHTTPError
from microvm import client as client_module


def _sandbox_json(sandbox_id, name, tags=None, image="alpine"):
    return {
        "id": sandbox_id,
        "name": name,
        "image": image,
        "status": "started",
        "tags": dict(tags or {}),
        "lifecycle": {},
    }


class FakeSandboxd:
    """A threaded HTTP server holding sandboxes in memory.

    ``lookup_barrier`` holds the first N name lookups until all N arrive, so
    N concurrent callers all miss before any of them creates: the race
    get_or_create has to survive.
    """

    def __init__(self, test, lookup_barrier=0, page_size=2):
        self.lock = threading.Lock()
        self.sandboxes = {}
        self.requests = []
        self.next_id = 0
        self.page_size = page_size
        self.conflict_without_name = False
        self.delete_status = {}
        self._barrier = threading.Barrier(lookup_barrier) if lookup_barrier else None
        self._barrier_left = lookup_barrier
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload=None, headers=None):
                body = b"" if payload is None else json.dumps(payload).encode("utf-8")
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                query = dict(urllib.parse.parse_qsl(parsed.query))
                with fake.lock:
                    fake.requests.append(("GET", self.path))
                if parsed.path != "/v1/sandboxes":
                    self._send(404, {"error": "not found"})
                    return
                if "name" in query:
                    wait = False
                    with fake.lock:
                        if fake._barrier is not None and fake._barrier_left > 0:
                            fake._barrier_left -= 1
                            wait = True
                    if wait:
                        fake._barrier.wait(timeout=10)
                    with fake.lock:
                        hit = [s for s in fake.sandboxes.values() if s["name"] == query["name"]]
                    self._send(200, hit)
                    return
                tags = {k[len("tag."):]: v for k, v in query.items() if k.startswith("tag.")}
                with fake.lock:
                    matched = sorted(
                        (s for s in fake.sandboxes.values() if all(s["tags"].get(k) == v for k, v in tags.items())),
                        key=lambda s: s["id"],
                    )
                start = int(query.get("page_token") or 0)
                page = matched[start : start + fake.page_size]
                headers = {}
                if start + fake.page_size < len(matched):
                    headers["X-Cluster-List-Next-Page-Token"] = str(start + fake.page_size)
                self._send(200, page, headers)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                with fake.lock:
                    fake.requests.append(("POST", self.path))
                    if fake.conflict_without_name:
                        self._send(409, {"error": "sandbox id already reserved"})
                        return
                    name = body.get("name", "")
                    if name and any(s["name"] == name for s in fake.sandboxes.values()):
                        self._send(409, {"error": "sandbox name already in use"})
                        return
                    fake.next_id += 1
                    sandbox = _sandbox_json("sb-%03d" % fake.next_id, name, body.get("tags"), body.get("image", ""))
                    fake.sandboxes[sandbox["id"]] = sandbox
                self._send(201, sandbox)

            def do_DELETE(self):
                sandbox_id = self.path.rsplit("/", 1)[-1]
                with fake.lock:
                    fake.requests.append(("DELETE", self.path))
                    status = fake.delete_status.get(sandbox_id)
                    if status is None:
                        status = 204 if fake.sandboxes.pop(sandbox_id, None) is not None else 404
                if status == 204:
                    self._send(204)
                else:
                    self._send(status, {"error": "delete failed with %d" % status})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:%d" % self.server.server_port

    def add(self, name, tags=None, image="alpine"):
        with self.lock:
            self.next_id += 1
            sandbox = _sandbox_json("sb-%03d" % self.next_id, name, tags, image)
            self.sandboxes[sandbox["id"]] = sandbox
            return sandbox["id"]

    def client(self):
        return MicroVM(self.url, "pat", config={"retry": {"maxRetries": 0}})

    def count(self, method):
        with self.lock:
            return sum(1 for m, _ in self.requests if m == method)


class GetOrCreateTests(unittest.TestCase):
    def test_creates_when_the_name_is_free(self):
        fake = FakeSandboxd(self)
        sandbox, created = fake.client().get_or_create("agent-1", image="alpine", tags={"team": "x"})
        self.assertTrue(created)
        self.assertEqual(sandbox.name, "agent-1")
        self.assertEqual(sandbox.tags, {"team": "x"})
        self.assertEqual((fake.count("GET"), fake.count("POST")), (1, 1))

    def test_returns_the_existing_sandbox_without_creating(self):
        fake = FakeSandboxd(self)
        sandbox_id = fake.add("agent-1", image="ubuntu")
        sandbox, created = fake.client().get_or_create("agent-1", {"image": "alpine"})
        self.assertFalse(created)
        self.assertEqual(sandbox.id, sandbox_id)
        self.assertEqual(sandbox.image, "ubuntu")
        self.assertEqual(fake.count("POST"), 0)

    def test_concurrent_callers_get_one_sandbox(self):
        callers = 8
        fake = FakeSandboxd(self, lookup_barrier=callers)
        client = fake.client()
        results = []
        errors = []

        def run():
            try:
                results.append(client.get_or_create("shared", image="alpine"))
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(callers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), callers)
        self.assertEqual(len({sandbox.id for sandbox, _ in results}), 1)
        self.assertEqual(sum(1 for _, created in results if created), 1)
        self.assertEqual(len(fake.sandboxes), 1)
        # Every caller missed the first lookup and tried to create.
        self.assertEqual(fake.count("POST"), callers)

    def test_a_conflict_on_something_else_is_raised(self):
        fake = FakeSandboxd(self)
        fake.conflict_without_name = True
        with self.assertRaises(MicroVMConflictError) as ctx:
            fake.client().get_or_create("agent-1", image="alpine")
        self.assertEqual(str(ctx.exception), "sandbox id already reserved")
        self.assertIsInstance(ctx.exception, MicroVMHTTPError)

    def test_rejects_a_missing_or_mismatched_name(self):
        client = MicroVM("http://127.0.0.1:9", "pat")
        for name, options in (("", {}), ("  ", {}), ("a", {"name": "b"})):
            with self.subTest(name=name, options=options):
                with self.assertRaises(ValueError):
                    client.get_or_create(name, options, image="alpine")

    def test_the_options_may_repeat_the_name(self):
        fake = FakeSandboxd(self)
        sandbox, created = fake.client().get_or_create(" agent-1 ", {"name": "agent-1", "image": "alpine"})
        self.assertTrue(created)
        self.assertEqual(sandbox.name, "agent-1")



class DestroyAllTests(unittest.TestCase):
    def test_deletes_every_match_across_pages(self):
        fake = FakeSandboxd(self, page_size=2)
        doomed = [fake.add("a-%d" % i, {"run": "42", "team": "x"}) for i in range(5)]
        kept = [fake.add("other", {"run": "41", "team": "x"}), fake.add("untagged")]
        gone = fake.client().destroy_all(tags={"run": "42", "team": "x"})
        self.assertEqual(gone, doomed)
        self.assertEqual(sorted(fake.sandboxes), sorted(kept))
        # Three list pages, then one delete per match.
        self.assertEqual(fake.count("GET"), 3)
        self.assertEqual(fake.count("DELETE"), 5)

    def test_a_second_call_finds_nothing(self):
        fake = FakeSandboxd(self)
        fake.add("a", {"run": "42"})
        client = fake.client()
        self.assertEqual(len(client.destroy_all(tags={"run": "42"})), 1)
        self.assertEqual(client.destroy_all(tags={"run": "42"}), [])

    def test_an_already_gone_sandbox_counts_as_deleted(self):
        fake = FakeSandboxd(self)
        first = fake.add("a", {"run": "42"})
        second = fake.add("b", {"run": "42"})
        fake.delete_status[first] = 404
        self.assertEqual(fake.client().destroy_all(tags={"run": "42"}), [first, second])

    def test_stops_at_a_failed_delete(self):
        fake = FakeSandboxd(self)
        first = fake.add("a", {"run": "42"})
        second = fake.add("b", {"run": "42"})
        third = fake.add("c", {"run": "42"})
        fake.delete_status[second] = 500
        with self.assertRaises(MicroVMHTTPError) as ctx:
            fake.client().destroy_all(tags={"run": "42"})
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertNotIn(first, fake.sandboxes)
        self.assertIn(third, fake.sandboxes)
        self.assertEqual(fake.count("DELETE"), 2)

    def test_needs_a_tag(self):
        client = MicroVM("http://127.0.0.1:9", "pat")
        for tags in ({}, None):
            with self.subTest(tags=tags):
                with self.assertRaises(ValueError):
                    client.destroy_all(tags=tags)



class AutoCleanupTests(unittest.TestCase):
    def test_leaving_a_with_block_keeps_the_sandbox_by_default(self):
        fake = FakeSandboxd(self)
        with fake.client().create(image="alpine", name="kept") as sandbox:
            self.assertFalse(sandbox.destroy_on_exit)
        self.assertEqual(fake.count("DELETE"), 0)
        self.assertEqual(len(fake.sandboxes), 1)

    def test_destroy_on_exit_deletes_when_the_block_ends(self):
        fake = FakeSandboxd(self)
        client = fake.client()
        for spelling in ("destroy_on_exit", "destroyOnExit"):
            with self.subTest(spelling=spelling):
                with client.create({"image": "alpine", spelling: True}) as sandbox:
                    self.assertTrue(sandbox.destroy_on_exit)
                self.assertEqual(fake.sandboxes, {})
        sandbox, _ = client.get_or_create("b", image="alpine", destroy_on_exit=True)
        with sandbox:
            pass
        self.assertEqual(fake.sandboxes, {})

    def test_the_flag_is_never_sent(self):
        payload = client_module._to_api_create_options({"image": "alpine", "destroy_on_exit": True, "destroyOnExit": True})
        self.assertNotIn("destroy_on_exit", payload)
        self.assertNotIn("destroyOnExit", payload)

    def test_the_block_error_wins_over_a_failed_delete(self):
        fake = FakeSandboxd(self)
        sandbox = fake.client().create(image="alpine", destroy_on_exit=True)
        fake.delete_status[sandbox.id] = 500
        with self.assertRaises(RuntimeError) as ctx:
            with sandbox:
                raise RuntimeError("work failed")
        self.assertEqual(str(ctx.exception), "work failed")
        notes = getattr(ctx.exception, "__notes__", None)
        if notes is not None:  # add_note exists from Python 3.11
            self.assertIn("destroying sandbox %s on exit also failed" % sandbox.id, notes[0])

    def test_close_deletes_once_and_reports_a_failure(self):
        fake = FakeSandboxd(self)
        sandbox = fake.client().create(image="alpine")
        sandbox.destroy_on_exit = True
        fake.delete_status[sandbox.id] = 500
        with self.assertRaises(MicroVMHTTPError):
            sandbox.close()
        fake.delete_status[sandbox.id] = 404
        sandbox.close()
        sandbox.close()
        self.assertEqual(fake.count("DELETE"), 2)

    def test_a_failed_delete_without_a_block_error_is_raised(self):
        fake = FakeSandboxd(self)
        sandbox = fake.client().create(image="alpine", destroy_on_exit=True)
        fake.delete_status[sandbox.id] = 500
        with self.assertRaises(MicroVMHTTPError):
            with sandbox:
                pass


if __name__ == "__main__":
    unittest.main()
