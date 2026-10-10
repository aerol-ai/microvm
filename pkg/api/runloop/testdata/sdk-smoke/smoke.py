"""Smoke test: the official Runloop Python SDK against the AerolVM /runloop
facade. RUNLOOP_BASE_URL and RUNLOOP_API_KEY come from the environment."""

from runloop_api_client import RunloopSDK


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


sdk = RunloopSDK(max_retries=1)

devbox = sdk.devbox.create(name="py-smoke", metadata={"lang": "py"})
info = devbox.get_info()
check(info.status == "running", f"running after create: {info.status}")
check(info.name == "py-smoke" and info.metadata["lang"] == "py", "name/metadata")
print("create ok", devbox.id)

r = devbox.cmd.exec("echo hello")
check(r.exit_code == 0 and r.stdout() == "hello\n", f"exec: {r.exit_code} {r.stdout()!r}")
check(devbox.cmd.exec("exit 7").exit_code == 7, "exit 7")
print("exec ok")

seen = []
cb = devbox.cmd.exec("echo streamed", stdout=seen.append)
check(cb.exit_code == 0 and "".join(seen).strip() == "streamed", f"callbacks: {seen!r}")
print("exec with callbacks ok")

many = devbox.cmd.exec("lines 150")
check(len([l for l in many.stdout().split("\n") if l]) == 150, "full stdout via SSE")
print("truncated stdout via SSE ok")

execution = devbox.cmd.exec_async("echo later")
check(execution.result().stdout() == "later\n", "async result")
print("exec_async ok")

shell = devbox.shell("main")
check(shell.exec("echo one").stdout() == "one\n", "named shell")
print("named shell ok")

devbox.file.write(file_path="notes/a.txt", contents='hi "there"\n')
text = devbox.file.read(file_path="notes/a.txt")
check(text == 'hi "there"\n', f"read: {text!r}")
devbox.file.upload(path="bin.dat", file=("bin.dat", b"\x01\x02\x03"))
data = devbox.file.download(path="bin.dat")
check(data == b"\x01\x02\x03", f"download: {data!r}")
print("files ok")

snap = devbox.snapshot_disk(name="py-snap", metadata={"k": "v"})
snap_info = snap.get_info()
check(snap_info.status == "complete" and snap_info.snapshot.name == "py-snap", f"snapshot: {snap_info}")
from_snap = snap.create_devbox(name="from-snap")
check(from_snap.get_info().snapshot_id == snap.id, "devbox from snapshot")
print("snapshot ok")

devbox.suspend()
check(devbox.get_info().status == "suspended", "suspended")
devbox.resume()
check(devbox.get_info().status == "running", "resumed")
devbox.keep_alive()
print("suspend/resume ok")

check(len(sdk.devbox.list(limit=10)) >= 2, "list")
from_snap.shutdown()
check(devbox.shutdown().status == "shutdown", "shutdown")
snap.delete()
print("PY SMOKE PASSED")
