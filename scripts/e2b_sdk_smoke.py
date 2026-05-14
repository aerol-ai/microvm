import os
import sys

from e2b import Sandbox


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def main() -> int:
    require_env("E2B_API_URL")
    require_env("E2B_SANDBOX_URL")
    require_env("E2B_API_KEY")

    sandbox = None
    snapshot = None
    try:
        sandbox = Sandbox.create(
            template="base",
            timeout=120,
            metadata={"suite": "smoke"},
            envs={"E2B_SMOKE": "smoke"},
            secure=True,
        )
        assert sandbox.sandbox_id, "sandbox_id was empty"
        assert sandbox.is_running(), "sandbox should report running"

        sandbox.files.write("/tmp/e2b-smoke.txt", "hello from sdk")
        content = sandbox.files.read("/tmp/e2b-smoke.txt")
        assert content == "hello from sdk", content

        entries = sandbox.files.list("/tmp", depth=1)
        assert any(entry.path == "/tmp/e2b-smoke.txt" for entry in entries), entries

        result = sandbox.commands.run("printf $E2B_SMOKE", envs={"E2B_SMOKE": "smoke"})
        assert result.stdout == "smoke", result.stdout

        listed = Sandbox.list(limit=20).next_items()
        assert any(item.sandbox_id == sandbox.sandbox_id for item in listed), listed

        snapshot = sandbox.create_snapshot()
        assert snapshot.snapshot_id, "snapshot_id was empty"

        snapshots = sandbox.list_snapshots(limit=20).next_items()
        assert any(item.snapshot_id == snapshot.snapshot_id for item in snapshots), snapshots

        sandbox.pause()
        sandbox = sandbox.connect(timeout=180)
        assert sandbox.is_running(), "sandbox should resume after connect"

        print("E2B SDK smoke passed")
        return 0
    finally:
        if snapshot is not None:
            try:
                Sandbox.delete_snapshot(snapshot.snapshot_id)
            except Exception:
                pass
        if sandbox is not None:
            try:
                sandbox.kill()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"assertion failed: {exc}", file=sys.stderr)
        raise