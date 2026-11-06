"""Sandbox creates that are safe to cancel.

The AerolVM SDK is synchronous, so a create runs in a worker thread.
Cancelling the task that awaits it does not stop the thread: the request
goes on and the server makes the sandbox. Its result would then be dropped
before the caller had its id, and nothing could delete it later; with no
lifecycle it would live forever. ``run_owned`` hands the result over under a
lock instead, so exactly one side releases it: the thread, when it finishes
after the task stopped waiting, or the task, when the thread had already
handed it over. The task's CancelledError still reaches its caller.

aerolvm_openai_agents/_owned.py is this module's twin. The two packages ship
apart and depend only on the published SDK, so each keeps its own copy.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Generic, TypeVar

from microvm import MicroVM, MicroVMError, MicroVMHTTPError
from microvm.client import Sandbox

LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")

# Every create carries this tag with a value unique to it. A create that
# fails without a clear answer may still have made a sandbox, and then no id
# came back to delete it by; the tag finds it.
CREATE_OP_TAG = "aerolvm-create-op"
# Bounds the search for such a sandbox, which runs before the create's own
# error reaches the caller.
_SWEEP_TIMEOUT_S = 30.0


async def run_owned(make: Callable[[], _T], release: Callable[[_T], None]) -> _T:
    """Run ``make`` in a worker thread and return what it made.

    If the awaiting task stops waiting first (cancelled, most often),
    ``release`` gets the result once ``make`` returns. ``release`` runs in a
    thread and must not raise.
    """
    handoff = _Handoff(make, release)
    try:
        return await asyncio.to_thread(handoff.run)
    except BaseException:
        handoff.abandon()
        raise


class _Handoff(Generic[_T]):
    def __init__(self, make: Callable[[], _T], release: Callable[[_T], None]) -> None:
        self._make = make
        self._release = release
        self._lock = threading.Lock()
        self._abandoned = False
        # The result, once handed over: empty or one item, so a None result
        # still counts.
        self._handed: list[_T] = []

    def run(self) -> _T:
        """The worker thread's side."""
        made = self._make()
        with self._lock:
            orphan = self._abandoned
            if not orphan:
                self._handed.append(made)
        if orphan:
            self._release(made)
        return made

    def abandon(self) -> None:
        """The awaiting task's side, on its way out. After a normal failure
        of ``make`` nothing was handed over, so this does nothing."""
        with self._lock:
            self._abandoned = True
            handed, self._handed = self._handed, []
        for made in handed:
            # Off the event loop, since a release is a network call. Not a
            # daemon thread, so the interpreter waits for it at exit.
            threading.Thread(target=self._release, args=(made,), name="aerolvm-release").start()


async def create_sandbox(client: MicroVM, request: Mapping[str, Any]) -> Sandbox:
    """``client.create(request)``, safe to cancel, with a ``CREATE_OP_TAG``
    tag of its own.

    A create that fails without a clear answer (a lost connection, a gateway
    that gave up) is followed by a search for that tag, which deletes the
    sandbox if the server made it anyway. The tag is logged, so a later
    ``destroy_all(tags=...)`` can catch one the server finishes after that.
    """
    op = uuid.uuid4().hex
    fields = dict(request)
    fields["tags"] = {**dict(fields.get("tags") or {}), CREATE_OP_TAG: op}

    def make() -> Sandbox:
        try:
            return client.create(fields)
        except Exception as e:
            if _may_have_made_one(e):
                _sweep(client, op, e)
            raise

    return await run_owned(make, lambda sandbox: _destroy_abandoned(client, sandbox.id, op))


def _may_have_made_one(err: Exception) -> bool:
    if isinstance(err, MicroVMHTTPError):
        # A 4xx refuses the request, and a 503 turns it away before any work
        # (the SDK's own reading of 503). Anything else, a 502 or 504 from a
        # gateway or a timeout (status 0), leaves it unknown.
        return not (400 <= err.status_code < 500 or err.status_code == 503)
    return isinstance(err, (MicroVMError, OSError))


def _sweep(client: MicroVM, op: str, err: Exception) -> None:
    tags = {CREATE_OP_TAG: op}
    try:
        gone = client.destroy_all(tags=tags, timeout=_SWEEP_TIMEOUT_S)
    except Exception as e:
        LOGGER.warning(
            "AerolVM create failed without a clear answer (%s), and the search for a sandbox it may have made "
            "failed too (%s). Delete it later with destroy_all(tags=%r).",
            err, e, tags,
        )
        return
    if gone:
        LOGGER.warning(
            "AerolVM create failed without a clear answer (%s); destroyed the sandbox it made anyway: %s",
            err, ", ".join(gone),
        )
        return
    LOGGER.warning(
        "AerolVM create failed without a clear answer (%s) and made no sandbox so far. One the server "
        "finishes later carries the tags %r; delete it with destroy_all(tags=%r).",
        err, tags, tags,
    )


def _destroy_abandoned(client: MicroVM, sandbox_id: str, op: str) -> None:
    try:
        client.destroy(sandbox_id)
    except Exception as e:
        if not (isinstance(e, MicroVMHTTPError) and e.status_code == 404):
            LOGGER.warning(
                "could not destroy AerolVM sandbox %s, whose create finished after its caller stopped waiting: %s. "
                "Delete it later with destroy_all(tags=%r).",
                sandbox_id, e, {CREATE_OP_TAG: op},
            )
        return
    LOGGER.info("destroyed AerolVM sandbox %s: its create finished after its caller stopped waiting", sandbox_id)
