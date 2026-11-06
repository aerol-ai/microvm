"""``BaseSandboxClient`` that runs Agents SDK sandbox sessions on AerolVM."""

from __future__ import annotations

import asyncio
import logging
import uuid

from agents.sandbox.manifest import Manifest
from agents.sandbox.session import SandboxSession, SandboxSessionState
from agents.sandbox.session.dependencies import Dependencies
from agents.sandbox.session.manager import Instrumentation
from agents.sandbox.session.sandbox_client import BaseSandboxClient
from agents.sandbox.snapshot import SnapshotBase, SnapshotSpec, resolve_snapshot
from microvm import MicroVM, MicroVMHTTPError

from .options import AerolVMSandboxClientOptions, AerolVMSandboxSessionState
from .session import AerolVMSandboxSession, create_request, is_not_found

logger = logging.getLogger(__name__)


class AerolVMSandboxClient(BaseSandboxClient[AerolVMSandboxClientOptions]):
    """Runs ``SandboxAgent`` work in AerolVM sandboxes.

    Pass a configured ``microvm.MicroVM``, or none to build one from
    ``SB_API_URL`` and ``SB_PAT_TOKEN``. Each ``create()`` makes one sandbox.
    """

    backend_id = "aerolvm"

    def __init__(
        self,
        client: MicroVM | None = None,
        *,
        instrumentation: Instrumentation | None = None,
        dependencies: Dependencies | None = None,
    ) -> None:
        self._client = client if client is not None else MicroVM()
        self._instrumentation = instrumentation or Instrumentation()
        self._dependencies = dependencies

    @property
    def client(self) -> MicroVM:
        return self._client

    async def create(
        self,
        *,
        snapshot: SnapshotSpec | SnapshotBase | None = None,
        manifest: Manifest | None = None,
        options: AerolVMSandboxClientOptions,
    ) -> SandboxSession:
        if options is None:
            raise ValueError("AerolVMSandboxClient.create requires AerolVMSandboxClientOptions")
        manifest = manifest if manifest is not None else Manifest()
        self._validate_manifest_for_create(manifest)

        session_id = uuid.uuid4()
        state = AerolVMSandboxSessionState(
            session_id=session_id,
            manifest=manifest,
            snapshot=resolve_snapshot(snapshot, str(session_id)),
            exposed_ports=options.exposed_ports,
            sandbox_id="",
            image=options.image,
            create_options=dict(options.create_options),
            workspace_persistence=options.workspace_persistence,
            on_shutdown=options.on_shutdown,
            exec_timeout_s=options.exec_timeout_s,
            max_output_bytes=options.max_output_bytes,
            snapshot_name_prefix=options.snapshot_name_prefix,
            delete_superseded_snapshots=options.delete_superseded_snapshots,
        )
        sandbox = await asyncio.to_thread(self._client.create, create_request(state))
        state.sandbox_id = sandbox.id
        inner = AerolVMSandboxSession(client=self._client, state=state)
        return self._wrap_session(inner, instrumentation=self._instrumentation)

    async def delete(self, session: SandboxSession) -> SandboxSession:
        # `_inner` belongs to the SDK's session wrapper, which only create()
        # and resume() hand out. getattr keeps a clear TypeError for anything
        # else instead of an AttributeError.
        inner = getattr(session, "_inner", None)
        if not isinstance(inner, AerolVMSandboxSession):
            raise TypeError("AerolVMSandboxClient.delete expects a session from create() or resume()")
        # shutdown() normally destroyed it already; this covers a session
        # that was never closed, or whose shutdown failed. A "stop" or "keep"
        # sandbox is left alone, because the caller chose to keep it.
        if inner.state.on_shutdown == "destroy":
            await inner.destroy_sandbox()
        return session

    async def resume(self, state: SandboxSessionState) -> SandboxSession:
        if not isinstance(state, AerolVMSandboxSessionState):
            raise TypeError("AerolVMSandboxClient.resume expects an AerolVMSandboxSessionState")
        state.assert_path_grants_rebound()

        preserved = await self._reattach(state)
        booted_from: str | None = None
        if not preserved:
            booted_from = await self._create_replacement(state)
        inner = AerolVMSandboxSession(client=self._client, state=state, booted_from_snapshot=booted_from)
        inner._set_start_state_preserved(preserved)
        return self._wrap_session(inner, instrumentation=self._instrumentation)

    def deserialize_session_state(self, payload: dict[str, object]) -> SandboxSessionState:
        return self._deserialize_session_state_payload(payload, AerolVMSandboxSessionState)

    # -- internals ---------------------------------------------------------

    async def _reattach(self, state: AerolVMSandboxSessionState) -> bool:
        """Whether the state's sandbox is usable again (started if stopped)."""
        try:
            sandbox = await asyncio.to_thread(self._client.get, state.sandbox_id)
        except Exception as e:
            # Only a missing sandbox justifies a replacement. Anything else
            # (the server unreachable, a 403) would orphan a sandbox that is
            # still running, so it propagates.
            if is_not_found(e):
                return False
            raise
        status = sandbox.to_dict().get("status")
        if status in ("error", "destroyed"):
            # A failed sandbox is not worth reusing; make sure it does not
            # linger next to its replacement.
            try:
                await asyncio.to_thread(self._client.destroy, state.sandbox_id)
            except Exception as e:
                if not is_not_found(e):
                    logger.warning("could not destroy failed sandbox %s: %s", state.sandbox_id, e)
            return False
        if status == "stopped":
            await asyncio.to_thread(self._client.start, state.sandbox_id)
        return True

    async def _create_replacement(self, state: AerolVMSandboxSessionState) -> str | None:
        """Make a new sandbox for a state whose sandbox is gone.

        It boots from the last AerolVM snapshot when there is one, so start()
        has nothing left to restore. Returns that snapshot's name, or None
        when the replacement started from the plain image (start() then
        restores the workspace from the SDK snapshot, if any).
        """
        state.workspace_root_ready = False
        if state.last_snapshot:
            try:
                sandbox = await asyncio.to_thread(
                    self._client.create, create_request(state, image=state.last_snapshot)
                )
            except MicroVMHTTPError as e:
                # A 4xx says the snapshot is gone or refused, and nothing was
                # made. Any other failure may have made a sandbox already,
                # so trying again from the image could make two.
                if not 400 <= e.status_code < 500:
                    raise
                logger.warning(
                    "could not boot from snapshot %s (%s); starting from %s", state.last_snapshot, e, state.image
                )
            else:
                state.sandbox_id = sandbox.id
                return state.last_snapshot
        sandbox = await asyncio.to_thread(self._client.create, create_request(state))
        state.sandbox_id = sandbox.id
        return None
