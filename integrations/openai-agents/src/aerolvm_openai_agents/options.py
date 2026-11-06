"""Options and session state for the AerolVM sandbox provider.

Both are pydantic models with a ``type`` discriminator. The Agents SDK keeps a
global registry of subclasses, filled when a subclass is defined, and uses it
to turn a saved session state back into the right provider's class. The
registry has no plugin discovery, so ``aerolvm_openai_agents`` must be
imported before ``BaseSandboxClient.deserialize_session_state`` (or
``Runner`` resuming a saved ``RunState``) can resolve ``"aerolvm"``.
"""

from __future__ import annotations

from typing import Any, Literal

from agents.sandbox.session import SandboxSessionState
from agents.sandbox.session.sandbox_client import BaseSandboxClientOptions
from pydantic import Field

# How persist_workspace() saves the workspace.
#
# "snapshot" saves the whole sandbox as an AerolVM snapshot (an image on the
# server) and hands the Agents SDK only a small reference to it. Restoring
# boots a new sandbox from that image, so installed packages come back too and
# nothing large crosses the network. It falls back to "tar" by itself when the
# manifest asks for paths to be left out of the snapshot, because an AerolVM
# snapshot cannot leave paths out.
#
# "tar" packs the workspace folder inside the sandbox and downloads it; the
# SDK's snapshot store then holds the bytes. Use it when the saved state must
# live outside the AerolVM server, or move between servers.
WorkspacePersistence = Literal["snapshot", "tar"]

# What shutdown() does to the sandbox when a run ends.
#
# "destroy" deletes it. A later resume makes a new sandbox and restores the
# workspace from the SDK snapshot, if one was configured.
# "stop" stops it: it keeps its disk but uses no CPU or memory, and resume
# starts it again with the workspace as it was, no snapshot needed.
# "keep" leaves it running, for debugging or a resume that must be instant.
# Use the sandbox's lifecycle (create_options["lifecycle"]) as a backstop so
# a forgotten "stop" or "keep" sandbox does not live forever.
ShutdownAction = Literal["destroy", "stop", "keep"]

# Used when the agent runs a command with no timeout. The SDK means "no
# limit", but toolboxd stops a command after 5 minutes when it is given none,
# which would surprise a long build. An hour is long enough for real work and
# still ends a command that hangs forever.
DEFAULT_EXEC_TIMEOUT_S = 3600.0


class AerolVMSandboxClientOptions(BaseSandboxClientOptions):
    """Per-run settings for :class:`~aerolvm_openai_agents.AerolVMSandboxClient`."""

    type: Literal["aerolvm"] = "aerolvm"

    image: str
    """Image (or AerolVM snapshot name) the sandbox starts from. It needs a
    POSIX shell, ``find`` and ``readlink`` (the SDK runs small shell helpers),
    plus ``tar`` for ``workspace_persistence="tar"``."""

    create_options: dict[str, Any] = Field(default_factory=dict)
    """Any other ``microvm.CreateOptions`` fields, such as ``cpu``,
    ``memoryMB``, ``runtime``, ``env``, ``networkAllowOut`` or ``lifecycle``.
    They are saved in the session state, because a resume that has to replace
    a lost sandbox must make it the same way. Keep secrets you would not store
    with your run state out of here."""

    exposed_ports: tuple[int, ...] = ()
    """Ports the agent may publish. ``resolve_exposed_port`` makes them public
    with ``expose_port`` the first time it is asked."""

    workspace_persistence: WorkspacePersistence = "snapshot"
    on_shutdown: ShutdownAction = "destroy"

    exec_timeout_s: float = DEFAULT_EXEC_TIMEOUT_S
    """Timeout for a command the agent runs without one."""

    max_output_bytes: int | None = None
    """Keep at most this many bytes of each command's stdout and of its
    stderr; the rest is dropped inside the sandbox. ``None`` keeps all of it.
    A cap stops one noisy command from filling the model's context."""

    snapshot_name_prefix: str = Field(default="openai-agents", pattern=r"^[a-z0-9][a-z0-9-]*$")
    """Snapshot names start with this, then the session id and a random
    suffix. Names are unique across the whole server, so pick a prefix that
    lets you find (and delete) your own. A new sandbox boots from a snapshot
    by naming it as its image, and an image name must be lowercase, so the
    prefix is lowercase letters, digits and dashes."""

    delete_superseded_snapshots: bool = False
    """Delete the previous AerolVM snapshot once a newer one is saved. Off by
    default: a run state you saved earlier may still point at the older
    snapshot (to fork an episode, say), and deleting it would make that state
    impossible to resume."""


class AerolVMSandboxSessionState(SandboxSessionState):
    """Everything needed to reattach to a sandbox from a later process.

    The creation settings are here because ``resume()`` may have to make a
    replacement sandbox, which has to be made the way the original was.
    Anything not recorded here would silently fall back to a default.
    Every field below ``sandbox_id`` has a default, so a state saved by an
    earlier version of this package still loads.
    """

    type: Literal["aerolvm"] = "aerolvm"

    sandbox_id: str
    image: str
    create_options: dict[str, Any] = Field(default_factory=dict)
    workspace_persistence: WorkspacePersistence = "snapshot"
    on_shutdown: ShutdownAction = "destroy"
    exec_timeout_s: float = DEFAULT_EXEC_TIMEOUT_S
    max_output_bytes: int | None = None
    snapshot_name_prefix: str = "openai-agents"
    delete_superseded_snapshots: bool = False

    last_snapshot: str | None = None
    """The AerolVM snapshot this session saved last, recorded only once the
    SDK's snapshot store has kept the reference to it. ``resume()`` boots a
    replacement sandbox straight from it, which saves a second create."""
