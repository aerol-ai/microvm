"""AerolVM sandbox provider for the OpenAI Agents SDK.

Importing this package registers the ``"aerolvm"`` options and session-state
types with the SDK's registries, which is what lets a saved session state be
read back and resumed.
"""

from .client import AerolVMSandboxClient
from .options import (
    DEFAULT_EXEC_TIMEOUT_S,
    AerolVMSandboxClientOptions,
    AerolVMSandboxSessionState,
    ShutdownAction,
    WorkspacePersistence,
)
from .session import AerolVMSandboxSession

__all__ = [
    "DEFAULT_EXEC_TIMEOUT_S",
    "AerolVMSandboxClient",
    "AerolVMSandboxClientOptions",
    "AerolVMSandboxSession",
    "AerolVMSandboxSessionState",
    "ShutdownAction",
    "WorkspacePersistence",
]
