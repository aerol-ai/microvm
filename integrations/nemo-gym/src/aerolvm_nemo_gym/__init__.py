"""AerolVM sandbox provider for NVIDIA NeMo Gym.

Installing this package publishes the provider under the name ``aerolvm`` in
NeMo Gym's ``nemo_gym.sandbox_providers`` entry-point group, so a config
block ``sandbox: {aerolvm: {...}}`` selects it with no registration code.
"""

from .provider import (
    PROVIDER_NAME,
    AerolVMCreateError,
    AerolVMCreateVerificationError,
    AerolVMProvider,
)

__all__ = ["PROVIDER_NAME", "AerolVMCreateError", "AerolVMCreateVerificationError", "AerolVMProvider"]
