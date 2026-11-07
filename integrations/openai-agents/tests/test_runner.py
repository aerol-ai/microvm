"""A whole agent run through ``Runner.run``, with a scripted model.

This is what a user writes: the agent is unchanged and only the run config
names the AerolVM client. The model asks for one shell command, then
answers. The run must create the sandbox, run the command in it, and on the
way out save the workspace and destroy the sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents import Runner, set_tracing_disabled
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.run import RunConfig
from agents.sandbox import SandboxAgent, SandboxRunConfig
from agents.sandbox.capabilities import Shell
from agents.sandbox.snapshot import LocalSnapshotSpec
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from aerolvm_openai_agents.session import decode_snapshot_ref
from support import ProviderTestCase

set_tracing_disabled(True)


class ScriptedModel(Model):
    """Calls exec_command once, then replies with the tool's output."""

    def __init__(self) -> None:
        self.tool_outputs: list[str] = []

    async def get_response(self, system_instructions: Any, input: Any, *args: Any, **kwargs: Any) -> ModelResponse:
        outputs = [item for item in input if isinstance(item, dict) and item.get("type") == "function_call_output"]
        if not outputs:
            call = ResponseFunctionToolCall(
                id="fc_1",
                call_id="call_1",
                name="exec_command",
                type="function_call",
                status="completed",
                arguments=json.dumps({"cmd": "echo built > out.txt && cat out.txt", "login": False}),
            )
            return ModelResponse(output=[call], usage=Usage(), response_id=None)
        self.tool_outputs.append(str(outputs[-1]["output"]))
        message = ResponseOutputMessage(
            id="msg_1",
            role="assistant",
            status="completed",
            type="message",
            content=[ResponseOutputText(type="output_text", text="done", annotations=[])],
        )
        return ModelResponse(output=[message], usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any):  # pragma: no cover - not used
        raise NotImplementedError


class RunnerTest(ProviderTestCase):
    async def test_agent_run_uses_the_sandbox_and_cleans_up(self) -> None:
        model = ScriptedModel()
        agent = SandboxAgent(name="builder", model=model, capabilities=[Shell()], default_manifest=self.manifest())
        store = self.tmp / "snapshots"
        run_config = RunConfig(
            sandbox=SandboxRunConfig(
                client=self.client,
                options=self.options(),
                snapshot=LocalSnapshotSpec(base_path=store),
            )
        )

        result = await Runner.run(agent, "build it", run_config=run_config)

        self.assertEqual(result.final_output, "done")
        self.assertIn("built", model.tool_outputs[0])
        self.assertEqual((self.workspace / "out.txt").read_text(), "built\n")
        # The run saved the workspace as an AerolVM snapshot and then
        # destroyed the sandbox it made.
        (saved,) = list(store.iterdir())
        self.assertIn(decode_snapshot_ref(saved.read_bytes()), self.fake.snapshots)
        self.assertEqual(len(self.fake.calls_to("create")), 1)
        self.assertEqual(self.fake.sandboxes, {})
        # The command ran with argv, in the workspace root.
        commands = [r for r in self.exec_requests() if "echo built" in " ".join(r.get("argv") or [])]
        self.assertEqual(commands[0]["workDir"], str(self.workspace))
        self.assertTrue(Path(commands[0]["workDir"]).is_dir())
