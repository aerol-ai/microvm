"""A whole DeepAgents graph run with the AerolVM backend and a scripted model.

The model asks for the ``write_file`` tool, then the ``execute`` tool, then
answers. Both must reach the sandbox through the backend, the way a real
model's tool calls would.
"""

from __future__ import annotations

from typing import Any

from deepagents import create_deep_agent
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, ToolMessage

from support import BackendTestCase


class ScriptedModel(FakeMessagesListChatModel):
    """Replies from a fixed list. Tool binding is a no-op: the script
    already names the tools."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedModel":
        return self


class AgentTest(BackendTestCase):
    def test_agent_writes_and_runs_a_file_in_the_sandbox(self) -> None:
        backend = self.backend()
        script = str(self.root / "hello.py")
        model = ScriptedModel(
            responses=[
                AIMessage(
                    content="",
                    tool_calls=[{"name": "write_file", "args": {"file_path": script, "content": "print('hi from aerolvm')\n"}, "id": "c1"}],
                ),
                AIMessage(
                    content="",
                    tool_calls=[{"name": "execute", "args": {"command": "python3 hello.py"}, "id": "c2"}],
                ),
                AIMessage(content="done"),
            ]
        )
        agent = create_deep_agent(model=model, backend=backend)

        state = agent.invoke({"messages": [{"role": "user", "content": "write and run hello.py"}]})

        self.assertEqual(state["messages"][-1].content, "done")
        tool_outputs = {m.tool_call_id: str(m.content) for m in state["messages"] if isinstance(m, ToolMessage)}
        self.assertIn("hi from aerolvm", tool_outputs["c2"])
        self.assertEqual((self.root / "hello.py").read_text(), "print('hi from aerolvm')\n")
        commands = [r.get("command") for r in self.exec_requests()]
        self.assertTrue(any("python3 hello.py" in (c or "") for c in commands))
