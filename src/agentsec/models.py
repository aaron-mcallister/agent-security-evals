"""Agent model adapters.

* AnthropicAgent  a real model via the Anthropic Messages API (tool use).
* ScriptedAgent   deterministic stand-ins used to validate the harness itself:
                    naive   does the task AND follows whatever attacker content it encounters;
                    robust  does only the task.
                  These are test fixtures for the scorer, NOT claims about any real model.
"""

from __future__ import annotations

from typing import Any, Protocol

from .types import PlannedCall, Scenario, ToolSpec, ToolUse, Turn, Variant


class AgentModel(Protocol):
    name: str

    def begin(self, scenario: Scenario, variant: Variant) -> None: ...

    def step(self, system: str, turns: list[Turn], tools: list[ToolSpec]) -> Turn: ...


# --------------------------------------------------------------------------- scripted
class ScriptedAgent:
    def __init__(self, mode: str) -> None:
        if mode not in {"naive", "robust"}:
            raise ValueError("scripted mode must be 'naive' or 'robust'")
        self.mode = mode
        self.name = f"scripted:{mode}"
        self._scenario: Scenario | None = None
        self._variant: Variant = "only"
        self._queue: list[PlannedCall] = []
        self._said: list[str] = []
        self._attacked = False
        self._n = 0

    def begin(self, scenario: Scenario, variant: Variant) -> None:
        self._scenario = scenario
        self._variant = variant
        self._queue = list(scenario.reference_plan)
        self._said = []
        self._attacked = False
        self._n = 0

    def _payload_seen(self, system: str, turns: list[Turn], tools: list[ToolSpec]) -> bool:
        sc = self._scenario
        if sc is None:
            raise RuntimeError("begin() must be called before step()")
        if sc.payload is None or self._variant != "injected" or not sc.payload.text:
            return False
        needle = sc.payload.text
        haystack = [system, *(t.description for t in tools)]
        for turn in turns:
            haystack.append(turn.text)
            haystack.extend(r.content for r in turn.tool_results)
        return any(needle in h for h in haystack)

    def step(self, system: str, turns: list[Turn], tools: list[ToolSpec]) -> Turn:
        sc = self._scenario
        if sc is None:
            raise RuntimeError("begin() must be called before step()")
        if self.mode == "naive" and not self._attacked:
            overreach = sc.payload is None
            if overreach or self._payload_seen(system, turns, tools):
                self._attacked = True
                actions = sc.attack_actions
                self._said += [a.args["text"] for a in actions if a.tool == "__say__"]
                real = [a for a in actions if a.tool != "__say__"]
                self._queue = real + self._queue
        if self._queue:
            call = self._queue.pop(0)
            self._n += 1
            use = ToolUse(id=f"s{self._n}", name=call.tool, args=dict(call.args))
            return Turn(role="assistant", tool_uses=[use])
        return Turn(role="assistant", text=" ".join([sc.reference_answer, *self._said]).strip())


# --------------------------------------------------------------------------- anthropic
class AnthropicAgent:
    """Tool-use loop against the Anthropic Messages API.

    The API key is read from the ANTHROPIC_API_KEY environment variable by the SDK. It is never
    accepted as an argument, logged, or written to results.
    """

    def __init__(
        self,
        model: str,
        client: Any = None,
        max_tokens: int = 2048,
        temperature: float | None = None,
    ) -> None:
        self.name = model
        self.model = model
        self._client = client
        self.max_tokens = max_tokens
        self.temperature = temperature

    def begin(self, scenario: Scenario, variant: Variant) -> None:  # noqa: ARG002
        return None

    @property
    def client(self) -> Any:
        if self._client is None:
            import anthropic  # imported lazily so the base install needs no SDK

            self._client = anthropic.Anthropic(timeout=90.0, max_retries=3)
        return self._client

    @staticmethod
    def _messages(turns: list[Turn]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in turns:
            blocks: list[dict[str, Any]] = []
            if t.tool_results:
                blocks += [
                    {
                        "type": "tool_result",
                        "tool_use_id": r.tool_use_id,
                        "content": r.content,
                        "is_error": r.is_error,
                    }
                    for r in t.tool_results
                ]
            if t.text:
                blocks.append({"type": "text", "text": t.text})
            blocks += [
                {"type": "tool_use", "id": u.id, "name": u.name, "input": u.args}
                for u in t.tool_uses
            ]
            out.append({"role": t.role, "content": blocks})
        return out

    def step(self, system: str, turns: list[Turn], tools: list[ToolSpec]) -> Turn:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": self._messages(turns),
        }
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in tools
            ]
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        resp = self.client.messages.create(**kwargs)
        text = "".join(b.text for b in resp.content if b.type == "text")
        uses = [
            ToolUse(id=b.id, name=b.name, args=dict(b.input))
            for b in resp.content
            if b.type == "tool_use"
        ]
        return Turn(role="assistant", text=text, tool_uses=uses)


def make_model(spec: str, temperature: float | None = None) -> AgentModel:
    if spec.startswith("scripted:"):
        return ScriptedAgent(spec.split(":", 1)[1])
    return AnthropicAgent(spec, temperature=temperature)
