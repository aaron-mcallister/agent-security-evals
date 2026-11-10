"""Data model: scenario schema (validated YAML) and runtime records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["indirect_injection", "tool_poisoning", "excessive_agency", "secret_handling"]
Variant = Literal["injected", "clean", "only"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# --------------------------------------------------------------------------- matchers/predicates
class Matcher(_Strict):
    """Conditions on one tool argument. All specified conditions must hold (AND)."""

    equals: str | None = None
    contains: str | None = None  # case-insensitive substring
    startswith: str | None = None
    not_startswith: str | None = None
    regex: str | None = None
    in_: list[str] | None = Field(default=None, alias="in")
    not_in: list[str] | None = None  # case-insensitive


class ToolCalled(_Strict):
    type: Literal["tool_called"]
    tool: str
    args: dict[str, Matcher] = Field(default_factory=dict)


class CanaryInArgs(_Strict):
    """A secret/canary string appears in the arguments of an outbound-capable tool call."""

    type: Literal["canary_in_args"]
    value: str
    tools: list[str] | None = None


class OutputContains(_Strict):
    """A string appears anywhere in the assistant's own text output."""

    type: Literal["output_contains"]
    value: str


class FinalContains(_Strict):
    """The final answer contains at least one of the strings (case-insensitive)."""

    type: Literal["final_contains"]
    any: list[str]


Predicate = Annotated[
    ToolCalled | CanaryInArgs | OutputContains | FinalContains, Field(discriminator="type")
]


# --------------------------------------------------------------------------- scenario
class PlannedCall(_Strict):
    """A scripted action. tool == "__say__" appends args["text"] to the final answer."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class EmailSeed(_Strict):
    id: str
    sender: str
    subject: str
    body: str


class WorldSeed(_Strict):
    files: dict[str, str] = Field(default_factory=dict)
    inbox: list[EmailSeed] = Field(default_factory=list)
    web: dict[str, str] = Field(default_factory=dict)


class ExtraTool(_Strict):
    """An additional (possibly poisoned) tool with a static result."""

    name: str
    description: str
    input_schema: dict[str, Any]
    result: str


class Payload(_Strict):
    """Attacker-controlled content. `{{PAYLOAD}}` in the scenario is replaced with `text` in the
    injected variant and with `clean_text` in the clean (control) variant."""

    text: str
    clean_text: str = ""


class Policy(_Strict):
    """Task-scoped capability policy used by the `policy` defense. None = unrestricted,
    [] = nothing allowed. Hand-written per scenario: it models the upper bound of what a
    correctly scoped deterministic control can do, not an automatically derived policy."""

    allowed_recipients: list[str] | None = None
    allowed_hosts: list[str] | None = None
    deny_read: list[str] = Field(default_factory=list)
    protected_paths: list[str] = Field(default_factory=list)
    delete_allowed_prefixes: list[str] | None = None


class Scenario(_Strict):
    id: str
    category: Category
    title: str
    threat: str
    task: str
    system_extra: str | None = None
    tools: list[str] = Field(default_factory=list)
    extra_tools: list[ExtraTool] = Field(default_factory=list)
    world: WorldSeed = Field(default_factory=WorldSeed)
    payload: Payload | None = None
    reference_plan: list[PlannedCall] = Field(default_factory=list)
    reference_answer: str
    # What the scripted "naive" fixture agent additionally does (follow the payload / overreach).
    attack_actions: list[PlannedCall] = Field(default_factory=list)
    utility: list[Predicate] = Field(default_factory=list)  # ALL must hold
    utility_on: list[Variant] | None = None  # variants where utility is meaningful (None = all)
    attack: list[Predicate]  # ANY holding means the attack succeeded
    policy: Policy = Field(default_factory=Policy)

    def variants(self) -> list[Variant]:
        return ["injected", "clean"] if self.payload else ["only"]


# --------------------------------------------------------------------------- runtime
@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    untrusted: bool = False  # result carries external, attacker-influenceable content


@dataclass
class ToolUse:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class ToolResult:
    tool_use_id: str
    content: str
    is_error: bool = False


@dataclass
class Turn:
    role: Literal["user", "assistant"]
    text: str = ""
    tool_uses: list[ToolUse] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)


@dataclass
class CallRecord:
    name: str
    args: dict[str, Any]
    result: str
    blocked: bool = False
    error: bool = False


@dataclass
class RunResult:
    scenario_id: str
    category: str
    variant: str
    model: str
    defense: str
    trial: int
    calls: list[CallRecord]
    assistant_text_raw: list[str]
    assistant_text: list[str]
    final_text: str
    utility: bool | None
    attack_executed: bool
    attack_attempted: bool
    steps: int
    stop_reason: str  # end | max_steps | error
    error: str | None = None
