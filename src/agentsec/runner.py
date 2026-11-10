"""Agent loop: drive a model through one scenario variant inside the simulated world."""

from __future__ import annotations

from .defenses import Defense
from .models import AgentModel
from .scenarios_loader import render
from .scoring import TraceView, attack_ok, utility_ok
from .types import (
    CallRecord,
    RunResult,
    Scenario,
    ToolResult,
    ToolUse,
    Turn,
    Variant,
)
from .world import ToolError, World, execute, tool_specs, truncate

DEFAULT_MAX_STEPS = 10


def run_scenario(
    scenario: Scenario,
    variant: Variant,
    model: AgentModel,
    defense: Defense,
    trial: int = 0,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> RunResult:
    rendered = render(scenario, variant)
    world = World.from_seed(rendered.world, rendered.extra_tools)
    specs = tool_specs(scenario.tools, rendered.extra_tools)
    by_name = {s.name: s for s in specs}
    system = defense.system(rendered.system)

    turns: list[Turn] = [Turn(role="user", text=rendered.task)]
    calls: list[CallRecord] = []
    raw_text: list[str] = []
    text: list[str] = []
    stop, error, steps = "max_steps", None, 0

    model.begin(scenario, variant)
    try:
        while steps < max_steps:
            steps += 1
            turn = model.step(system, turns, specs)
            raw_text.append(turn.text)
            text.append(defense.filter_output(turn.text))
            turns.append(turn)
            if not turn.tool_uses:
                stop = "end"
                break
            results = [
                _run_tool(use, by_name, world, defense, scenario, calls) for use in turn.tool_uses
            ]
            turns.append(Turn(role="user", tool_results=results))
    except Exception as exc:  # noqa: BLE001 - provider/network errors must not abort a sweep
        stop, error = "error", f"{type(exc).__name__}: {exc}"

    final_raw = next((t for t in reversed(raw_text) if t), "")
    final = next((t for t in reversed(text) if t), "")
    executed_view = TraceView(calls, text, final)
    attempted_view = TraceView(calls, raw_text, final_raw)

    wants_utility = scenario.utility_on is None or variant in scenario.utility_on
    utility = utility_ok(scenario.utility, executed_view) if wants_utility else None
    return RunResult(
        scenario_id=scenario.id,
        category=scenario.category,
        variant=variant,
        model=model.name,
        defense=defense.name,
        trial=trial,
        calls=calls,
        assistant_text_raw=raw_text,
        assistant_text=text,
        final_text=final,
        utility=utility,
        attack_executed=attack_ok(scenario.attack, executed_view, "executed"),
        attack_attempted=attack_ok(scenario.attack, attempted_view, "attempted"),
        steps=steps,
        stop_reason=stop,
        error=error,
    )


def _run_tool(
    use: ToolUse,
    by_name: dict,
    world: World,
    defense: Defense,
    scenario: Scenario,
    calls: list[CallRecord],
) -> ToolResult:
    spec = by_name.get(use.name)
    if spec is None:
        msg = f"unknown tool: {use.name}"
        calls.append(CallRecord(use.name, use.args, msg, error=True))
        return ToolResult(use.id, msg, is_error=True)
    reason = defense.gate(use.name, use.args, scenario.policy)
    if reason:
        msg = f"BLOCKED by policy: {reason}"
        calls.append(CallRecord(use.name, use.args, msg, blocked=True))
        return ToolResult(use.id, msg, is_error=True)
    try:
        out = truncate(execute(world, spec, use.args))
    except ToolError as exc:
        calls.append(CallRecord(use.name, use.args, str(exc), error=True))
        return ToolResult(use.id, str(exc), is_error=True)
    calls.append(CallRecord(use.name, use.args, out))
    return ToolResult(use.id, defense.wrap_result(spec, out))
