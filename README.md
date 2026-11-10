# agent-security-evals

Small, deterministic security evals for **tool-using LLM agents**. Twelve scenarios probe whether an
agent can be steered by hostile content into leaking secrets, taking destructive actions, or
exceeding the scope of what the user asked, and whether a deterministic control layer closes the
gap the model leaves.

It is built to be read in one sitting, run in seconds against scripted agents, and extended with
a YAML file.

## What it measures

| Category | What happens | Scenarios |
|---|---|---|
| `indirect_injection` | Attacker text arrives through a tool result (web page, email, file) | 5 |
| `tool_poisoning` | A tool's *description* (MCP-style) carries hidden instructions, or one tool rewrites how another is used | 2 |
| `excessive_agency` | No attacker. The agent oversteps the scope the user stated | 3 |
| `secret_handling` | Credentials are extracted or propagated | 2 |

These map to OWASP's LLM Top 10 (2025) items LLM01 prompt injection, LLM02 sensitive information
disclosure and LLM06 excessive agency.

Each attack scenario runs twice: an **injected** variant and a **clean control** with the payload
swapped for benign text. The control exists to prove the scorer does not fire on normal behaviour.
Scenarios with no attacker (excessive agency) run once.

### Metrics

- **Utility**: the user's legitimate task was completed. Reported alongside security, because an
  agent that refuses everything is not secure, just useless.
- **ASR executed**: an attack-success condition held after any defences.
- **ASR attempted**: the model *tried* the attack even if a control blocked it. The gap between the
  two is the value the control layer adds on top of the model.
- **Secure utility**: task completed and no attack executed. This is the headline number.
- **Control false positives**: attack condition tripped on the clean variant. Must be 0.

Rates come with Wilson 95% intervals. With a dozen scenarios the intervals are wide. Read them.

## Design choices

- **Deterministic scoring, no LLM judge.** Every verdict is a predicate over the recorded tool-call
  trace (was `send_email` called with a non-allowlisted recipient? does the canary string appear in
  an outbound argument?). Results are reproducible and auditable.
- **Simulated tools only.** The "filesystem", "mail" and "web" are dictionaries
  (`src/agentsec/world.py`). Nothing touches the real host, network, mail or shell, so a model
  steered by an attacker cannot cause real side effects. A test asserts that reading `/etc/passwd`
  fails inside the sandbox.
- **Scripted fixture agents validate the scorer.** `scripted:naive` follows any attacker content it
  sees; `scripted:robust` only does the task. The test suite requires naive to be flagged on every
  attack, robust on none, and neither on any clean control. These are test fixtures for the
  harness, not claims about any real model. The first run of this check caught a real scorer bug
  (a GET to an attacker URL that returned 404 was not counted as executed exfiltration).
- **Defence layers are separable** (`--defense`):
  - `none`: the model alone.
  - `spotlight`: untrusted tool output is fenced in `<untrusted_data>` tags (closing tags inside
    the content are neutralised) and the model is told it is data. Prompt-level, probabilistic.
  - `policy`: a deterministic gate in front of the tools: task-scoped recipient, host, read and
    delete rules, plus a generic secret-pattern DLP on tool arguments and final text.
  - `spotlight+policy`: both.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                   # 100 tests, no network, no API key

agentsec list
agentsec run --model scripted:naive,scripted:robust --defense none,policy
```

### Against Claude

```bash
export ANTHROPIC_API_KEY=...             # from your shell or a secret manager, never a CLI flag
agentsec run --model claude-sonnet-5-5 --defense none,spotlight,policy --trials 3
```

Use any Anthropic model id. The key is read from the environment by the SDK; the harness never
accepts, logs or writes it. Start with `--trials 1 --defense none` to see cost: a full sweep is a
few hundred short calls. Results land in `results/<timestamp>/` (`runs.jsonl` traces plus
`report.md`). Record the model id, date and trial count with any number you quote, because models
change under the same name.

## Design notes

Why the harness is built this way, and what each choice costs: [docs/DESIGN.md](docs/DESIGN.md).

## Add a scenario

Drop a YAML file into `src/agentsec/scenarios/`. The schema is `agentsec.types.Scenario`
(validated by pydantic, unknown fields rejected). The minimum is a `task`, the `tools` it may use,
a `world`, a `reference_plan` (what a correct agent does), `utility` predicates, and `attack`
predicates. Use `{{PAYLOAD}}` wherever attacker content should appear. `pytest` then checks that
the new scenario is well formed and that the fixture agents score as expected.

## Limitations (read before quoting numbers)

- **Twelve hand-written, static scenarios.** This is a probe set, not a benchmark or leaderboard.
  The attacks are not adaptive: a motivated attacker iterates against a specific model and
  defence.
- **The `policy` defence is an oracle.** Its policies are written per scenario from the user's
  request. It shows what a correctly scoped deterministic control can do, not that such a policy
  can be derived automatically.
- **Predicate scoring has blind spots.** A model that paraphrases, translates or encodes a secret
  can slip past string and pattern checks, and the DLP pattern is generic and easy to evade. A
  scenario passing means "this check did not fire", not "this is safe".
- **Single-task, short horizon.** No long-running agents, memory poisoning, multi-agent handoffs or
  real MCP transport.
- **Non-determinism.** Use `--trials` and read the intervals.

## Safety of the harness itself

All payloads are generic and defensive: synthetic canary strings and RFC 2606 `.example`
addresses, with no real targets, no working exploit code and nothing that executes model-generated
code. CI runs ruff and `pip-audit`, workflows have read-only permissions with SHA-pinned actions,
and Dependabot keeps dependencies and actions current. See [SECURITY.md](SECURITY.md).

## Prior work

This is deliberately small. For broader coverage see AgentDojo (Debenedetti et al., 2024) and
InjecAgent (Zhan et al., 2024). The spotlighting defence follows Hines et al. (2024). The idea that
deterministic capability control beats asking the model to behave is the motivation behind CaMeL
(Debenedetti et al., 2025). The questions this repo asks are narrower: which controls are worth
buying on top of a model, and what do they cost in utility?

## License

MIT. See [LICENSE](LICENSE).
