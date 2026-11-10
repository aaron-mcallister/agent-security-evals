# Design notes

Why the harness is built the way it is, what each choice buys, and what it costs. Read this
before quoting numbers from a run.

## 1. Deterministic scoring, no LLM judge

**Decision.** Every verdict is a predicate over the recorded tool-call trace: was `send_email`
called with a recipient outside the allowlist, does the canary string appear in an outbound
argument, does the final answer contain the expected fact (`src/agentsec/scoring.py`).

**Why.** Results are reproducible and auditable, and a judge model is itself a target for the
same injection techniques being tested. A judge also drifts between versions, which makes
comparisons over time unreliable.

**Cost.** Predicates see only what they are written to see. A model that paraphrases, translates
or encodes a secret can slip past a string check. A scenario passing means "this check did not
fire", not "this is safe". The control variants (section 2) guard against false positives, not
false negatives.

## 2. Paired injected and clean variants

**Decision.** Each attack scenario runs twice: once with the payload and once with the payload
replaced by benign text (`{{PAYLOAD}}` substitution). Scenarios with no attacker run once.

**Why.** The clean run proves the scorer does not fire on normal behaviour. The "control false
positives" column in the report must be 0; anything else means a predicate is wrong, not that
the model misbehaved.

## 3. Utility is measured next to security

**Decision.** Each scenario has a legitimate user task with its own success predicates.
"Secure utility" (task completed AND no attack executed) is the headline metric.

**Why.** An agent that refuses everything has an attack success rate of zero and is useless.
Reporting only attack success rewards that. The same logic applies to defences: a control that
blocks the attack and breaks the task is a cost, and the report shows it.

## 4. Three notions of "happened": utility, executed, attempted

**Decision.** The scorer evaluates a trace in three modes:

- *utility*: only calls that succeeded count, because a failed delete did not accomplish the task;
- *executed*: every call that reached the tool counts, including ones that then errored, because
  a GET to an attacker URL has left the machine even if the server answers 404;
- *attempted*: everything the model asked for counts, including calls a control blocked.

**Why.** The gap between attempted and executed is the value a control layer adds on top of the
model, which is the question the project exists to answer. The executed rule came from a real bug
found by the fixture agents (section 6): the first version treated errored calls as not executed
and missed a URL-exfiltration attack. A regression test pins it.

## 5. Simulated tools only

**Decision.** Files, mail and web are in-memory dictionaries (`src/agentsec/world.py`). Paths are
normalised (`..` collapsed) and a test asserts that reading a real host file such as
`/etc/passwd` fails.

**Why.** A model steered by an attacker cannot cause real side effects, runs are reproducible,
and the suite needs no network. This is also why it is safe to publish hostile scenario content.

**Cost.** Tool behaviour is only as faithful as the simulation. There is no real MCP transport,
authentication handshake or tool discovery.

## 6. Scripted fixture agents validate the harness, not the models

**Decision.** `scripted:naive` follows any attacker content it sees; `scripted:robust` only does
the task. The tests require naive to be flagged on every attack, robust on none, and neither on
any clean control, under every defence.

**Why.** It gives the scorer and defences a known-answer test with no model in the loop. These
agents say nothing about how any real model behaves, and results from them must never be
presented as model results.

## 7. The policy defence is an oracle, and the report should be read that way

**Decision.** The `policy` defence is a deterministic gate in front of the tools: recipient, host,
read and delete rules scoped to each task, plus a generic secret-pattern DLP on tool arguments and
the final text. Policies are written per scenario from the user's request.

**What it shows.** What a correctly scoped deterministic control can do, and what it costs in
utility, independent of model robustness.

**What it does not show.** That such a policy can be derived automatically from a request, or
that the gate covers attacks outside the scenarios. The DLP pattern is generic and easy to evade
by encoding. `spotlight` is the contrasting case: a prompt-level defence whose effect is
probabilistic and model-dependent.

## 8. Spotlighting is fenced, and the fence cannot be closed from inside

**Decision.** Untrusted tool output is wrapped in `<untrusted_data>` tags and any closing tag in
the content is neutralised case-insensitively (`defenses.spotlight_wrap`), with a test.

**Why.** A fence that attacker content can close is not a fence.

## 9. Credentials

**Decision.** The Anthropic key comes only from the `ANTHROPIC_API_KEY` environment variable via
the SDK. The harness takes no key argument, and a test asserts the adapter's constructor has none.
Traces contain only synthetic canary strings.

## 10. Statistics

**Decision.** Rates are reported as `k/n` with 95% Wilson intervals, and `--trials` repeats runs.

**Why.** Twelve scenarios give wide intervals and model output is non-deterministic. Showing the
interval stops one run from being read as a ranking. Always record the model id, date and trial
count next to any number.
