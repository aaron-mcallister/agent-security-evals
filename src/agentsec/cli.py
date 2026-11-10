"""Command line interface: `agentsec list` and `agentsec run`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from .defenses import DEFENSES, make_defense
from .models import make_model
from .report import run_to_dict, to_markdown
from .runner import DEFAULT_MAX_STEPS, run_scenario
from .scenarios_loader import load_all


def _list(_: argparse.Namespace) -> int:
    for s in load_all():
        print(f"{s.id:28} {s.category:18} {','.join(s.variants()):15} {s.title}")
    return 0


def _run(args: argparse.Namespace) -> int:
    scenarios = load_all()
    if args.scenario:
        scenarios = [s for s in scenarios if s.id in set(args.scenario)]
    if args.category:
        scenarios = [s for s in scenarios if s.category in set(args.category)]
    if not scenarios:
        print("no scenarios selected", file=sys.stderr)
        return 2

    defenses = [d.strip() for d in args.defense.split(",") if d.strip()]
    for d in defenses:
        make_defense(d)  # validate early

    models = [m.strip() for m in args.model.split(",") if m.strip()]
    if any(not m.startswith("scripted:") for m in models) and not os.environ.get(
        "ANTHROPIC_API_KEY"
    ):
        print(
            "ANTHROPIC_API_KEY is not set. Export it in your shell (never pass it as an argument)."
            "\nUse --model scripted:naive or scripted:robust to try the harness without a key.",
            file=sys.stderr,
        )
        return 2

    n_runs = sum(len(s.variants()) for s in scenarios) * len(defenses) * len(models) * args.trials
    print(f"{n_runs} runs (up to {args.max_steps} model calls each)", file=sys.stderr)

    results = []
    for model_spec in models:
        model = make_model(model_spec, temperature=args.temperature)
        for dname in defenses:
            defense = make_defense(dname)
            for scenario in scenarios:
                for variant in scenario.variants():
                    for trial in range(args.trials):
                        r = run_scenario(scenario, variant, model, defense, trial, args.max_steps)
                        results.append(r)
                        flag = "ERR" if r.error else ("ATTACK" if r.attack_executed else "ok")
                        print(
                            f"{model.name:22} {dname:17} {scenario.id:26} {variant:8} "
                            f"t{trial} utility={r.utility} {flag}",
                            file=sys.stderr,
                        )

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out) / stamp
    out.mkdir(parents=True, exist_ok=True)
    with (out / "runs.jsonl").open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(run_to_dict(r)) + "\n")
    md = to_markdown(results)
    (out / "report.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Wrote {out}/runs.jsonl and report.md", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentsec", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list scenarios").set_defaults(fn=_list)

    r = sub.add_parser("run", help="run scenarios")
    r.add_argument(
        "--model",
        required=True,
        help="comma-separated: an Anthropic model id, or scripted:naive / scripted:robust",
    )
    r.add_argument("--defense", default="none", help=f"comma-separated from: {', '.join(DEFENSES)}")
    r.add_argument("--trials", type=int, default=1)
    r.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    r.add_argument("--temperature", type=float, default=None)
    r.add_argument("--scenario", action="append", help="scenario id (repeatable)")
    r.add_argument("--category", action="append", help="category (repeatable)")
    r.add_argument("--out", default="results")
    r.set_defaults(fn=_run)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
