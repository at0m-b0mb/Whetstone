"""``whet`` — the human surface.

Four commands, each of which answers a question you want answered *before* an
exercise rather than during one:

``whet verbs``      What can this thing do?
``whet coverage``   Which of those attacks would nothing notice?
``whet check``      Is my engagement document valid, and what does it permit?
``whet plan``       Would this specific action be allowed, and why?

``plan`` is the important one and it deliberately does not run anything. It
takes the same path through :func:`whetstone.gate.policy.decide` that a real
submission would, prints the verdict and the rule that produced it, and stops.
You can therefore rehearse an entire engagement against the real policy without
touching a target — which is also how the training pipeline labels proposed
actions.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import verbs as _catalogue  # noqa: F401  (registers the catalogue)
from .actions import NO_DETECTION, REGISTRY, Intent, SchemaError, Side
from .gate import (
    Engagement,
    EngagementError,
    Verdict,
    decide,
    load_engagement,
    null_engagement,
    verify,
)

_SIDE_MARK = {Side.RED: "red ", Side.BLUE: "blue", Side.NEUTRAL: "    "}


def _load(path: str | None) -> Engagement:
    if not path:
        return null_engagement()
    return load_engagement(path)


def _cmd_verbs(args: argparse.Namespace) -> int:
    side = {"red": Side.RED, "blue": Side.BLUE, "neutral": Side.NEUTRAL}.get(args.side)
    selected = REGISTRY.select(side=side, group=args.group)
    if not selected:
        print("no verbs match that filter", file=sys.stderr)
        return 1

    current = ""
    for verb in selected:
        if verb.group != current:
            current = verb.group
            print(f"\n{current}")
        params = ", ".join(
            f"{p.name}:{p.type}" + ("" if p.required else "?") for p in verb.params
        )
        print(f"  [{_SIDE_MARK[verb.side]} {verb.intent.value:<7}] "
              f"{verb.id}({params})")
        print(f"      {verb.summary}")
        if verb.attck:
            print(f"      ATT&CK: {', '.join(verb.attck)}")
        if verb.detected_by:
            seen = ", ".join(verb.detected_by)
            note = "  ← nothing covers this yet" if NO_DETECTION in verb.detected_by else ""
            print(f"      detected by: {seen}{note}")
    print(f"\n{len(selected)} verb(s)")
    return 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    """Which attacks would nothing notice — a finding about Whetstone itself."""
    coverage = REGISTRY.coverage()
    if not coverage:
        print("no red verbs registered")
        return 0

    covered = {k: v for k, v in coverage.items() if v}
    gaps = sorted(k for k, v in coverage.items() if not v)

    print("detection coverage of the red catalogue\n")
    for verb_id in sorted(covered):
        print(f"  covered   {verb_id}")
        print(f"            ← {', '.join(covered[verb_id])}")
    for verb_id in gaps:
        verb = REGISTRY.get(verb_id)
        print(f"  GAP       {verb_id}  ({', '.join(verb.attck)})")
        print("            nothing in this catalogue would notice it")

    total = len(coverage)
    print(f"\n{len(covered)}/{total} red verbs have a detection; {len(gaps)} gap(s).")
    if gaps:
        print(
            "\nA gap here is a to-do for the blue side, not a defect. It is "
            "listed so that a report can say 'we did not test for this' rather "
            "than implying the technique was covered."
        )
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        engagement = _load(args.engagement)
    except EngagementError as exc:
        print(f"engagement invalid: {exc}", file=sys.stderr)
        return 2

    print(engagement.summary())

    state = engagement.window_state()
    if state != "open":
        print(f"\nthis engagement is {state}; every action would be denied")
        return 1

    permitted = [
        v for v in REGISTRY
        if decide(engagement, v, v.bind(
            {p.name: _placeholder(p) for p in v.params if p.required},
            target=_placeholder_target(v),
        )).verdict is not Verdict.DENY
    ]
    red = [v for v in permitted if v.side is Side.RED]
    print(f"\n{len(permitted)} of {len(REGISTRY)} verbs could run under this "
          f"engagement, {len(red)} of them red.")
    return 0


def _placeholder(param) -> object:
    return {
        "integer": 1, "boolean": False, "enum": param.choices[0] if param.choices else "",
    }.get(param.type, "placeholder")


def _placeholder_target(verb) -> str | None:
    from .actions import TargetKind
    if verb.target is TargetKind.NONE:
        return None
    if verb.target is TargetKind.PATH:
        return "/nonexistent/placeholder"
    return "127.0.0.1"


def _cmd_plan(args: argparse.Namespace) -> int:
    """Rule on one action without running it."""
    try:
        engagement = _load(args.engagement)
    except EngagementError as exc:
        print(f"engagement invalid: {exc}", file=sys.stderr)
        return 2

    params: dict[str, object] = {}
    for pair in args.param:
        if "=" not in pair:
            print(f"parameter {pair!r} is not name=value", file=sys.stderr)
            return 2
        name, _, value = pair.partition("=")
        params[name] = value

    try:
        action = REGISTRY.bind(args.verb, params, target=args.target)
    except SchemaError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    verb = REGISTRY.get(args.verb)
    decision = decide(engagement, verb, action)

    mark = {Verdict.ALLOW: "ALLOW  ", Verdict.CONFIRM: "CONFIRM", Verdict.DENY: "DENY   "}
    print(f"{mark[decision.verdict]} {action.render()}")
    print(f"        rule: {decision.rule}")
    print(f"        {decision.reason}")

    if verb.side is Side.RED and decision.verdict is not Verdict.DENY:
        print(f"\n        after this runs, the agent checks: "
              f"{', '.join(verb.detected_by)}")
        if NO_DETECTION in verb.detected_by:
            print("        nothing in the catalogue covers this technique — "
                  "silence afterwards would prove nothing")

    return 0 if decision.verdict is not Verdict.DENY else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    ok, message = verify(args.log)
    print(("ok   " if ok else "BROKEN ") + message)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="whet",
        description="Whetstone — purple-team agent runtime. "
                    "The red half exists to sharpen the blue half.",
    )
    p.add_argument("-e", "--engagement", metavar="FILE",
                   help="engagement document; without one, loopback and "
                        "observe-only")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verbs", help="list the action catalogue")
    v.add_argument("--side", choices=("red", "blue", "neutral"))
    v.add_argument("--group", help="e.g. enum, exploit, detect")
    v.set_defaults(func=_cmd_verbs)

    c = sub.add_parser("coverage", help="which attacks nothing would notice")
    c.set_defaults(func=_cmd_coverage)

    k = sub.add_parser("check", help="validate an engagement and show what it permits")
    k.set_defaults(func=_cmd_check)

    pl = sub.add_parser("plan", help="rule on one action without running it")
    pl.add_argument("verb")
    pl.add_argument("target", nargs="?")
    pl.add_argument("-p", "--param", action="append", default=[],
                    metavar="NAME=VALUE")
    pl.set_defaults(func=_cmd_plan)

    a = sub.add_parser("audit", help="verify an audit log's hash chain")
    a.add_argument("log")
    a.set_defaults(func=_cmd_audit)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
