"""whetbench — does the model actually know any security, or does it just sound like it?

Loss curves say a model is learning something. Generation samples say what, but
cherry-picked ones say whatever you want them to. This measures capabilities that
are **mechanically checkable**, so the answer is evidence rather than an opinion
about how plausible some text looked.

Every probe here has a ground truth that exists independently of the model:

*Schema fidelity.* A CVSS v3 vector is a grammar. Either the eight metrics are
present, in order, with legal values, or they are not. No judgement required.

*Identifier reality.* ``T1547.001`` either is in the real ATT&CK catalogue or it
is invented. The catalogue is on disk. A model that emits well-formed but
non-existent technique ids has learned the *shape* of an identifier without the
referent, and that distinction is invisible to loss and obvious here.

*Action validity.* The one task the model exists to do: emit an action the verb
registry accepts. ``REGISTRY.parse`` raises on a hallucinated verb, a missing
parameter or an invented parameter name, so the pass rate is exact.

*Register routing.* Prompted with PowerShell, does it continue in PowerShell —
or does it slide into whatever register dominates the corpus? This is the probe
that caught the corpus skew: the first ``tiny`` run answered CVE records to a
``Get-Process`` prompt, because advisory text outweighed shell text twelve to
one. Loss never mentioned it.

**On honesty.** Scores are reported per probe and never averaged into one number.
A single headline invites the reading "83% good", which is meaningless when the
probes measure unrelated things and a 14.6M model is expected to fail most of
them. The point of a benchmark on a small model is to show *which* capability
appeared first, not to award a grade.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

__all__ = ["Probe", "PROBES", "run_bench"]


# --------------------------------------------------------------------------
# checkers — each returns (passed, detail)
# --------------------------------------------------------------------------

_CVSS3 = re.compile(
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_CWE = re.compile(r"\bCWE-\d{1,4}\b")


def _real_techniques() -> set[str]:
    """Technique ids that genuinely exist, read from the cached ATT&CK bundle.

    Falls back to an empty set if the bundle is absent, and the probe then
    reports itself as skipped rather than silently passing everything — a skip
    that looks like a pass is the one outcome a benchmark must never produce.
    """
    import gzip

    for candidate in (
        Path("/Volumes/at0m_b0mb/whetstone/corpus/raw/attack/enterprise-attack.json.gz"),
        Path("data/corpus/raw/attack/enterprise-attack.json.gz"),
    ):
        if not candidate.is_file():
            continue
        try:
            with gzip.open(candidate, "rt", encoding="utf-8") as fh:
                bundle = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        out: set[str] = set()
        for obj in bundle.get("objects", ()):
            for ref in obj.get("external_references", ()) or ():
                ident = ref.get("external_id", "")
                if ref.get("source_name") == "mitre-attack" and _TECHNIQUE.fullmatch(ident):
                    out.add(ident)
        return out
    return set()


REAL_TECHNIQUES: set[str] = _real_techniques()


def check_cvss(text: str) -> tuple[bool, str]:
    """A syntactically complete CVSS v3 vector anywhere in the continuation."""
    m = _CVSS3.search(text)
    if m:
        return True, m.group(0)
    loose = re.search(r"CVSS:3\.[01]/\S+", text)
    return False, f"malformed: {loose.group(0)[:48]}" if loose else "no vector emitted"


def check_technique_real(text: str) -> tuple[bool, str]:
    """Emitted technique ids must exist in the real ATT&CK catalogue."""
    found = _TECHNIQUE.findall(text)
    if not found:
        return False, "no technique id emitted"
    if not REAL_TECHNIQUES:
        return False, "SKIP: ATT&CK bundle not available to check against"
    real = [t for t in found if t in REAL_TECHNIQUES]
    return bool(real), (f"{len(real)}/{len(found)} real — "
                        f"{', '.join(found[:4])}")


def check_cve_shape(text: str) -> tuple[bool, str]:
    m = _CVE.search(text)
    return (True, m.group(0)) if m else (False, "no well-formed CVE id")


def check_cwe_shape(text: str) -> tuple[bool, str]:
    m = _CWE.search(text)
    return (True, m.group(0)) if m else (False, "no CWE id")


def extract_json_object(text: str) -> str | None:
    """First balanced ``{...}`` in ``text``, or None.

    A non-greedy ``\\{.*?\\}`` cannot do this and the difference is not
    academic: an action is ``{"verb":"enum.host","params":{},"target":"..."}``
    and the lazy match stops at the ``}`` closing the empty ``params``, handing
    the parser ``{"verb":"enum.host","params":{}`` — invalid JSON. The benchmark
    scored a correct model 0/5 and reported "Expecting ',' delimiter" as though
    the model had produced malformed output. Brace depth, tracked properly, with
    string literals and escapes respected so a brace inside a value does not
    close the object.
    """
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def check_action_json(text: str) -> tuple[bool, str]:
    """The task the model exists for: emit an action the registry accepts."""
    from whetstone.actions import REGISTRY, SchemaError
    import whetstone.verbs  # noqa: F401

    blob = extract_json_object(text)
    if blob is None:
        return False, "no JSON object emitted"
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError as exc:
        return False, f"unparseable: {exc.msg} — {blob[:44]}"
    try:
        action = REGISTRY.parse(payload)
    except SchemaError as exc:
        return False, f"rejected: {str(exc)[:66]}"
    return True, action.render()[:70]


def _register_checker(markers: tuple[str, ...], label: str) -> Callable[[str], tuple[bool, str]]:
    def check(text: str) -> tuple[bool, str]:
        hits = [m for m in markers if m.lower() in text.lower()]
        return bool(hits), (f"{label}: {', '.join(hits[:3])}" if hits
                            else f"drifted out of {label}")
    return check


check_shell = _register_checker(
    ("get-", "set-", "new-", "| select", "-command", "$_", "sudo", "systemctl",
     "/etc/", "chmod", "grep", "ps -", "netstat", "launchctl"), "shell")
check_detection = _register_checker(
    ("detection:", "selection:", "condition:", "logsource", "eventid",
     "falsepositives", "level:", "index=", "| stats"), "detection")


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------


@dataclass
class Probe:
    """One capability, its prompt, and a mechanical check."""

    name: str
    prompt: str
    check: Callable[[str], tuple[bool, str]]
    #: What a pass actually demonstrates. Printed with the result so a number is
    #: never separated from its meaning.
    measures: str
    samples: int = 5
    max_tokens: int = 90
    results: list[tuple[bool, str]] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for ok, _ in self.results if ok)

    @property
    def skipped(self) -> bool:
        return bool(self.results) and all(
            d.startswith("SKIP") for _ok, d in self.results)


def _action_prompt() -> str:
    """A realistic trajectory prefix, ending at the point the model must act."""
    from whetstone.actions import REGISTRY, Intent, TargetKind
    import whetstone.verbs  # noqa: F401

    from training.tokenizer.protocol import ACT, BOS, HOST, SCOPE, TASK, VERBS

    catalogue = "; ".join(
        f"{v.id}({', '.join(p.name for p in v.params)})"
        for v in REGISTRY.select(intent=Intent.OBSERVE)
        if v.target is TargetKind.HOST)[:400]
    return (f"{BOS}{TASK}Find anything on this host that runs without a human "
            f"starting it.{HOST}macos{SCOPE}observe; loopback only; no red "
            f"verbs{VERBS}{catalogue}{ACT}")


_ACTION_PROMPT = _action_prompt()


PROBES: list[Probe] = [
    Probe("cvss-vector", "CVE-2024-",
          check_cvss,
          "can produce a grammatically valid CVSS v3 vector — 8 metrics, in "
          "order, legal values"),
    Probe("cve-shape", "A new vulnerability was published as ",
          check_cve_shape,
          "has learned the CVE identifier format"),
    Probe("cwe-shape", "CVE-2023-4863\ncvss: 8.8 HIGH\n",
          check_cwe_shape,
          "associates a weakness class with a vulnerability record"),
    Probe("attck-real", "The adversary used technique ",
          check_technique_real,
          "emits ATT&CK ids that EXIST, not just ids that look right — the "
          "difference between learning a referent and learning a shape"),
    Probe("shell-routing", "PS C:\\> Get-Process | ",
          check_shell,
          "stays in the shell register when prompted in it, rather than "
          "sliding into whatever register dominates the corpus"),
    Probe("detection-routing", "title: Suspicious Process Creation\nlogsource:\n",
          check_detection,
          "continues a detection rule as a detection rule"),
    # Prompted in the WIRE PROTOCOL, because that is what the model was trained
    # on. The first version prompted with a bare `{"verb": "enum.` fragment,
    # which resembles nothing in any trajectory: the model had no reason to
    # continue it as an action and the probe measured prompt mismatch rather
    # than capability. A probe must speak the format it is testing.
    Probe("action-json", _ACTION_PROMPT,
          check_action_json,
          "THE TASK: emit an action the verb registry accepts. Hallucinated "
          "verbs, missing params and invented param names all fail here",
          max_tokens=48),
]


#: Task -> verbs a competent operator would accept as a first move. Several are
#: right for each, so this measures judgement rather than guessing one answer.
VERB_CHOICE_TASKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Find anything that runs without a human starting it.",
     ("enum.persistence", "enum.services", "detect.persistence_change")),
    ("Check what network services are exposed on this machine.",
     ("enum.network", "enum.services", "enum.shares")),
    ("Establish who I am on this box and what privileges I hold.",
     ("enum.privileges", "enum.users")),
    ("Would this host see an attack if one happened?",
     ("detect.telemetry", "detect.process_creation", "detect.persistence_change",
      "detect.credential_access", "detect.authentication")),
    ("Look for credentials left somewhere they should not be.",
     ("vuln.credential_exposure", "enum.users", "detect.credential_access")),
    ("Is any installed software known-vulnerable?",
     ("vuln.patch_gap", "enum.software")),
    ("Find a route from my current account to administrator.",
     ("vuln.privilege_path", "enum.privileges", "vuln.weak_permissions")),
    ("List the processes running right now.",
     ("enum.processes",)),
)


def verb_choice_score(model: Any, tok: Any) -> tuple[int, int, list[str]]:
    """Constrained decoding: does the model pick a *sensible* verb?

    Separated from ``action-json`` on purpose. That probe conflated two things —
    whether the model can write valid JSON, and whether it picks the right verb —
    and reported the sum as capability. With constrained decoding the first is
    guaranteed by construction, so what remains is judgement, and judgement is
    the thing that should improve with training. Measuring them together meant a
    syntax failure and a reasoning failure were the same number.
    """
    import whetstone.verbs  # noqa: F401

    from whetstone.actions import REGISTRY, TargetKind
    from whetstone.gate import Gate, null_engagement
    from training.constrained import decode_action
    from training.tokenizer.protocol import ACT, BOS, HOST, SCOPE, TASK, VERBS

    gate = Gate(null_engagement(), registry=REGISTRY)
    permitted = [v for v in gate.catalogue() if v.target is TargetKind.HOST]
    catalogue = "; ".join(
        f"{v.id}({', '.join(p.name for p in v.params)})" for v in permitted)[:400]

    hits = 0
    detail: list[str] = []
    for task, acceptable in VERB_CHOICE_TASKS:
        prompt = (f"{BOS}{TASK}{task}{HOST}macos{SCOPE}observe; loopback only"
                  f"{VERBS}{catalogue}{ACT}")
        got = decode_action(model, tok, prompt, permitted=permitted,
                            target="127.0.0.1")
        ok = got.verb.id in acceptable
        hits += ok
        detail.append(f"{'✓' if ok else '·'} {task[:38]:<40} -> {got.verb.id}")
    return hits, len(VERB_CHOICE_TASKS), detail


def run_bench(checkpoint: Path, tokenizer: Path, *, temperature: float = 0.7,
              seed: int = 0, only: list[str] | None = None) -> list[Probe]:
    from tokenizers import Tokenizer

    from training.generate import generate, load_for_inference

    model, cfg = load_for_inference(checkpoint)
    tok = Tokenizer.from_file(str(tokenizer))
    step = json.loads((checkpoint / "state.json").read_text())["step"]

    probes = [p for p in PROBES if not only or p.name in only]

    print(f"whetbench — {cfg.name} {cfg.n_params/1e6:.1f}M params, step {step:,}")
    print(f"{'probe':<20}{'pass':>8}   measures")
    print("-" * 96)

    for probe in probes:
        for i in range(probe.samples):
            text = generate(model, tok, probe.prompt,
                            max_tokens=probe.max_tokens,
                            temperature=temperature, seed=seed + i)
            probe.results.append(probe.check(probe.prompt + text))

        rate = probe.passed / max(len(probe.results), 1)
        mark = "SKIP" if probe.skipped else f"{probe.passed}/{len(probe.results)}"
        print(f"{probe.name:<20}{mark:>8}   {probe.measures[:64]}")
        for ok, detail in probe.results[:2]:
            print(f"{'':<20}{'✓' if ok else '·':>8}   {detail[:64]}")
        print()

    return probes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Benchmark a Whetstone checkpoint.")
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--tokenizer", type=Path, required=True)
    p.add_argument("--temperature", type=float, default=0.7)
    p.add_argument("--samples", type=int, default=None)
    p.add_argument("--only", nargs="*")
    p.add_argument("--json", type=Path, help="also write results here")
    args = p.parse_args(argv)

    if args.samples:
        for probe in PROBES:
            probe.samples = args.samples

    probes = run_bench(args.checkpoint, args.tokenizer,
                       temperature=args.temperature, only=args.only)

    # Constrained decoding is reported separately because it answers a
    # different question: not "can it write an action" but "does it choose a
    # sensible one". Validity is guaranteed there, so a low score here is
    # judgement and nothing else.
    if not args.only or "verb-choice" in args.only:
        from training.generate import load_for_inference
        from tokenizers import Tokenizer as _T
        _model, _cfg = load_for_inference(args.checkpoint)
        _tok = _T.from_file(str(args.tokenizer))
        hits, total, detail = verb_choice_score(_model, _tok)
        print(f"{'verb-choice':<20}{f'{hits}/{total}':>8}   CONSTRAINED decoding: "
              f"validity is guaranteed, so this is judgement alone")
        for line in detail:
            print(f"{'':<20}{'':>8}   {line}")
        print()

    print("-" * 96)
    print("Deliberately not averaged into one score: these probes measure "
          "unrelated capabilities,\nand a single headline would imply a grade "
          "where what matters is WHICH capability appeared.")

    if args.json:
        args.json.write_text(json.dumps([
            {"probe": p.name, "passed": p.passed, "of": len(p.results),
             "measures": p.measures,
             "details": [d for _ok, d in p.results]}
            for p in probes], indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
