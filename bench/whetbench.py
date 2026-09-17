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


def check_action_json(text: str) -> tuple[bool, str]:
    """The task the model exists for: emit an action the registry accepts."""
    from whetstone.actions import REGISTRY, SchemaError
    import whetstone.verbs  # noqa: F401

    candidate = re.search(r"\{.*?\}", text, re.S)
    if not candidate:
        return False, "no JSON object emitted"
    blob = candidate.group(0)
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError:
        return False, f"unparseable JSON: {blob[:56]}"
    try:
        action = REGISTRY.parse(payload)
    except SchemaError as exc:
        return False, f"rejected: {str(exc)[:70]}"
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
    Probe("action-json", '{"verb": "enum.',
          check_action_json,
          "THE TASK: emit an action the verb registry accepts. Hallucinated "
          "verbs, missing params and invented param names all fail here"),
]


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
