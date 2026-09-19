#!/usr/bin/env python3
"""A live view of the whole pipeline, read from the logs it already writes.

    python3 scripts/watch_training.py

Follows whichever stage is running — corpus, tokenizer, shards, pretrain, SFT,
verify — and renders the one in flight with the detail that stage actually has.
Pretraining has a validation curve and a token rate; fine-tuning has epochs and
a masked loss and no token rate at all, and showing either one's shape for the
other is how a watcher ends up lying about a run.

It reads the supervisor's own logs rather than instrumenting the training loop.
That means it attaches to a run already in flight, survives being closed and
reopened, and cannot perturb what it is watching — the alternative adds a
failure mode to the thing you least want to add failure modes to.

Ctrl-C stops the watcher. It does not stop the training.
"""

from __future__ import annotations

import json
import math
import re
import sys
import time
from pathlib import Path

D = Path("/Volumes/at0m_b0mb/whetstone")
RUN = D / "runs/overnight-v5"

STAGES = [("1", "corpus"), ("2", "tokenizer"), ("3", "shards"),
          ("4", "pretrain"), ("5", "sft"), ("6", "verify")]

PRE = re.compile(r"^step\s+([\d,]+)/([\d,]+)\s+loss\s+([\d.]+)\s+lr\s+([\d.e+-]+)\s+"
                 r"\|g\|\s+([\d.]+)\s+([\d,]+) tok/s")
SFT = re.compile(r"^epoch\s+(\d+)/(\d+)\s+step\s+([\d,]+)/([\d,]+)\s+loss\s+([\d.]+)\s+"
                 r"lr\s+([\d.e+-]+)\s+\|g\|\s+([\d.]+)")
VAL = re.compile(r"val loss ([\d.]+)\s+\(ppl ([\d.]+)\)(\s+← best)?")

C = {"dim": "\033[2m", "b": "\033[1m", "g": "\033[32m", "y": "\033[33m",
     "c": "\033[36m", "r": "\033[31m", "m": "\033[35m", "x": "\033[0m"}


def _n(s: str) -> int:
    return int(s.replace(",", ""))


def markers() -> set[str]:
    d = RUN / "markers"
    return {p.name for p in d.iterdir()} if d.is_dir() else set()


def current_stage() -> tuple[str, str] | None:
    """The first stage with no completion marker — the one in flight."""
    done = markers()
    for num, name in STAGES:
        if f"{num}-{name}" not in done:
            return num, name
    return None


def sparkline(values: list[float], width: int = 46) -> str:
    if len(values) < 2:
        return ""
    blocks = "▁▂▃▄▅▆▇█"
    pts = values[-width:]
    lo, hi = min(pts), max(pts)
    if hi - lo < 1e-9:
        return blocks[0] * len(pts)
    return "".join(blocks[min(7, int((v - lo) / (hi - lo) * 7.99))] for v in pts)


def bar(frac: float, width: int = 42) -> str:
    return "█" * int(frac * width) + "░" * (width - int(frac * width))


def hms(sec: float) -> str:
    sec = max(0, int(sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


def stage_strip(cur: tuple[str, str] | None) -> str:
    done = markers()
    out = []
    for num, name in STAGES:
        if f"{num}-{name}" in done:
            out.append(f"{C['g']}✓ {name}{C['x']}")
        elif cur and cur[1] == name:
            out.append(f"{C['c']}{C['b']}▶ {name}{C['x']}")
        else:
            out.append(f"{C['dim']}· {name}{C['x']}")
    return "  ".join(out)


def read_pretrain() -> tuple[list[dict], list[dict], bool]:
    log = RUN / "4-pretrain.log"
    steps, vals, done = [], [], False
    if not log.is_file():
        return steps, vals, done
    for line in log.read_text(errors="replace").splitlines():
        if (m := PRE.match(line)):
            steps.append({"step": _n(m.group(1)), "total": _n(m.group(2)),
                          "loss": float(m.group(3)), "lr": float(m.group(4)),
                          "g": float(m.group(5)), "tps": _n(m.group(6))})
        elif (m := VAL.search(line)):
            vals.append({"loss": float(m.group(1)), "ppl": float(m.group(2)),
                         "best": bool(m.group(3)),
                         "at": steps[-1]["step"] if steps else 0})
        elif line.lstrip().startswith("done."):
            done = True
    return steps, vals, done


def read_sft() -> list[dict]:
    log = RUN / "5-sft.log"
    rows = []
    if not log.is_file():
        return rows
    for line in log.read_text(errors="replace").splitlines():
        if (m := SFT.match(line)):
            rows.append({"epoch": int(m.group(1)), "epochs": int(m.group(2)),
                         "step": _n(m.group(3)), "total": _n(m.group(4)),
                         "loss": float(m.group(5)), "lr": float(m.group(6)),
                         "g": float(m.group(7))})
    return rows


def checkpoints() -> list[str]:
    out = []
    for name in ("small", "small/best", "small-sft"):
        sj = D / "models/checkpoints-v5" / name / "state.json"
        if sj.is_file():
            try:
                d = json.loads(sj.read_text())
                ppl = d.get("val_ppl")
                out.append(f"{name:<12} step {d['step']:>6,}"
                           + (f"   val ppl {ppl}" if ppl else ""))
            except Exception:
                pass
    return out


def render() -> tuple[str, bool]:
    cur = current_stage()
    L: list[str] = []
    A = L.append
    A(f"{C['b']}{C['c']}  WHETSTONE — pipeline v5{C['x']}"
      f"{C['dim']}   small 61.5M · 99.7M tokens · 29 sources{C['x']}")
    A("")
    A("  " + stage_strip(cur))
    A("")

    if cur is None:
        A(f"  {C['g']}{C['b']}✓ every stage complete{C['x']}")
        for c in checkpoints():
            A(f"    {C['dim']}{c}{C['x']}")
        return "\n".join(L), True

    num, name = cur

    if name == "sft":
        rows = read_sft()
        if not rows:
            A(f"  {C['y']}fine-tuning starting…{C['x']}")
            return "\n".join(L), False
        r = rows[-1]
        frac = r["step"] / r["total"]
        # ~2 steps/sec measured; the log carries no rate of its own.
        eta = (r["total"] - r["step"]) / 2.0
        A(f"  {C['c']}{bar(frac)}{C['x']}  {C['b']}{frac:5.1%}{C['x']}")
        A(f"  {C['b']}fine-tuning on 13,206 agent trajectories{C['x']}")
        A(f"  epoch {C['b']}{r['epoch']}/{r['epochs']}{C['x']}"
          f"    step {C['b']}{r['step']:,}{C['x']} / {r['total']:,}"
          f"    {C['dim']}eta{C['x']} {C['b']}~{hms(eta)}{C['x']}")
        A("")
        A(f"  {C['dim']}loss{C['x']} {C['b']}{r['loss']:.3f}{C['x']}"
          f"     {C['dim']}lr{C['x']} {r['lr']:.2e}"
          f"     {C['dim']}|g|{C['x']} {r['g']:.2f}")
        losses = [x["loss"] for x in rows]
        A(f"  {C['m']}{sparkline(losses)}{C['x']}")
        A("")
        A(f"  {C['b']}mean loss per epoch{C['x']}  {C['dim']}(loss is masked to the "
          f"model's own turns){C['x']}")
        for e in range(1, r["epochs"] + 1):
            v = [x["loss"] for x in rows if x["epoch"] == e]
            if v:
                mark = f"  {C['c']}← now{C['x']}" if e == r["epoch"] else ""
                A(f"    epoch {e}   mean {C['b']}{sum(v)/len(v):.3f}{C['x']}"
                  f"   min {min(v):.3f}   {C['dim']}n={len(v)}{C['x']}{mark}")
        A("")
        A(f"  {C['dim']}this is the stage that teaches verb CHOICE — the traced run"
          f"{C['x']}")
        A(f"  {C['dim']}showed the pretrained model picking at a 0.009-nat margin"
          f"{C['x']}")

    elif name == "pretrain":
        steps, vals, _ = read_pretrain()
        if not steps:
            A(f"  {C['y']}waiting for the first step…{C['x']}")
            return "\n".join(L), False
        s = steps[-1]
        frac = s["step"] / s["total"]
        eta = (s["total"] - s["step"]) * 65536 / max(s["tps"], 1)
        A(f"  {C['c']}{bar(frac)}{C['x']}  {C['b']}{frac:5.1%}{C['x']}")
        A(f"  step {C['b']}{s['step']:,}{C['x']} / {s['total']:,}"
          f"    {C['dim']}eta{C['x']} {C['b']}{hms(eta)}{C['x']}")
        A("")
        A(f"  {C['dim']}loss{C['x']} {C['b']}{s['loss']:.3f}{C['x']}"
          f"    {C['dim']}lr{C['x']} {s['lr']:.2e}"
          f"    {C['dim']}|g|{C['x']} {s['g']:.2f}"
          f"    {C['dim']}speed{C['x']} {s['tps']:,} tok/s")
        A(f"  {C['m']}{sparkline([x['loss'] for x in steps])}{C['x']}")
        if vals:
            A("")
            A(f"  {C['b']}validation{C['x']} {C['dim']}(lower is better){C['x']}")
            for v in vals[-5:]:
                star = f" {C['g']}← best{C['x']}" if v["best"] else ""
                A(f"    step {v['at']:>6,}   ppl {C['b']}{v['ppl']:6.2f}{C['x']}{star}")
    else:
        log = RUN / f"{num}-{name}.log"
        A(f"  {C['c']}{C['b']}▶ {name}{C['x']}  {C['dim']}in progress{C['x']}")
        if log.is_file():
            tail = log.read_text(errors="replace").splitlines()[-6:]
            A("")
            for line in tail:
                A(f"    {C['dim']}{line[:92]}{C['x']}")

    ck = checkpoints()
    if ck:
        A("")
        A(f"  {C['b']}checkpoints{C['x']}")
        for c in ck:
            A(f"    {C['dim']}{c}{C['x']}")
    A("")
    A(f"  {C['dim']}Ctrl-C stops this view — it does not stop training{C['x']}")
    return "\n".join(L), False


def main() -> int:
    try:
        while True:
            body, finished = render()
            sys.stdout.write("\033[H\033[J" + body + "\n")
            sys.stdout.flush()
            if finished:
                return 0
            time.sleep(3)
    except KeyboardInterrupt:
        sys.stdout.write("\n  stopped watching. Training continues.\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
