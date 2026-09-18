#!/usr/bin/env bash
# The overnight run: corpus -> tokenizer -> shards -> pretrain -> SFT -> verify.
#
# Built to survive a night alone. Every stage writes a marker when it completes,
# so re-running resumes at the first unfinished stage instead of redoing hours
# of work. Training is wrapped in a retry loop that resumes from the last
# checkpoint, because the failure this project has actually seen is the external
# SSD dropping mid-run, and a run that cannot resume loses the whole night.
#
#   ./scripts/overnight.sh            # run the pipeline
#   ./scripts/overnight.sh --from N   # force-restart from stage N
#   STAGES: 1 corpus  2 tokenizer  3 shards  4 pretrain  5 sft  6 verify
#
# Nothing here is interactive. Everything lands in $RUN/ as a log per stage, so
# the morning question "what happened at 3am" has a real answer.

set -uo pipefail          # NOT -e: a failed stage must be caught and reported,
                          # not kill the supervisor that is meant to retry it.

D=/Volumes/at0m_b0mb/whetstone
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER=v5
RUN="$D/runs/overnight-$VER"
MARK="$RUN/markers"
MODEL=${MODEL:-small}
MAX_RETRIES=${MAX_RETRIES:-20}
HOURS=${HOURS:-9}          # wall-clock budget for pretraining

mkdir -p "$RUN" "$MARK"
cd "$REPO" || exit 1
export PYTHONPATH="$REPO"

FROM=0
[[ "${1:-}" == "--from" ]] && FROM="${2:-0}"

log()  { printf '%s  %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$RUN/supervisor.log"; }
done_marker() { [[ -f "$MARK/$1" && $FROM -eq 0 ]]; }
mark() { touch "$MARK/$1"; }

# Keep the machine awake for the whole pipeline. Without this the run dies at
# whatever hour the display sleeps, which is the most embarrassing possible way
# to lose a night of training.
if ! pgrep -qf "caffeinate -dimsu -w $$"; then
    caffeinate -dimsu -w $$ &
    log "caffeinate armed (pid $!) — display and disk sleep inhibited"
fi

stage() {                 # stage <n> <name> <command...>
    local n=$1 name=$2; shift 2
    if done_marker "$n-$name"; then log "stage $n ($name) already done — skipping"; return 0; fi
    [[ $FROM -gt 0 && $n -lt $FROM ]] && { log "stage $n ($name) skipped (--from $FROM)"; return 0; }
    log "── stage $n: $name ──"
    local t0=$SECONDS
    if "$@" >>"$RUN/$n-$name.log" 2>&1; then
        mark "$n-$name"
        log "   stage $n ($name) OK in $(( (SECONDS-t0)/60 ))m"
        return 0
    fi
    log "   stage $n ($name) FAILED — see $RUN/$n-$name.log"
    tail -20 "$RUN/$n-$name.log" | tee -a "$RUN/supervisor.log"
    return 1
}

# ── 1. corpus ────────────────────────────────────────────────────────────────
build_corpus() {
    # NOT --balance: its own help records that scaling every register down to
    # the scarcest cost 78% of the corpus. --max-register-multiple trims only
    # what is over-represented. And NOT --report in the same call: --report
    # describes an existing build and returns without fetching anything.
    # --max-source-share matters more than usual now that rfc fetches properly:
    # it is 9,825 documents and was 64% of the corpus on its own before the cap.
    python3 -m training.corpus.build --out "$D/corpus/clean-$VER" \
        --cache "$D/cache" --max-register-multiple 1.6 --max-source-share 0.15 \
        && python3 -m training.corpus.build --out "$D/corpus/clean-$VER" --report
}

# ── 2. tokenizer ─────────────────────────────────────────────────────────────
# Retrained on the new corpus. The existing tokenizer was measured at +29% over
# gpt2 on the OLD mix; the new mix adds real code and raw HTTP, which are
# surface forms it never saw. Training from scratch here is cheap and the model
# is being trained from scratch anyway, so there is no checkpoint to invalidate.
build_tokenizer() {
    # --clean (not --corpus) is the mode that trains on the training side of a
    # held-out split and then measures per-register compression against gpt2 --
    # the measurement that settled the domain-tokenizer question at +29%. Do NOT
    # pass --compare: with a tokenizer already on disk it measures and exits
    # without training, which would silently leave stage 3 using the old vocab.
    python3 -m training.tokenizer.train_tokenizer \
        --clean "$D/corpus/clean-$VER" --out "$D/models/tokenizer-$VER" \
        --vocab-size 16384
}

# ── 3. shards ────────────────────────────────────────────────────────────────
build_shards() {
    python3 - <<PY
from pathlib import Path
from training.data import tokenize_corpus
idx = tokenize_corpus([Path("$D/corpus/clean-$VER")],
                      Path("$D/models/tokenizer-$VER/tokenizer.json"),
                      Path("$D/corpus/tokenized-$VER"))
print(f"{idx.total_tokens:,} tokens across {len(idx.shards)} shard(s), "
      f"{idx.documents:,} documents")
for k, v in sorted(idx.by_source.items(), key=lambda x: -x[1]):
    print(f"  {k:<18}{v:>12,}  {v/idx.total_tokens:5.1%}")
PY
}

# ── 4. pretrain, with retries ────────────────────────────────────────────────
# The retry loop is the point. --resume restores weights, optimizer AND the data
# position, so a restart continues the stream rather than replaying it.
# How many steps to run is not a constant: it depends on how big the corpus
# turned out, how fast this machine actually is, and how much night is left.
# Three ceilings, and the lowest wins:
#   * the wall-clock budget, so the run finishes before morning;
#   * Chinchilla (20 tokens per parameter), past which more steps buy little;
#   * an epoch cap, because repeating a small corpus many times is how `tiny`
#     ended up with a val curve that turned around and rose.
plan_steps() {
    python3 - "$D/corpus/tokenized-$VER" "$MODEL" "$HOURS" <<'PY'
import json, sys
from pathlib import Path
from training.config import STAIRCASE, TrainConfig

data, model, hours = Path(sys.argv[1]), sys.argv[2], float(sys.argv[3])
cfg, t = STAIRCASE[model], TrainConfig()
total = json.loads((data / "index.json").read_text())["total_tokens"]

TPS = 9300                      # measured on this machine for `small` at bf16
budget = int(hours * 3600 * TPS) // t.batch_tokens
chinchilla = t.total_steps(cfg)
epoch = max(1, total // t.batch_tokens)
epoch_cap = epoch * 4

steps = max(1, min(budget, chinchilla, epoch_cap))
why = min((budget, "wall-clock budget"), (chinchilla, "Chinchilla 20 tok/param"),
          (epoch_cap, "4-epoch cap"), key=lambda x: x[0])[1]
print(f"corpus {total:,} tokens = {total/65536:,.0f} steps/epoch", file=sys.stderr)
print(f"budget {budget:,} | chinchilla {chinchilla:,} | 4 epochs {epoch_cap:,}",
      file=sys.stderr)
print(f"-> {steps:,} steps ({steps/epoch:.1f} epochs), bound by {why}",
      file=sys.stderr)
print(steps)
PY
}

pretrain() {
    local try=1 resume=""
    local steps; steps=$(plan_steps)
    [[ -z "$steps" ]] && { log "   could not plan steps"; return 1; }
    log "   planned $steps steps for a ${HOURS}h budget"
    while (( try <= MAX_RETRIES )); do
        log "   pretrain attempt $try/$MAX_RETRIES $resume"
        if python3 -m training.pretrain --model "$MODEL" \
                --data "$D/corpus/tokenized-$VER" \
                --out "$D/models/checkpoints-$VER" \
                --max-steps "$steps" $resume; then
            return 0
        fi
        # Anything after the first attempt resumes; the checkpoint is written
        # every `checkpoint_every` steps, so at most that much work is lost.
        resume="--resume"; try=$((try+1))
        log "   pretrain died — retrying in 60s"
        sleep 60
    done
    return 1
}

# ── 5. SFT ───────────────────────────────────────────────────────────────────
# Trajectories are regenerated against the real agent loop first, so the model
# is fine-tuned on what the current code actually does, not a stale capture.
run_sft() {
    python3 -m training.trajectories --out "$D/corpus/trajectories-$VER.jsonl" || return 1
    local base="$D/models/checkpoints-$VER/$MODEL"
    [[ -d "$base/best" ]] && base="$base/best"   # prefer best over last
    log "   SFT base: $base"
    python3 -m training.sft --checkpoint "$base" \
        --tokenizer "$D/models/tokenizer-$VER/tokenizer.json" \
        --trajectories "$D/corpus/trajectories-$VER.jsonl" \
        --out "$D/models/checkpoints-$VER/$MODEL-sft" \
        --replay "$D/corpus/tokenized-$VER"
}

# ── 6. verify ────────────────────────────────────────────────────────────────
verify() {
    local tok="$D/models/tokenizer-$VER/tokenizer.json"
    local ck="$D/models/checkpoints-$VER/$MODEL-sft"
    echo "=== whetbench: $MODEL-sft ==="
    python3 -m bench.whetbench --checkpoint "$ck" --tokenizer "$tok" \
        --json "$RUN/bench-$MODEL-sft.json"
    echo; echo "=== test suite ==="
    python3 -m pytest tests/ -q
    echo; echo "=== lab: the model driving the real loop ==="
    python3 -m lab.run --both --model "$ck" --tokenizer "$tok"
}

log "════ overnight $VER starting — model=$MODEL ════"
stage 1 corpus    build_corpus    || exit 1
stage 2 tokenizer build_tokenizer || exit 1
stage 3 shards    build_shards    || exit 1
stage 4 pretrain  pretrain        || exit 1
stage 5 sft       run_sft         || log "   SFT failed — verifying the base model instead"
stage 6 verify    verify          || log "   verify reported failures — see the log"
log "════ overnight $VER complete ════"
log "artifacts: $D/models/checkpoints-$VER   logs: $RUN"
