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
    python3 -m training.corpus.build --out "$D/corpus/clean-$VER" \
        --cache "$D/cache" --balance --max-source-share 0.18 --report
}

# ── 2. tokenizer ─────────────────────────────────────────────────────────────
# Retrained on the new corpus. The existing tokenizer was measured at +29% over
# gpt2 on the OLD mix; the new mix adds real code and raw HTTP, which are
# surface forms it never saw. Training from scratch here is cheap and the model
# is being trained from scratch anyway, so there is no checkpoint to invalidate.
build_tokenizer() {
    python3 -m training.tokenizer.train_tokenizer \
        --corpus "$D/corpus/clean-$VER" --out "$D/models/tokenizer-$VER" \
        --vocab-size 16384 --compare
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
pretrain() {
    local try=1 resume=""
    while (( try <= MAX_RETRIES )); do
        log "   pretrain attempt $try/$MAX_RETRIES $resume"
        if python3 -m training.pretrain --model "$MODEL" \
                --data "$D/corpus/tokenized-$VER" \
                --out "$D/models/checkpoints-$VER" $resume; then
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
