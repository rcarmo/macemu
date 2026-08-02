#!/usr/bin/env bash
# Bounded register-only PPC interpreter/JIT benchmark and coverage census.
# Timing and coverage are separate binaries/runs. This script owns one CPU policy
# for the complete series and restores it on every exit path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIX_DIR="$ROOT/src/Unix"
TIMING_BIN="${SS_TIMING_BIN:-$UNIX_DIR/SheepShaver-bench-timing}"
CENSUS_BIN="${SS_CENSUS_BIN:-$UNIX_DIR/SheepShaver-bench-census}"
ITERATIONS="${ITERATIONS:-1000000}"
CENSUS_ITERATIONS="${CENSUS_ITERATIONS:-100000}"
TRIALS="${TRIALS:-9}"
TIMEOUT_SEC="${TIMEOUT_SEC:-120}"
BENCH_CPU="${BENCH_CPU:-11}"
OUTDIR="${OUTDIR:-/workspace/tmp/sheepshaver-jit-benchmark-$(date +%Y%m%d-%H%M%S)}"
LOCK_FILE="${BENCH_LOCK_FILE:-/run/lock/sheepshaver-jit-benchmark.lock}"
WORKLOAD=ss-ppc-register-loop-v1

for v in ITERATIONS CENSUS_ITERATIONS TRIALS TIMEOUT_SEC; do
    [[ "${!v}" =~ ^[1-9][0-9]*$ ]] || { echo "$v must be positive" >&2; exit 2; }
done
[[ "$BENCH_CPU" =~ ^[0-9]+$ ]] || { echo 'BENCH_CPU must be a CPU number' >&2; exit 2; }
command -v flock >/dev/null || { echo 'flock is required' >&2; exit 2; }
command -v taskset >/dev/null || { echo 'taskset is required' >&2; exit 2; }
[[ -x "$TIMING_BIN" ]] || { echo "missing timing binary: $TIMING_BIN" >&2; exit 2; }
[[ -x "$CENSUS_BIN" ]] || { echo "missing census binary: $CENSUS_BIN" >&2; exit 2; }
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || {
    echo 'refusing benchmark from dirty source tree' >&2; exit 2;
}
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "benchmark lock is already held: $LOCK_FILE" >&2; exit 2; }
if pgrep -x SheepShaver >/dev/null || pgrep -x Previous >/dev/null; then
    echo 'another emulator process is active; refusing shared-host timing' >&2
    pgrep -a -x SheepShaver >&2 || true
    pgrep -a -x Previous >&2 || true
    exit 2
fi

CPU_POLICY=$(readlink -f "/sys/devices/system/cpu/cpu$BENCH_CPU/cpufreq" 2>/dev/null || true)
[[ -d "$CPU_POLICY" ]] || { echo "CPU $BENCH_CPU has no cpufreq policy" >&2; exit 2; }
sudo -n true 2>/dev/null || { echo 'passwordless sudo is required' >&2; exit 2; }
OLD_GOVERNOR=$(<"$CPU_POLICY/scaling_governor")
OLD_MIN_FREQ=$(<"$CPU_POLICY/scaling_min_freq")
OLD_MAX_FREQ=$(<"$CPU_POLICY/scaling_max_freq")
FIXED_FREQ=$(<"$CPU_POLICY/cpuinfo_max_freq")
POLICY_OWNED=0
restore_host() {
    local rc=$? restore_failed=0
    trap - EXIT INT TERM
    if ((POLICY_OWNED)); then
        printf '%s' "$OLD_MIN_FREQ" | sudo -n tee "$CPU_POLICY/scaling_min_freq" >/dev/null || restore_failed=1
        printf '%s' "$OLD_MAX_FREQ" | sudo -n tee "$CPU_POLICY/scaling_max_freq" >/dev/null || restore_failed=1
        printf '%s' "$OLD_GOVERNOR" | sudo -n tee "$CPU_POLICY/scaling_governor" >/dev/null || restore_failed=1
        [[ "$(<"$CPU_POLICY/scaling_governor")" == "$OLD_GOVERNOR" &&
           "$(<"$CPU_POLICY/scaling_min_freq")" == "$OLD_MIN_FREQ" &&
           "$(<"$CPU_POLICY/scaling_max_freq")" == "$OLD_MAX_FREQ" ]] || restore_failed=1
    fi
    if ((restore_failed)); then
        echo "ERROR: failed to restore $CPU_POLICY" >&2
        ((rc == 0)) && rc=4
    fi
    exit "$rc"
}
trap restore_host EXIT INT TERM
POLICY_OWNED=1
printf '%s' performance | sudo -n tee "$CPU_POLICY/scaling_governor" >/dev/null
printf '%s' "$FIXED_FREQ" | sudo -n tee "$CPU_POLICY/scaling_max_freq" >/dev/null
printf '%s' "$FIXED_FREQ" | sudo -n tee "$CPU_POLICY/scaling_min_freq" >/dev/null
[[ "$(<"$CPU_POLICY/scaling_governor")" == performance &&
   "$(<"$CPU_POLICY/scaling_min_freq")" == "$FIXED_FREQ" &&
   "$(<"$CPU_POLICY/scaling_max_freq")" == "$FIXED_FREQ" ]] || {
    echo 'failed to establish fixed-frequency ownership' >&2; exit 2;
}

mkdir -p "$OUTDIR"
SHA=$(git -C "$ROOT" rev-parse HEAD)
TIMING_SHA=$(sha256sum "$TIMING_BIN" | awk '{print $1}')
CENSUS_SHA=$(sha256sum "$CENSUS_BIN" | awk '{print $1}')
WORKLOAD_SHA=$(printf '%s\n' '38630001 7c841a14 7ca52278 54a6383e 7ce73214 4200ffec 00000000' | sha256sum | awk '{print $1}')
{
    printf 'timestamp_utc=%s\nhost=%s\nsha=%s\n' "$(date -u +%FT%TZ)" "$(hostname)" "$SHA"
    printf 'timing_binary=%s\ntiming_binary_sha256=%s\n' "$TIMING_BIN" "$TIMING_SHA"
    printf 'census_binary=%s\ncensus_binary_sha256=%s\n' "$CENSUS_BIN" "$CENSUS_SHA"
    printf 'workload=%s\nworkload_sha256=%s\niterations=%s\ncensus_iterations=%s\ntrials=%s\n' \
        "$WORKLOAD" "$WORKLOAD_SHA" "$ITERATIONS" "$CENSUS_ITERATIONS" "$TRIALS"
    printf 'timing_scope=in_process_post_warmup_cpu_execute_only\n'
    printf 'bench_cpu=%s\ncpu_policy=%s\npolicy_cpus=%s\nfixed_frequency_khz=%s\n' \
        "$BENCH_CPU" "$CPU_POLICY" "$(<"$CPU_POLICY/related_cpus")" "$FIXED_FREQ"
    printf 'original_cpu_governor=%s\noriginal_min_frequency_khz=%s\noriginal_max_frequency_khz=%s\n' \
        "$OLD_GOVERNOR" "$OLD_MIN_FREQ" "$OLD_MAX_FREQ"
} >"$OUTDIR/manifest.env"
printf 'trial\tengine\telapsed_ns\tarchitectural\tstate_hash\tlog\n' >"$OUTDIR/timing.tsv"

run_timing() {
    local engine=$1 trial=$2 log="$OUTDIR/timing-${engine}-${trial}.log" active=0
    [[ "$engine" == jit ]] && active=1
    timeout "$TIMEOUT_SEC" taskset -c "$BENCH_CPU" env -u SS_JIT_RATIO -u SS_JIT_HIST \
        -u SS_JIT_NATIVE_HIST -u SS_JIT_SKIP_HIST -u SS_JIT_SKIP_LOG -u SS_JIT_FAILPROBE \
        SS_TEST_HEX="$WORKLOAD" SS_BENCH_MODE=timing SS_BENCH_ITERATIONS="$ITERATIONS" \
        SS_USE_JIT="$active" SS_TEST_DUMP=0 "$TIMING_BIN" >"$log" 2>&1
    local line elapsed architectural hash
    line=$(grep '^SSBENCH mode=timing ' "$log")
    [[ $(grep -c '^SSBENCH mode=timing ' "$log") == 1 && "$line" == *"engine=$engine "* && "$line" == *' valid=1 '* ]] || {
        echo "invalid timing result: $log" >&2; return 1;
    }
    elapsed=$(sed -n 's/.* elapsed_ns=\([0-9][0-9]*\).*/\1/p' <<<"$line")
    architectural=$(sed -n 's/.* architectural=\([0-9][0-9]*\).*/\1/p' <<<"$line")
    hash=$(sed -n 's/.* state_hash=\([0-9a-f][0-9a-f]*\).*/\1/p' <<<"$line")
    [[ -n "$elapsed" && -n "$architectural" && -n "$hash" ]] || return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$trial" "$engine" "$elapsed" "$architectural" "$hash" "$log" >>"$OUTDIR/timing.tsv"
}

for ((trial=1; trial<=TRIALS; trial++)); do
    # Pair order alternates AB / BA; grouped pairs therefore form ABBA.
    if ((trial % 2)); then run_timing interp "$trial"; run_timing jit "$trial"
    else run_timing jit "$trial"; run_timing interp "$trial"; fi
done

run_census() {
    local engine=$1 log="$OUTDIR/census-${engine}.log" active=0
    [[ "$engine" == jit ]] && active=1
    timeout "$TIMEOUT_SEC" taskset -c "$BENCH_CPU" env \
        SS_TEST_HEX="$WORKLOAD" SS_BENCH_MODE=census SS_BENCH_ITERATIONS="$CENSUS_ITERATIONS" \
        SS_USE_JIT="$active" SS_TEST_DUMP=0 "$CENSUS_BIN" >"$log" 2>&1
    grep -Eq "^SSBENCH mode=census engine=$engine .* valid=1$" "$log" || return 1
    grep -Eq "^SSBENCHCOVERAGE engine=$engine .* reconciled=1 .* terminal=1 " "$log" || return 1
    grep -Eq '^SSBENCHCOMPILE .* stable=1$' "$log" || return 1
}
run_census interp
run_census jit

# Exact parity across every timing sample and both census arms.
[[ $(awk -F '\t' 'NR>1 {print $4" "$5}' "$OUTDIR/timing.tsv" | sort -u | wc -l) == 1 ]] || {
    echo 'timing architectural denominator/state hash mismatch' >&2; exit 3;
}
[[ $(grep '^SSBENCH mode=census ' "$OUTDIR"/census-*.log | sed -E 's/.*architectural=([0-9]+).*state_hash=([0-9a-f]+).*/\1 \2/' | sort -u | wc -l) == 1 ]] || {
    echo 'census architectural denominator/state hash mismatch' >&2; exit 3;
}

emit_stats() {
    local engine=$1
    mapfile -t vals < <(awk -F '\t' -v e="$engine" 'NR>1 && $2==e {print $3}' "$OUTDIR/timing.tsv" | sort -n)
    local n=${#vals[@]} median min=${vals[0]} max=${vals[n-1]}
    if ((n % 2)); then median=${vals[n/2]}; else median=$(( (vals[n/2-1] + vals[n/2]) / 2 )); fi
    printf '%s_n=%s\n%s_median_ns=%s\n%s_min_ns=%s\n%s_max_ns=%s\n' "$engine" "$n" "$engine" "$median" "$engine" "$min" "$engine" "$max"
}
{ emit_stats interp; emit_stats jit; } >"$OUTDIR/summary.env"
interp_median=$(awk -F= '$1=="interp_median_ns"{print $2}' "$OUTDIR/summary.env")
jit_median=$(awk -F= '$1=="jit_median_ns"{print $2}' "$OUTDIR/summary.env")
awk -v i="$interp_median" -v j="$jit_median" 'BEGIN {printf "speedup_interp_over_jit=%.6f\n",i/j}' >>"$OUTDIR/summary.env"

printf 'SheepShaver bounded benchmark complete: %s\n' "$OUTDIR"
cat "$OUTDIR/summary.env"
