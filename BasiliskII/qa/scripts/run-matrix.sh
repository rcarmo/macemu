#!/usr/bin/env bash
# BasiliskII QA matrix runner scaffold.
# Generates repeatable prefs/manifests and can run short ROM smoke cases.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
B2_DIR="$ROOT/BasiliskII"
BIN="${B2_BIN:-$B2_DIR/src/Unix/BasiliskII}"
ROM="${B2_ROM:-/workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM}"
DISK="${B2_DISK:-/workspace/fixtures/basilisk/images/HD200MB}"
ART_ROOT="${B2_QA_ARTIFACTS:-$B2_DIR/qa/artifacts}"
TIMEOUT_SEC="${B2_QA_TIMEOUT:-60}"
ROM_TICKS="${B2_QA_ROM_TICKS:-300}"
VNC_PORT="${B2_QA_VNC_PORT:-5900}"
CASE=""
DRY_RUN=0
RUN_PREFLIGHT=0

usage() {
  cat <<EOF
Usage: $0 --list
       $0 --case CASE [--dry-run] [--timeout SEC] [--rom-ticks N] [--preflight]

Environment overrides:
  B2_BIN, B2_ROM, B2_DISK, B2_QA_ARTIFACTS, B2_QA_TIMEOUT, B2_QA_ROM_TICKS, B2_QA_VNC_PORT

Cases:
EOF
  list_cases
}

list_cases() {
  cat <<'EOF'
  interpreter-rom-smoke       JIT disabled ROM smoke comparison
  optlev0-rom-smoke           JIT dispatcher with optlev0/interpreter codegen
  optlev2-rom-smoke           ARM64 optlev2 JIT ROM smoke
  optlev2-stable-rom-smoke    optlev2 + stable direct-edge profiling ROM smoke
  optlev2-desktop-vnc         prefs/manifests for VNC desktop boot QA
  optlev2-desktop-soak        prefs/manifests for timed desktop soak
  optlev2-network-slirp       prefs/manifests for safe user-mode slirp network attempt
  optlev2-audio-dummy         prefs/manifests for SDL dummy audio smoke
  optlev2-audio-real          prefs/manifests for manual real-audio smoke
  optlev2-disk-persistence    prefs/manifests for disk persistence QA
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) list_cases; exit 0 ;;
    --case) CASE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --timeout) TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --rom-ticks) ROM_TICKS="${2:-}"; shift 2 ;;
    --preflight) RUN_PREFLIGHT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$CASE" ]]; then
  usage >&2
  exit 2
fi

require_file() {
  local path="$1" label="$2"
  [[ -e "$path" ]] || { echo "Missing $label: $path" >&2; exit 1; }
}

case_defaults() {
  JIT=true
  MODE_ENV=()
  STABLE_ENV=()
  AUDIO_ENV=(SDL_AUDIODRIVER=dummy)
  VIDEO_ENV=(SDL_VIDEODRIVER=dummy)
  DISK_ENABLED=false
  NETWORK=none
  AUDIO_PREF="nosound true"
  VNC=false
  RUN_KIND=rom-smoke
  DESCRIPTION=""
}

case_config() {
  case_defaults
  case "$CASE" in
    interpreter-rom-smoke)
      JIT=false
      DESCRIPTION="JIT disabled ROM smoke comparison"
      ;;
    optlev0-rom-smoke)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_FORCE_OPTLEV0=1 B2_JIT_MAX_OPTLEV=2)
      DESCRIPTION="JIT dispatcher with optlev0/interpreter codegen"
      ;;
    optlev2-rom-smoke)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DESCRIPTION="ARM64 optlev2 JIT ROM smoke"
      ;;
    optlev2-stable-rom-smoke)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      STABLE_ENV=(B2_JIT_ENABLE_STABLE_DIRECT_EDGES=1 B2_JIT_STABLE_DIRECT_ROM_ONLY=1 B2_JIT_STABLE_EDGE_MIN_EXEC=1 B2_JIT_STABLE_EDGE_MIN_PCT=50)
      DESCRIPTION="optlev2 plus stable direct-edge profiling ROM smoke"
      ;;
    optlev2-desktop-vnc)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DISK_ENABLED=true
      VNC=true
      RUN_KIND=desktop
      DESCRIPTION="optlev2 desktop boot over VNC"
      ;;
    optlev2-desktop-soak)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DISK_ENABLED=true
      VNC=true
      RUN_KIND=desktop-soak
      DESCRIPTION="optlev2 desktop soak over VNC"
      ;;
    optlev2-network-slirp)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DISK_ENABLED=true
      NETWORK=slirp
      VNC=true
      RUN_KIND=desktop-network
      DESCRIPTION="optlev2 desktop with user-mode slirp networking"
      ;;
    optlev2-audio-dummy)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DISK_ENABLED=true
      AUDIO_PREF="nosound false"
      AUDIO_ENV=(SDL_AUDIODRIVER=dummy)
      VNC=true
      RUN_KIND=desktop-audio
      DESCRIPTION="optlev2 desktop with SDL dummy audio"
      ;;
    optlev2-audio-real)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DISK_ENABLED=true
      AUDIO_PREF="nosound false"
      AUDIO_ENV=()
      VNC=true
      RUN_KIND=manual-audio
      DESCRIPTION="optlev2 desktop with real SDL audio path"
      ;;
    optlev2-disk-persistence)
      MODE_ENV=(B2_JIT_FORCE_TRANSLATE=1 B2_JIT_MAX_OPTLEV=2)
      DISK_ENABLED=true
      VNC=true
      RUN_KIND=desktop-disk
      DESCRIPTION="optlev2 disk read/write persistence test"
      ;;
    *) echo "Unknown QA case: $CASE" >&2; usage >&2; exit 2 ;;
  esac
}

write_prefs() {
  local prefs="$1"
  cat >"$prefs" <<EOF
rom $ROM
ramsize 8388608
modelid 14
cpu 4
fpu false
jit $JIT
jitfpu false
jitcachesize ${B2_JIT_CACHE_SIZE:-32768}
screen win/640/480
$AUDIO_PREF
nocdrom true
ignoresegv true
EOF
  if [[ "$DISK_ENABLED" == true ]]; then
    echo "disk $DISK" >>"$prefs"
  fi
  if [[ "$NETWORK" == slirp ]]; then
    echo "ether slirp" >>"$prefs"
  fi
  if [[ "$VNC" == true ]]; then
    cat >>"$prefs" <<EOF
vncserver true
vncport $VNC_PORT
EOF
  fi
}

run_preflight() {
  echo "== Preflight: build =="
  make -C "$B2_DIR/src/Unix" -j"$(nproc)"
  echo "== Preflight: JIT vector harness =="
  (cd "$ROOT" && ./jit-test/run.sh)
}

case_config
require_file "$ROM" "ROM"
require_file "$BIN" "BasiliskII binary"
if [[ "$DISK_ENABLED" == true ]]; then
  require_file "$DISK" "disk image"
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$CASE"
RUN_DIR="$ART_ROOT/reports/$RUN_ID"
mkdir -p "$RUN_DIR" "$ART_ROOT/logs" "$ART_ROOT/prefs"
PREFS="$RUN_DIR/prefs"
write_prefs "$PREFS"
cp "$PREFS" "$ART_ROOT/prefs/$RUN_ID.prefs"

GIT_COMMIT="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
{
  echo "case_id=$CASE"
  echo "description=$DESCRIPTION"
  echo "run_kind=$RUN_KIND"
  echo "git_commit=$GIT_COMMIT"
  echo "binary=$BIN"
  echo "rom=$ROM"
  echo "disk=$([[ "$DISK_ENABLED" == true ]] && echo "$DISK" || echo none)"
  echo "prefs=$PREFS"
  echo "timeout_sec=$TIMEOUT_SEC"
  echo "rom_ticks=$ROM_TICKS"
  printf 'mode_env='; printf '%s ' "${MODE_ENV[@]}"; printf '\n'
  printf 'stable_env='; printf '%s ' "${STABLE_ENV[@]}"; printf '\n'
  printf 'video_env='; printf '%s ' "${VIDEO_ENV[@]}"; printf '\n'
  printf 'audio_env='; printf '%s ' "${AUDIO_ENV[@]}"; printf '\n'
} >"$RUN_DIR/manifest.env"

cat >"$RUN_DIR/report.md" <<EOF
# BasiliskII QA run: $CASE

- Result: PENDING
- Commit: $GIT_COMMIT
- Description: $DESCRIPTION
- Run kind: $RUN_KIND
- Prefs: $PREFS
- Logs: $RUN_DIR/out, $RUN_DIR/err

## Notes

Fill this report using qa/reports/run-report-template.md after the run.
EOF

if [[ "$RUN_PREFLIGHT" == 1 ]]; then
  run_preflight | tee "$RUN_DIR/preflight.log"
fi

if [[ "$DRY_RUN" == 1 ]]; then
  echo "Prepared QA case $CASE in $RUN_DIR"
  echo "Prefs: $PREFS"
  exit 0
fi

if [[ "$RUN_KIND" != rom-smoke ]]; then
  echo "Prepared desktop/manual QA case $CASE in $RUN_DIR"
  echo "This scaffold does not yet drive the desktop; use qa/scripts/vnc-gherkin-runner.js for future scripted UI steps."
  echo "To launch manually:"
  printf '  env HOME=%q ' "$RUN_DIR/home"
  printf '%q ' "${MODE_ENV[@]}" "${STABLE_ENV[@]}" "${VIDEO_ENV[@]}" "${AUDIO_ENV[@]}"
  printf 'timeout -k 2 %q %q --config %q\n' "$TIMEOUT_SEC" "$BIN" "$PREFS"
  exit 0
fi

mkdir -p "$RUN_DIR/home"
set +e
env HOME="$RUN_DIR/home" \
    B2_ROM_HARNESS="$ROM_TICKS" \
    "${MODE_ENV[@]}" \
    "${STABLE_ENV[@]}" \
    "${VIDEO_ENV[@]}" \
    "${AUDIO_ENV[@]}" \
    timeout -k 2 "$TIMEOUT_SEC" "$BIN" --config "$PREFS" >"$RUN_DIR/out" 2>"$RUN_DIR/err"
RC=$?
set -e

LAST_DC="$(grep -a '^DC\[' "$RUN_DIR/err" | tail -n1 || true)"
BAD_PCP="$(grep -a -c 'bad pc_p' "$RUN_DIR/err" || true)"
BUSERR="$(grep -a -c 'bus error for unmapped PC' "$RUN_DIR/err" || true)"
HARNESS_OK="$(grep -a -c 'ROM_HARNESS: result=MAX_TICKS' "$RUN_DIR/err" || true)"
{
  echo "rc=$RC"
  echo "bad_pcp=$BAD_PCP"
  echo "buserr=$BUSERR"
  echo "harness_max_ticks=$HARNESS_OK"
  echo "last_dc=$LAST_DC"
} | tee "$RUN_DIR/result.env"

if [[ "$RC" -eq 0 && "$BAD_PCP" -eq 0 && "$BUSERR" -eq 0 && "$HARNESS_OK" -gt 0 ]]; then
  sed -i 's/Result: PENDING/Result: PASS/' "$RUN_DIR/report.md"
else
  sed -i 's/Result: PENDING/Result: FAIL/' "$RUN_DIR/report.md"
fi

exit "$RC"
