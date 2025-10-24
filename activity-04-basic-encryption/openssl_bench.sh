#!/usr/bin/env bash
#
# openssl_bench.sh — OpenSSL performance runner (final: no dsa3072)
# Benchmarks: SHA-1, RC4, Blowfish (ECB/CBC), DSA-2048.
#
set -euo pipefail

SECONDS_PER_TRIAL=3
TRIALS=3
DO_MULTI=0

while getopts ":s:t:m" opt; do
  case $opt in
    s) SECONDS_PER_TRIAL="$OPTARG" ;;
    t) TRIALS="$OPTARG" ;;
    m) DO_MULTI=1 ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

timestamp="$(date +%Y%m%d-%H%M%S)"
outdir="openssl_bench_logs/$timestamp"
mkdir -p "$outdir"

log() { printf "[%s] %s\n" "$(date '+%H:%M:%S')" "$*" ; }
logf() { printf "[%s] " "$(date '+%H:%M:%S')" ; printf "$@" ; printf "\n" ; }

# 0) Environment capture
{
  echo "# System & OpenSSL environment"
  echo "DATE: $(date -Iseconds)"
  echo "UNAME: $(uname -a)"
  if command -v lscpu >/dev/null 2>&1; then
    echo
    echo "## lscpu"
    lscpu
  elif [[ "$(uname)" == "Darwin" ]]; then
    echo
    echo "## macOS CPU"
    sysctl -n machdep.cpu.brand_string || true
    sysctl -a | grep -iE 'brand|microcode|cpus|cache' || true
  fi
  echo
  echo "## OpenSSL version"
  openssl version -a || true
} > "$outdir/env.txt"

# Detect OpenSSL 3.x
PROVIDER_FLAGS=""
IS_O3=0
if openssl version 2>/dev/null | grep -qE '\b3\.'; then
  IS_O3=1
  PROVIDER_FLAGS="-provider legacy -provider default"
fi

# Verify legacy ciphers are fetchable (if not, we will skip)
SKIP_LEGACY=0
if [[ $IS_O3 -eq 1 ]]; then
  if ! openssl list -cipher-algorithms $PROVIDER_FLAGS 2>/dev/null | grep -qiE '(^|[^A-Z])rc4|(^|[^A-Z])bf-|blowfish'; then
    SKIP_LEGACY=1
  fi
fi

CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"

run_speed() {
  local label="$1"; shift
  local logfile="$outdir/${label}.log"
  log "Running: $label  (${SECONDS_PER_TRIAL}s x ${TRIALS})"
  : > "$logfile"
  for i in $(seq 1 "$TRIALS"); do
    logf "  Trial %d/%d" "$i" "$TRIALS"
    openssl speed -elapsed -seconds "$SECONDS_PER_TRIAL" $@ 2>&1 | tee -a "$logfile" || true
    echo -e "\n---" >> "$logfile"
  done
}

# 1) Single-core baseline
run_speed "sha1"         -evp sha1

if [[ "$SKIP_LEGACY" -eq 1 ]]; then
  log "Legacy provider present but ciphers not fetchable. Skipping RC4 and Blowfish."
  printf "LEGACY UNAVAILABLE: RC4/Blowfish cannot be fetched on this OpenSSL build.\n" > "$outdir/rc4.log"
  printf "LEGACY UNAVAILABLE: RC4/Blowfish cannot be fetched on this OpenSSL build.\n" > "$outdir/bf-ecb.log"
  printf "LEGACY UNAVAILABLE: RC4/Blowfish cannot be fetched on this OpenSSL build.\n" > "$outdir/bf-cbc.log"
else
  run_speed "rc4"          $PROVIDER_FLAGS -evp rc4
  run_speed "bf-ecb"       $PROVIDER_FLAGS -evp bf-ecb
  run_speed "bf-cbc"       $PROVIDER_FLAGS -evp bf-cbc
fi

run_speed "dsa2048"      dsa2048

# 2) Optional multi-core scaling
if [[ "$DO_MULTI" -eq 1 && "$CORES" -gt 1 ]]; then
  run_speed "sha1_multi"    -multi "$CORES" -evp sha1
  if [[ "$SKIP_LEGACY" -eq 0 ]]; then
    run_speed "rc4_multi"     -multi "$CORES" $PROVIDER_FLAGS -evp rc4
    run_speed "bf-cbc_multi"  -multi "$CORES" $PROVIDER_FLAGS -evp bf-cbc
  fi
  run_speed "dsa2048_multi" -multi "$CORES" dsa2048
fi

# 3) Summary extraction
summary_csv="$outdir/summary.csv"
printf "algorithm,metric,size_or_key,trial,estimate\n" > "$summary_csv"

parse_mb_s() {
  awk -v pat="$2" '
    BEGIN { found=0 }
    tolower($0) ~ tolower(pat) && $0 ~ / 8192 bytes / {
      for (i=NF; i>=1; i--) if ($i ~ /^[0-9.]+k$/) { gsub("k","",$i); printf("%.3f\n", $i/1024.0); found=1; exit }
    }
  ' "$1"
}

parse_dsa_ops() {
  awk -v bits="$2" -v op="$3" '
    BEGIN{val=""}
    tolower($0) ~ tolower(op) && $0 ~ bits && tolower($0) ~ /dsa/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^[0-9.]+$/) cand=$i;
        if (tolower($(i)) ~ /ops\/s/) { if (cand!="") { print cand; exit } }
      }
      lastnum=""; for (i=1;i<=NF;i++) if ($i ~ /^[0-9.]+$/) lastnum=$i
      if (lastnum!="") { print lastnum; exit }
    }
  ' "$1"
}

summarize_log_trials() {
  local algo="$1"; local metric="$2"; local size="$3"; local logfile="$4"
  if [[ ! -s "$logfile" ]]; then
    for t in $(seq 1 "$TRIALS"); do
      printf "%s,%s,%s,%d,%s\n" "$algo" "$metric" "$size" "$t" "N/A" >> "$summary_csv"
    done
    return
  fi
  csplit -q -f "$logfile.part." -b "%02d" "$logfile" '/^---$/' '{*}' || true
  parts=( $(ls "$logfile".part.* 2>/dev/null || true) )
  if [[ ${#parts[@]} -eq 0 ]]; then parts=("$logfile"); fi

  local t=1
  for p in "${parts[@]}"; do
    local est=""
    if [[ "$metric" == "MB/s" ]]; then
      est="$(parse_mb_s "$p" "$algo" || true)"
    else
      local bits="${size%%-*}"
      local op="${size##*-}"
      est="$(parse_dsa_ops "$p" "$bits" "$op" || true)"
    fi
    [[ -z "$est" ]] && est="N/A"
    printf "%s,%s,%s,%d,%s\n" "$algo" "$metric" "$size" "$t" "$est" >> "$summary_csv"
    t=$((t+1))
  done
}

summarize_log_trials "sha1"    "MB/s" "8192B"   "$outdir/sha1.log"
summarize_log_trials "rc4"     "MB/s" "8192B"   "$outdir/rc4.log"
summarize_log_trials "bf-ecb"  "MB/s" "8192B"   "$outdir/bf-ecb.log"
summarize_log_trials "bf-cbc"  "MB/s" "8192B"   "$outdir/bf-cbc.log"
summarize_log_trials "dsa"     "ops/s" "2048-sign"   "$outdir/dsa2048.log"
summarize_log_trials "dsa"     "ops/s" "2048-verify" "$outdir/dsa2048.log"

printf "\n=== Summary (medians across %d trial(s)) ===\n" "$TRIALS"
python3 - "$summary_csv" << 'PYCODE'
import csv, statistics, sys
path=sys.argv[1]
rows={}
with open(path,newline='') as f:
    for r in csv.DictReader(f):
        key=(r['algorithm'], r['metric'], r['size_or_key'])
        rows.setdefault(key, []).append(r['estimate'])
def num(x):
    try: return float(x)
    except: return None
print("{:<10} {:<8} {:<12} {:>12}".format("Algorithm","Metric","Size/Key","Median"))
for (algo,metric,size),vals in sorted(rows.items()):
    nums=[num(v) for v in vals if v!='N/A']
    nums=[v for v in nums if v is not None]
    med = "N/A" if not nums else f"{statistics.median(nums):.3f}"
    print("{:<10} {:<8} {:<12} {:>12}".format(algo,metric,size,med))
PYCODE

echo
echo "Raw logs and CSV saved under: $outdir"
echo "File list:"
ls -1 "$outdir"
