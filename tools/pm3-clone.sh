#!/usr/bin/env bash

set -e
set -o pipefail

PM3_BIN="pm3"
WORKDIR="/tmp/pm3"
LOGDIR="$WORKDIR/logs"
PM3_TIMEOUT=30
ALLOW_BLOCK0_WRITE="0"                   # Set to 1 to allow protected block writes (e.g., block 0/UID).
ALLOW_UID_WRITE="0"                      # Set to 1 to allow UID special writes for Ultralight/NTAG magic tags.

# Optional key overrides (leave empty to use autopwn).
# SRC_KEYFILE="/path/to/source-keys.bin"  # If set, skip source autopwn and dump with these keys.
# DST_KEYFILE="/path/to/dest-keys.bin"    # If set, skip destination autopwn and restore/verify with these keys.
# MFU_KEY="AABBCCDD"                      # Optional key/pwd for Ultralight/NTAG (4 bytes) or UL-C (16 bytes).
SRC_KEYFILE=""
DST_KEYFILE=""
MFU_KEY=""

mkdir -p "$WORKDIR" "$LOGDIR"
cd "$WORKDIR"

check_pm3() {
  if ! command -v "$PM3_BIN" >/dev/null 2>&1; then
    echo "[!] Proxmark3 client not found in PATH: $PM3_BIN"
    exit 1
  fi

  if ! compgen -G "/dev/ttyACM*" >/dev/null; then
    echo "[!] Proxmark3 device node not found (expected /dev/ttyACM*)"
    exit 1
  fi

  local output=""
  local status=0

  if command -v timeout >/dev/null 2>&1; then
    output="$(timeout "${PM3_TIMEOUT}s" $PM3_BIN -c "hw version; quit" 2>&1)" || status=$?
    if [ "$status" -eq 124 ]; then
      if printf "%s" "$output" | grep -qiE "waiting for proxmark3 to appear"; then
        echo "[!] Proxmark3 not detected or not connected"
      else
        echo "[!] Proxmark3 not responding (timed out after ${PM3_TIMEOUT}s)"
      fi
      exit 1
    fi
  else
    output="$($PM3_BIN -c "hw version; quit" 2>&1)" || status=$?
  fi

  if [ "$status" -ne 0 ]; then
    if printf "%s" "$output" | grep -qiE "waiting for proxmark3 to appear|no device|not found|not connected|could not open|open failed|usb|serial"; then
      echo "[!] Proxmark3 not detected or not connected"
    else
      echo "[!] Proxmark3 failed to respond"
    fi
    if [ -n "$output" ]; then
      echo "[!] Details: $output"
    fi
    exit 1
  fi
}


get_uid() {
  $PM3_BIN -c "hf 14a info; quit" 2>/dev/null \
    | awk '/UID:/{sub(/.*UID:/,""); gsub(/[^0-9A-Fa-f]/,"",$0); if (length($0)>0){print toupper($0); exit}}'
}

detect_tag_family() {
  local output=""
  if command -v timeout >/dev/null 2>&1; then
    output="$(timeout "${PM3_TIMEOUT}s" $PM3_BIN -c "hf 14a info; quit" 2>&1)" || true
  else
    output="$($PM3_BIN -c "hf 14a info; quit" 2>&1)" || true
  fi
  if printf "%s" "$output" | grep -qiE "Ultralight|NTAG"; then
    echo "mfu"
    return 0
  fi
  if printf "%s" "$output" | grep -qiE "MIFARE Classic|Classic 1k|Classic 4k|S50|S70"; then
    echo "mf"
    return 0
  fi
  echo "unknown"
  return 0
}

ensure_mfu_dump_ok() {
  local dump_file="$1"
  local log_file="$2"
  if [ ! -s "$dump_file" ]; then
    echo "[!] Ultralight/NTAG dump not created: $dump_file"
    exit 1
  fi
  if grep -q "Failed dumping card" "$log_file"; then
    echo "[!] Ultralight/NTAG dump failed (see $log_file)"
    exit 1
  fi
}

ensure_mfu_read_ok() {
  local log_file="$1"
  if grep -qiE "Failed dumping card" "$log_file"; then
    echo "[!] Read failed for Ultralight/NTAG. Provide MFU_KEY if needed."
    exit 1
  fi
  if grep -qiE "read failed|authentication failed|can't authenticate" "$log_file"; then
    local bad_pages=""
    bad_pages="$(awk '
      /read failed|authentication failed|can.t authenticate/ {
        if (match($0, /page[^0-9]*([0-9]+)/, m)) {print m[1]}
      }
    ' "$log_file" | sort -n | uniq | tr '\n' ' ')"
    if [ -z "$bad_pages" ]; then
      echo "[!] Read failed for Ultralight/NTAG. Provide MFU_KEY if needed."
      exit 1
    fi
    if echo "$bad_pages" | awk '{for(i=1;i<=NF;i++){if($i+0>3){exit 1}}}'; then
      echo "[*] Read failures only in UID pages (0-3); treating as OK"
    else
      echo "[!] Read failed for pages: ${bad_pages}Provide MFU_KEY if needed."
      exit 1
    fi
  fi
}

ensure_autopwn_keys_ok() {
  local log_file="$1"
  local bad=0
  bad="$(awk -F'|' '
    $1 ~ /[0-9]/ {
      sec=$1
      resA=$4
      resB=$6
      gsub(/[[:space:]]+/,"",sec)
      gsub(/[[:space:]]+/,"",resA)
      gsub(/[[:space:]]+/,"",resB)
      if (sec != "" && sec+0 > 0 && (resA=="0" || resB=="0")) {print 1; exit}
    }
  ' "$log_file")"
  if [ "$bad" = "1" ]; then
    echo "[!] Autopwn did not recover keys for some sectors (>0). Provide a keyfile."
    exit 1
  fi
}
run_pm3_cmd() {
  local desc="$1"
  local cmd="$2"
  local log_file="$3"
  local status=0

  if [ -n "$log_file" ]; then
    $PM3_BIN -c "$cmd; quit" | tee "$log_file"
    status=${PIPESTATUS[0]}
  else
    $PM3_BIN -c "$cmd; quit"
    status=$?
  fi

  if [ "$status" -ne 0 ]; then
    echo "[!] pm3 command failed during: $desc"
    exit 1
  fi
}

ensure_read_ok_classic() {
  local log_file="$1"
  local bad=""
  bad="$(awk -F'|' '
    /\( fail \)/ {
      blk=$1
      gsub(/[^0-9]/,"",blk)
      if (blk != "" && blk+0 > 0) {print blk}
    }
  ' "$log_file" | sort -n | uniq | tr '\n' ' ')"
  if [ -n "$bad" ]; then
    echo "[!] Read failed for blocks: ${bad}Provide a keyfile."
    exit 1
  fi
}


compare_dump_sizes() {
  local src="$1"
  local dst="$2"
  local src_size=""
  local dst_size=""
  if [ -f "$src" ] && [ -f "$dst" ]; then
    src_size="$(stat -c '%s' "$src" 2>/dev/null || true)"
    dst_size="$(stat -c '%s' "$dst" 2>/dev/null || true)"
    if [ -n "$src_size" ] && [ -n "$dst_size" ] && [ "$dst_size" -gt "$src_size" ]; then
      echo "[*] Note: destination tag dump ($dst_size bytes) is larger than source ($src_size bytes)"
    fi
  fi
}

ensure_restore_ok_classic() {
  local log_file="$1"
  local allow_block0="$2"
  local bad=""
  bad="$(awk -F'|' '
    /\( fail \)/ {
      blk=$1
      gsub(/[^0-9]/,"",blk)
      if (blk != "" && (blk+0 > 0 || allow_block0==1)) {print blk}
    }
  ' allow_block0="$allow_block0" "$log_file" | sort -n | uniq | tr '\n' ' ')"
  if [ -n "$bad" ]; then
    echo "[!] Restore failed for locked blocks: ${bad}Provide a keyfile."
    exit 1
  fi
}

wait_for_card_tag() {
  local label="$1"
  local uid=""
  echo "[*] $label" >&2
  while true; do
    uid="$(get_uid)"
    if [ -n "$uid" ]; then
      echo "[*] UID detected: $uid" >&2
      echo "$uid"
      return 0
    fi
    sleep 1
  done
}

wait_for_new_card() {
  local label="$1"
  local exclude_uid_a="$2"
  local exclude_uid_b="$3"
  local uid=""
  if [ -n "$label" ]; then
    echo "[*] $label" >&2
  fi
  while true; do
    uid="$(get_uid)"
    if [ -z "$uid" ]; then
      sleep 1
      continue
    fi
    if [ -n "$exclude_uid_a" ] && [ "$uid" = "$exclude_uid_a" ]; then
      echo "[*] Still detecting the source card/tag ($uid). Waiting for change..." >&2
      sleep 1
      continue
    fi
    if [ -n "$exclude_uid_b" ] && [ "$uid" = "$exclude_uid_b" ]; then
      echo "[*] Still detecting the previous destination card/tag ($uid). Waiting for change..." >&2
      sleep 1
      continue
    fi
    echo "[*] Destination card/tag UID detected: $uid" >&2
    echo "$uid"
    return 0
  done
}

# 1. Wait for source card/tag
check_pm3
echo "[*] Starting Proxmark3 in batch mode"
SRC_UID="$(wait_for_card_tag "Place the source card/tag")"

if [ -z "$SRC_UID" ]; then
  echo "[!] Source UID not found"
  exit 1
fi

KEYFILE=""
DUMPFILE=""
TAG_FAMILY="$(detect_tag_family)"
if [ "$TAG_FAMILY" = "unknown" ]; then
  echo "[!] Unable to detect tag family from hf 14a info. Replace card/tag."
  exit 1
fi
echo "[*] Detected tag family: $TAG_FAMILY"

if [ "$TAG_FAMILY" = "mfu" ]; then
  if [ -n "$SRC_KEYFILE" ] || [ -n "$DST_KEYFILE" ]; then
    echo "[!] SRC_KEYFILE/DST_KEYFILE are for Classic only. Use MFU_KEY for Ultralight/NTAG."
    exit 1
  fi
  echo "[*] Step 1: dump source card/tag (Ultralight/NTAG)"
  DUMPFILE="$WORKDIR/src-${SRC_UID}-dump.bin"
  MFU_KEY_ARG=""
  if [ -n "$MFU_KEY" ]; then
    MFU_KEY_ARG="-k $MFU_KEY"
  fi
  run_pm3_cmd "dump source card/tag (Ultralight/NTAG)" "hf mfu dump -f $DUMPFILE $MFU_KEY_ARG" "$LOGDIR/dump.log"
  ensure_mfu_dump_ok "$DUMPFILE" "$LOGDIR/dump.log"
  ensure_mfu_read_ok "$LOGDIR/dump.log"
else
  if [ -n "$SRC_KEYFILE" ]; then
    echo "[*] Step 1: using provided source keyfile (skipping autopwn)"
    KEYFILE="$SRC_KEYFILE"
  else
    echo "[*] Step 1: autopwn source card/tag"
    run_pm3_cmd "autopwn source card/tag" "hf mf autopwn" "$LOGDIR/autopwn.log"
    ensure_autopwn_keys_ok "$LOGDIR/autopwn.log"
  fi

  if [ -n "$SRC_KEYFILE" ]; then
    KEYFILE="$SRC_KEYFILE"
    DUMPFILE="$WORKDIR/src-${SRC_UID}-dump.bin"
    run_pm3_cmd "dump source card/tag" "hf mf dump -f $DUMPFILE -k $KEYFILE" "$LOGDIR/dump.log"
    run_pm3_cmd "verify readable sectors" "hf mf dump -f /tmp/pm3/src-${SRC_UID}-readcheck.bin -k $KEYFILE" "$LOGDIR/readcheck.log"
    ensure_read_ok_classic "$LOGDIR/readcheck.log"
  else
    KEYFILE="$(awk -F'`' '/Found keys have been dumped to/{print $2; exit}' "$LOGDIR/autopwn.log")"
    DUMPFILE="$(awk -F'`' '/Saved 1024 bytes to binary file/{print $2; exit}' "$LOGDIR/autopwn.log")"
  fi

  if [ -z "$KEYFILE" ] || [ ! -f "$KEYFILE" ]; then
    echo "[!] Keyfile not found: $KEYFILE"
    exit 1
  fi
  run_pm3_cmd "verify readable sectors" "hf mf dump -f /tmp/pm3/src-${SRC_UID}-readcheck.bin -k $KEYFILE" "$LOGDIR/readcheck.log"
  ensure_read_ok_classic "$LOGDIR/readcheck.log"
fi

# 2. Full dump
if [ -z "$DUMPFILE" ] || [ ! -f "$DUMPFILE" ]; then
  echo "[!] Dump not found: $DUMPFILE"
  exit 1
fi

if [ -n "$KEYFILE" ] && [ "$(dirname "$KEYFILE")" != "$WORKDIR" ]; then
  mv -f "$KEYFILE" "$WORKDIR/"
  KEYFILE="$WORKDIR/$(basename "$KEYFILE")"
  echo "[*] Moved source keyfile to $KEYFILE"
fi
if [ "$(dirname "$DUMPFILE")" != "$WORKDIR" ]; then
  mv -f "$DUMPFILE" "$WORKDIR/"
  DUMPFILE="$WORKDIR/$(basename "$DUMPFILE")"
  echo "[*] Moved source dump to $DUMPFILE"
fi

echo "[*] Dump completed: $DUMPFILE"

# 3. Clone to destination card(s)
echo
echo "=== REMOVE THE SOURCE CARD/TAG ==="
echo "=== PLACE THE DESTINATION CARD/TAG ==="
PREV_TGT_UID="$SRC_UID"

while true; do
  TGT_UID="$(wait_for_new_card "" "$SRC_UID" "$PREV_TGT_UID")"
  TGT_FAMILY="$(detect_tag_family)"
  if [ "$TGT_FAMILY" = "unknown" ]; then
    echo "[!] Unable to detect destination tag family. Replace destination card/tag."
    PREV_TGT_UID="$TGT_UID"
    continue
  fi
  if [ "$TGT_FAMILY" != "$TAG_FAMILY" ]; then
    echo "[!] Destination tag family ($TGT_FAMILY) does not match source ($TAG_FAMILY)."
    echo "[!] Replace destination card/tag."
    PREV_TGT_UID="$TGT_UID"
    continue
  fi

  if [ "$TAG_FAMILY" = "mfu" ]; then
    # 4. Restore (Ultralight/NTAG)
    echo "[*] Step 3: restore to destination card/tag (Ultralight/NTAG)"
    MFU_KEY_ARG=""
    if [ -n "$MFU_KEY" ]; then
      MFU_KEY_ARG="-k $MFU_KEY"
    fi
    MFU_UID_ARG=""
    if [ "${ALLOW_UID_WRITE:-0}" = "1" ]; then
      echo "[*] ALLOW_UID_WRITE=1 set; enabling special UID write (-s)"
      MFU_UID_ARG="-s"
    else
      echo "[*] UID pages will be skipped (set ALLOW_UID_WRITE=1 to override)"
    fi
    run_pm3_cmd "restore destination card/tag (Ultralight/NTAG)" "hf mfu restore -f $DUMPFILE $MFU_KEY_ARG $MFU_UID_ARG" "$LOGDIR/restore.log"

    # 5. Final verification (dump + compare)
    echo "[*] Step 4: final verification (dump + compare)"
    DEST_DUMP="$WORKDIR/dst-${TGT_UID}-dump.bin"
    run_pm3_cmd "verify destination card/tag (Ultralight/NTAG)" "hf mfu dump -f $DEST_DUMP $MFU_KEY_ARG" "$LOGDIR/verify.log"
  else
    # 4. Autopwn on destination card/tag
    if [ -n "$DST_KEYFILE" ]; then
      echo "[*] Step 3: using provided destination keyfile (skipping autopwn)"
      KEYFILE_DST="$DST_KEYFILE"
    else
      echo "[*] Step 3: autopwn destination card/tag"
      run_pm3_cmd "autopwn destination card/tag" "hf mf autopwn" "$LOGDIR/autopwn-dst.log"
      ensure_autopwn_keys_ok "$LOGDIR/autopwn-dst.log"
      KEYFILE_DST="$(awk -F'`' '/Found keys have been dumped to/{print $2; exit}' "$LOGDIR/autopwn-dst.log")"
    fi

    if [ ! -f "$KEYFILE_DST" ]; then
      echo "[!] Destination keyfile not found: $KEYFILE_DST"
      exit 1
    fi

    if [ "$(dirname "$KEYFILE_DST")" != "$WORKDIR" ]; then
      mv -f "$KEYFILE_DST" "$WORKDIR/"
      KEYFILE_DST="$WORKDIR/$(basename "$KEYFILE_DST")"
      echo "[*] Moved destination keyfile to $KEYFILE_DST"
    fi

    # 5. Restore (skip protected blocks unless explicitly allowed)
    echo "[*] Step 4: restore to destination card/tag"
    RESTORE_FORCE=""
    if [ "${ALLOW_BLOCK0_WRITE:-0}" = "1" ]; then
      echo "[*] ALLOW_BLOCK0_WRITE=1 set; allowing protected block writes"
      RESTORE_FORCE="--force"
    else
      echo "[*] Protected blocks will be skipped (set ALLOW_BLOCK0_WRITE=1 to override)"
    fi
    run_pm3_cmd "restore destination card/tag" "hf mf restore -f $DUMPFILE -k $KEYFILE_DST $RESTORE_FORCE" "$LOGDIR/restore.log"
    if [ -z "$DST_KEYFILE" ]; then
      ensure_restore_ok_classic "$LOGDIR/restore.log" "${ALLOW_BLOCK0_WRITE:-0}"
    fi

    # 6. Final verification (dump + compare)
    echo "[*] Step 5: final verification (dump + compare)"
    DEST_DUMP="$WORKDIR/dst-${TGT_UID}-dump.bin"
    run_pm3_cmd "verify destination card/tag" "hf mf dump -f $DEST_DUMP -k $KEYFILE_DST" "$LOGDIR/verify.log"
  fi

  if [ ! -f "$DEST_DUMP" ]; then
    echo "[!] Destination dump not created: $DEST_DUMP"
    exit 1
  fi
  compare_dump_sizes "$DUMPFILE" "$DEST_DUMP"

  if ! cmp -s "$DUMPFILE" "$DEST_DUMP"; then
    echo "[!] Verification mismatch: destination dump differs from source"
    cmp -l "$DUMPFILE" "$DEST_DUMP" > "$LOGDIR/verify-diff.raw" || true
    echo "[*] Showing all differing bytes (offset -> block: src != dst)"
    awk '{off=$1-1; blk=int(off/16); printf "  offset %d (block %d): %03o != %03o\n", off, blk, $2, $3}' \
      "$LOGDIR/verify-diff.raw" | tee "$LOGDIR/verify-diff.log"

    if [ "$TAG_FAMILY" = "mfu" ]; then
      if [ "${ALLOW_UID_WRITE:-0}" != "1" ]; then
        if awk '{off=$1-1; if (off>=12) {exit 1}}' "$LOGDIR/verify-diff.raw"; then
          echo "[*] Differences are only in UID pages and ALLOW_UID_WRITE is not set; treating as OK"
        else
          exit 1
        fi
      else
        exit 1
      fi
    else
      if [ "${ALLOW_BLOCK0_WRITE:-0}" != "1" ]; then
        if awk '{off=$1-1; blk=int(off/16); if (blk!=0) {exit 1}}' "$LOGDIR/verify-diff.raw"; then
          echo "[*] Differences are only in block 0 and ALLOW_BLOCK0_WRITE is not set; treating as OK"
        else
          exit 1
        fi
      else
        exit 1
      fi
    fi
  fi

  echo
  echo "[+] Clone completed for UID $TGT_UID (source: $SRC_UID)"
  PREV_TGT_UID="$TGT_UID"
  read -r -p "Clone same source to another destination card/tag? (y/N): " REPLY
  if [ "${REPLY:-n}" != "y" ] && [ "${REPLY:-n}" != "Y" ]; then
    break
  fi
  echo
  echo "=== PLACE THE NEXT DESTINATION CARD/TAG (same source dump) ==="
done
