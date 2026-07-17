#!/usr/bin/env bash
# Create stacked upstream PR branches from integrated fork master.
# Usage: ./tools/create_upstream_pr_branches.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INTEGRATED="${INTEGRATED_BRANCH:-master}"
UP="${UPSTREAM_REF:-upstream/master}"

git fetch upstream master 2>/dev/null || true
git fetch origin "$INTEGRATED" 2>/dev/null || true

if ! git rev-parse "$UP" >/dev/null 2>&1; then
    echo "Missing $UP — add remote: git remote add upstream https://github.com/RfidResearchGroup/proxmark3.git"
    exit 1
fi

TERMINAL_3A=(
    emv/terminal/emv_term_ctx.c
    emv/terminal/emv_term_ctx.h
    emv/terminal/emv_term_profile.c
    emv/terminal/emv_term_profile.h
    emv/terminal/emv_term_scheme.c
    emv/terminal/emv_term_scheme.h
    emv/terminal/emv_term_session.c
    emv/terminal/emv_term_session.h
    emv/terminal/emv_term_session_view.c
    emv/terminal/emv_term_session_view.h
    emv/terminal/emv_term_tvr.c
    emv/terminal/emv_term_tvr.h
    emv/terminal/emv_term_load.c
    emv/terminal/emv_term_load.h
    emv/terminal/emv_transaction.c
    emv/terminal/emv_transaction.h
    emv/terminal/phase_init.c
    emv/terminal/phase_init.h
    emv/terminal/phase_oda.c
    emv/terminal/phase_oda.h
    emv/terminal/phase_restrict.c
    emv/terminal/phase_restrict.h
    emv/terminal/phase_cvm.c
    emv/terminal/phase_cvm.h
    emv/terminal/phase_trm.c
    emv/terminal/phase_trm.h
    emv/terminal/phase_taa.c
    emv/terminal/phase_taa.h
    emv/terminal/phase_caa.c
    emv/terminal/phase_caa.h
    emv/terminal/phase_complete.c
    emv/terminal/phase_complete.h
    emv/terminal/phase_scripts.c
    emv/terminal/phase_scripts.h
    emv/terminal/emv_term_mock.c
    emv/terminal/emv_term_mock.h
    emv/terminal/emv_term_secure.c
    emv/terminal/emv_term_secure.h
    emv/terminal/emv_term_exception.c
    emv/terminal/emv_term_exception.h
    emv/terminal/emv_term_redact.c
    emv/terminal/emv_term_redact.h
    emv/terminal/emv_term_tlv.c
    emv/terminal/emv_term_tlv.h
    emv/terminal/emv_term_reader_session.c
    emv/terminal/emv_term_reader_session.h
    emv/test/terminal_taa_test.c
    emv/test/terminal_taa_test.h
    emv/test/terminal_cvm_test.c
    emv/test/terminal_cvm_test.h
    emv/test/terminal_exception_test.c
    emv/test/terminal_exception_test.h
    emv/terminal/emv_term_pcap.c
    emv/terminal/emv_term_pcap.h
    emv/terminal/emv_term_pin_prompt.c
    emv/terminal/emv_term_pin_prompt.h
)

TERMINAL_3B=(
    emv/terminal/emv_terminal.c
    emv/terminal/emv_terminal.h
    emv/terminal/phase_online.c
    emv/terminal/phase_online.h
    emv/terminal/emv_term_arqc.c
    emv/terminal/emv_term_arqc.h
    emv/terminal/emv_term_host.c
    emv/terminal/emv_term_host.h
    emv/terminal/emv_term_host_tcp.c
    emv/terminal/emv_term_host_tcp.h
    emv/terminal/emv_term_golden.c
    emv/terminal/emv_term_golden.h
    emv/terminal/emv_term_sim_export.c
    emv/terminal/emv_term_sim_export.h
    emv/terminal/emv_term_lua.c
    emv/terminal/emv_term_lua.h
    emv/terminal/emv_term_banner.c
    emv/terminal/emv_term_banner.h
    emv/terminal/emv_term_replay.c
    emv/terminal/emv_term_replay.h
    emv/terminal/emv_term_timing.c
    emv/terminal/emv_term_timing.h
    emv/terminal/emv_term_probe.c
    emv/terminal/emv_term_probe.h
    emv/terminal/emv_term_crypto.c
    emv/terminal/emv_term_crypto.h
    emv/terminal/emv_term_crypto_digest.c
    emv/terminal/emv_term_crypto_digest.h
    emv/terminal/emv_term_capabilities.c
    emv/terminal/emv_term_capabilities.h
    emv/test/terminal_host_test.c
    emv/test/terminal_host_test.h
    emv/test/terminal_crypto_test.c
    emv/test/terminal_crypto_test.h
    emv/test/terminal_sim_export_test.c
    emv/test/terminal_sim_export_test.h
    emv/test/terminal_pcap_test.c
    emv/test/terminal_pcap_test.h
    emv/test/terminal_replay_test.c
    emv/test/terminal_replay_test.h
)

checkout_terminal_files() {
    local prefix="client/src"
    for f in "$@"; do
        git checkout "$INTEGRATED" -- "$prefix/$f"
    done
}

strip_makefile_terminal_3b() {
    local patterns=(
        'emv/terminal/emv_terminal.c'
        'emv/terminal/phase_online.c'
        'emv/terminal/emv_term_cmd.c'
        'emv/terminal/emv_term_arqc.c'
        'emv/terminal/emv_term_host.c'
        'emv/terminal/emv_term_golden.c'
        'emv/terminal/emv_term_sim_export.c'
        'emv/terminal/emv_term_host_tcp.c'
        'emv/terminal/emv_term_lua.c'
        'emv/terminal/emv_term_banner.c'
        'emv/terminal/emv_term_replay.c'
        'emv/terminal/emv_term_timing.c'
        'emv/terminal/emv_term_probe.c'
        'emv/terminal/emv_term_crypto.c'
        'emv/terminal/emv_term_crypto_digest.c'
        'emv/terminal/emv_term_crypto_cmd.c'
        'emv/terminal/emv_term_capabilities.c'
        'emv/test/terminal_host_test.c'
        'emv/test/terminal_crypto_test.c'
        'emv/test/terminal_sim_export_test.c'
        'emv/test/terminal_pcap_test.c'
        'emv/test/terminal_replay_test.c'
    )
    for p in "${patterns[@]}"; do
        sed -i "/${p//\//\\/}/d" client/Makefile
    done
}

strip_makefile_terminal_cmd() {
    local patterns=(
        'emv/terminal/emv_term_cmd.c'
        'emv/terminal/emv_term_crypto_cmd.c'
    )
    for p in "${patterns[@]}"; do
        sed -i "/${p//\//\\/}/d" client/Makefile
        sed -i "/${p//\//\\/}/d" client/CMakeLists.txt
        sed -i "/${p//\//\\/}/d" client/experimental_lib/CMakeLists.txt
    done
}

write_cryptotest_terminal() {
    local mode="$1"
    git checkout "$UP" -- client/src/emv/test/cryptotest.c client/src/emv/test/cryptotest.h
    python3 - "$mode" <<'PY'
import sys
from pathlib import Path

mode = sys.argv[1]
p = Path("client/src/emv/test/cryptotest.c")
text = p.read_text()

includes = {
    "3a": (
        "#include \"terminal_taa_test.h\"\n"
        "#include \"terminal_cvm_test.h\"\n"
        "#include \"terminal_exception_test.h\"\n"
    ),
    "3b": (
        "#include \"terminal_taa_test.h\"\n"
        "#include \"terminal_host_test.h\"\n"
        "#include \"terminal_cvm_test.h\"\n"
        "#include \"terminal_crypto_test.h\"\n"
        "#include \"terminal_exception_test.h\"\n"
        "#include \"terminal_sim_export_test.h\"\n"
        "#include \"terminal_pcap_test.h\"\n"
        "#include \"terminal_replay_test.h\"\n"
    ),
}
tests = {
    "3a": (
        "    res = exec_terminal_taa_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_cvm_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_exception_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
    ),
    "3b": (
        "    res = exec_terminal_taa_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_host_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_cvm_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_crypto_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_exception_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_sim_export_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_pcap_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
        "    res = exec_terminal_replay_test(verbose);\n"
        "    if (res) TestFail = true;\n\n"
    ),
}

anchor = "#include \"cda_test.h\"\n"
if anchor not in text:
    raise SystemExit("cryptotest.c anchor not found")
text = text.replace(anchor, anchor + includes[mode], 1)

before = "    res = exec_crypto_test(verbose, include_slow_tests);\n"
if before not in text:
    raise SystemExit("cryptotest.c exec_crypto_test anchor not found")
text = text.replace(before, tests[mode] + before, 1)
p.write_text(text)
PY
}

echo "=== PR1: docs/emv-terminal-planning ==="
git checkout -B cursor/upstream-pr-1-docs-e836 "$UP"
git checkout "$INTEGRATED" -- doc/planning doc/emv_pcap_format.md
rm -f doc/planning/emv-terminal-emulator/OPERATOR-GUIDE.md
git checkout "$INTEGRATED" -- README.md
# Docs-only CHANGELOG line
python3 <<'PY'
from pathlib import Path
cl = Path("CHANGELOG.md")
text = cl.read_text()
needle = "## [unreleased][unreleased]\n"
insert = "- Added EMV terminal emulator planning documentation under `doc/planning/emv-terminal-emulator/` (lab/research use only; not a certified payment terminal).\n"
if insert.strip() not in text:
    text = text.replace(needle, needle + insert, 1)
    cl.write_text(text)
PY
git add doc/planning doc/emv_pcap_format.md README.md CHANGELOG.md
git commit -m "docs(emv): add EMV terminal emulator planning bundle

Planning specs, milestones, and architecture for the lab terminal emulator.
No executable code. Operator guide and CLI docs land in a follow-up PR."

echo "=== PR2: chore/emv-terminal-resources ==="
git checkout -B cursor/upstream-pr-2-resources-e836 cursor/upstream-pr-1-docs-e836
git checkout "$INTEGRATED" -- \
    client/resources/emv_terminal_profile.json \
    client/resources/host_sim_interac.json \
    client/resources/interac_test_keys.json \
    client/resources/emv_terminal_profile_interac.json \
    client/resources/terminal_aid_candidates.json \
    client/resources/exception_file_sample.txt \
    client/resources/scheme_profiles \
    client/src/emv/test/fixtures
git checkout "$INTEGRATED" -- .gitignore
git commit -m "chore(emv): add terminal profiles, scheme JSON, and golden fixtures

Public interoperability test keys and synthetic fixtures only.
No C source changes."

echo "=== PR3a: feat/emv-terminal-core-phases ==="
git checkout -B cursor/upstream-pr-3a-phases-e836 cursor/upstream-pr-2-resources-e836
checkout_terminal_files "${TERMINAL_3A[@]}"
git checkout "$INTEGRATED" -- \
    client/src/emv/emvcore.c \
    client/src/emv/emvcore.h \
    client/src/emv/emvjson.c \
    client/src/emv/emvjson.h \
    client/src/emv/emv_pk.c \
    client/src/emv/emv_pk.h \
    client/src/iso7816/iso7816core.c \
    client/Makefile
strip_makefile_terminal_3b
write_cryptotest_terminal 3a
git checkout "$INTEGRATED" -- client/src/emv/test/terminal_test_util.h
git add -A
git commit -m "feat(emv): terminal emulator phase engine and offline unit tests

Adds phase pipeline (init through CAA/complete), session/profile/scheme
loaders, mock APDU path, and terminal_taa/cvm/exception self-tests.
Full terminal orchestrator, online host path, and crypto lab land in
follow-up PRs 3b and 4."

echo "=== PR3b: feat/emv-terminal-core-host-crypto ==="
git checkout -B cursor/upstream-pr-3b-host-crypto-e836 cursor/upstream-pr-3a-phases-e836
checkout_terminal_files "${TERMINAL_3B[@]}"
git checkout "$INTEGRATED" -- \
    client/src/scripting.c \
    client/luascripts/emv_terminal_demo.lua \
    client/Makefile \
    client/CMakeLists.txt \
    client/experimental_lib/CMakeLists.txt
strip_makefile_terminal_cmd
write_cryptotest_terminal 3b
git add -A
git commit -m "feat(emv): host simulator, golden runner, and crypto playground core

Adds online phase, host/TCP acquirer, ARQC/ARPC, golden fixtures runner,
crypto lab internals, Lua hooks, and remaining terminal self-tests.
User-facing emv terminal CLI commands land in PR 4."

echo "=== PR4: feat/emv-terminal-cli ==="
git checkout -B cursor/upstream-pr-4-cli-e836 cursor/upstream-pr-3b-host-crypto-e836
git checkout "$INTEGRATED" -- \
    client/src/emv/terminal/emv_term_cmd.c \
    client/src/emv/terminal/emv_term_cmd.h \
    client/src/emv/terminal/emv_term_crypto_cmd.c \
    client/src/emv/terminal/emv_term_crypto_cmd.h \
    client/src/emv/cmdemv.c \
    client/src/proxmark3.c \
    doc/planning/emv-terminal-emulator/OPERATOR-GUIDE.md \
    doc/emv_notes.md \
    CHANGELOG.md \
    README.md \
    tools/pm3_tests.sh \
    .github/workflows/ubuntu.yml \
    .github/workflows/macos.yml \
    .github/workflows/windows.yml \
    .github/codeql/codeql-config.yml \
    .github/workflows/codeql-analysis.yml \
    client/src/emv/test/cryptotest.c \
    client/src/emv/test/cryptotest.h \
    client/Makefile \
    client/CMakeLists.txt \
    client/experimental_lib/CMakeLists.txt
# Field activation / protocol hooks if present
for f in armsrc/iso14443b.c include/protocols.h include/iso14b.h client/src/cmdhf14b.c client/src/ui.h client/resources/aidlist.json client/resources/capk.txt client/resources/emv_defparams.json; do
    if git diff --name-only "$UP" "$INTEGRATED" -- "$f" | grep -q .; then
        git checkout "$INTEGRATED" -- "$f"
    fi
done
git add -A
git commit -m "feat(emv): emv terminal CLI, operator docs, and CI fixes

User-facing emv terminal command tree, crypto playground CLI, operator
guide, offline test hooks, MinGW-safe strings, cmake source sync, and
CodeQL tuning for historic EMV interop algorithms."

echo "=== Done. Branches:"
git branch --list 'cursor/upstream-pr-*'
