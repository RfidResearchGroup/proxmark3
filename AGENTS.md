# AGENTS.md

Instructions for AI coding agents (and humans using one) proposing pull requests
to this repository. This complements `README.md` and `Maintainers.md`; when in
doubt, those human-facing docs win.

## Repo shape (quick map)

- `bootrom/`, `armsrc/` — ARM firmware for the device (Proxmark3
  hardware targets), buildable via **either** the top-level
  `Makefile` **or** their respective `CMakeLists.txt`. Keep both build definitions in sync.
- `client/` — host-side client, buildable via **either** the top-level
  `Makefile` **or** `client/CMakeLists.txt`. Keep both build definitions in sync.
- `client/experimental_lib/` — experimental shared-lib build of the client,
  has its own `CMakeLists.txt`. Any change to the client `client/CMakeLists.txt` almost always implies a change in `client/experimental_lib/CMakeLists.txt`.
- `common_arm/`, `common/` — shared code between firmware and/or client.
- `tools/` — standalone tool suites (`hitag2crack`, `mfc/*`, `fpga_compress`,
  `ePassport`, etc.), each with its own `Makefile` and its own `check` target.

## Before opening a PR: build matrix

Do not treat "it compiles for me" as done. For any non-trivial change, verify
across the axes below (skip only the ones genuinely unaffected by your diff,
and say explicitly in the PR description which axes you *did* and *did not*
test):

1. **Zero warnings.** `make clean && make all` must complete with no compiler
   warnings on the default toolchain (gcc). Warnings are effectively treated
   as errors in this project's normal dev flow.
2. **Second compiler.** Also try building host client and host tools (if touched) with clang, e.g. `make clean && make client -j CC=clang CXX=clang++ LD=clang++`
   and fix anything it flags that gcc didn't — clang's
   diagnostics catch different classes of bugs (e.g. some format-string and
   sign issues).
3. **Both client build systems.** If you touched client code, dependencies,
   or build flags, update and test:
   - `client/Makefile` (default `make client`)
   - `client/CMakeLists.txt`
   - `client/experimental_lib/CMakeLists.txt`
   A file added to one and not the others is an incomplete PR.
4. **ARM firmware targets.** If you touched `armsrc/`, `bootrom/`,
   `common_arm/`, or anything reachable from firmware, compile at least for **both**
   main platform configs (`PLATFORM=` per `Makefile.platform`): PM3RDV4 and PM5.
   Use also PLATFORM_EXTRAS if relevant to your changes.
5. **Cross-OS for platform-sensitive code.** Anything touching serial/USB
   comms, filesystem paths, threading, or conditional `#ifdef _WIN32` /
   `__APPLE__` / `__linux__` code needs to at least be reasoned through, and
   ideally exercised, on all three supported environments: native Linux,
   Windows (ProxSpace or WSL, per the project's documented Windows build
   path), and macOS. Say in the PR which of these you actually ran.
6. **Offline tests.** Run `make check` (or the narrower `<target>/check`,
   e.g. `client/check`, `armsrc/check`) and make sure it stays green. Add to
   `tools/pm3_tests.sh` coverage if you're adding a new command/module that
   can be exercised offline.

## Code style

- Respect the style used in this project: trailing
  whitespace/EOL cleanup, Equivalent of `astyle` on `*.c`/`*.h` with 
  `--style=google --indent=spaces=4 --indent-switches --keep-one-line-blocks
  --max-continuation-indent=60 --pad-oper --unpad-paren --pad-header
  --align-pointer=name` and on `*.cpp`/`*.hpp` (same, minus `--pad-oper`).
  Don't hand-format C/C++ differently from what `astyle` produces.
- Don't reformat existing code outside of your changes, only format your own code.
- If your change adds/changes a client command, run `make commands` to
  regenerate `doc/commands.md` and `doc/commands.json` — don't hand-edit
  those generated files.
- **Preserve existing comments** in code you touch or move. Don't drop,
  "clean up", or silently reword neighboring comments as a side effect of an
  unrelated change.
- Keep the GPLv3 file header banner (see any existing `.c`/`.h`/`Makefile`)
  on new files; copy it verbatim from a neighboring file of the same type.

## PR description format

Structure the PR description in these sections:

- **Problem** — what's actually wrong today, with concrete symptoms/examples,
  not just "code is messy."
- **Change** — what you did, file by file if it helps a reviewer, and *why*
  this approach (e.g. why runtime computation instead of a regenerated table).
- **Behaviour change** — call out explicitly, as its own section, anything a
  user or downstream code could observe differently after your change, even
  if the new behavior is strictly more correct. Don't let this hide inside
  the diff.
- **Testing** — be specific and be honest:
  - List the exact build variants exercised, e.g. "readline (`make`),
    linenoise (`SKIPREADLINE=1`), CMake client, `experimental_lib` (LIBPM3),
    `PLATFORM=PM5` and default RDV4."
  - Explicitly state what you did **not** test (e.g. "Not tested here:
    Windows/ProxSpace and macOS") rather than implying full coverage. Where
    possible, give a one-line reason the untested paths are low-risk (e.g.
    "only uses `scandir`/`alphasort`, already used portably elsewhere in
    `fileutils.c`").
  - Net diff size and notable deletions are worth mentioning — removing a
    stale generated table or dead code is a feature of the PR, not a
    side note.

## PR checklist (put this in the PR description)

- [ ] Proper style of own code, no unrelated reformatting included
- [ ] Builds warning-free with gcc; also tried with clang
- [ ] `client/Makefile`, `client/CMakeLists.txt`, and
      `client/experimental_lib/CMakeLists.txt` all updated if client sources
      changed
- [ ] ARM firmware builds clean for RDV4 and PM5 platform configs (if
      `armsrc`/`bootrom`/`common_arm` touched)
- [ ] Platform-sensitive code reasoned about / tested on Linux, Windows
      (ProxSpace/WSL), and macOS (if applicable) — state which were tested
- [ ] Existing comments in touched files preserved
- [ ] `doc/commands.md` / `doc/commands.json` regenerated if commands changed

## Commit attribution

If an AI agent authored or materially contributed to a commit, say so with a
trailer, the same way you'd credit a human co-author, e.g.:

```
Co-Authored-By: <agent/model name> <noreply@anthropic.com>
```

Don't omit this to make a PR look purely human-written.

## What not to do

- Don't add `-Werror`-suppressing flags or `#pragma` warning silences to make
  a warning disappear — fix the underlying issue.
- Don't introduce a dependency in one client build file without mirroring it
  in the other two.
- Don't submit ARM-side changes only test-built for one platform target.
