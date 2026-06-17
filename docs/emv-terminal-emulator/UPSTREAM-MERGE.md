# Upstream Merge Plan — EMV Terminal Emulator

This document describes how to land the stacked development PRs as **one contribution** to the upstream Proxmark3 Iceman repository.

---

## Development PR stack (this fork)

| PR | Branch | Base | Milestone |
|----|--------|------|-----------|
| #1 | `cursor/emv-terminal-emulator-specs-d143` | `master` | Docs + v2 specs |
| #3 | `cursor/emv-wave-b-d143` | Wave A (#1 branch) | M10–M12 |
| #4 | `cursor/emv-wave-c-d143` | Wave B | M13 integration |
| #5 | `cursor/emv-wave-d-d143` | Wave C | M14 trace/polish |

---

## Merge order (into each other)

Merge **newest into older**, then one final branch off `master`:

```text
1. Merge PR #5 (Wave D) → into cursor/emv-wave-c-d143
2. Merge PR #4 (Wave C) → into cursor/emv-wave-b-d143   (now includes D)
3. Merge PR #3 (Wave B)  → into cursor/emv-terminal-emulator-specs-d143 (now includes C+D)
4. Rebase or merge PR #1 branch onto latest master (resolve conflicts)
5. Open ONE upstream PR from the consolidated branch
```

Alternatively, **squash-merge locally** (cleaner for upstream):

```bash
git checkout master
git pull origin master
git checkout -b feat/emv-terminal-emulator-upstream

# Merge the tip of the stack (contains everything)
git merge --no-ff origin/cursor/emv-wave-d-d143

# Or cherry-pick the 5 feature commits in order:
# b6917ec49 docs
# 5c5ca6a98 wave A
# e8686726a wave B
# 41631c62c wave C
# bccbf99a6 wave D

make -C client CC=gcc
./pm3 --offline -c 'emv test'
./pm3 --offline -c 'emv terminal test --golden'
```

---

## Recommended upstream pull request

| Field | Value |
|-------|--------|
| **Title** | `feat(emv): add EMV terminal emulator (lab research tool)` |
| **Base** | upstream `master` |
| **Labels** | `enhancement`, `documentation` (as appropriate) |

### Suggested PR description outline

1. **Disclaimer** — research/lab only; link `docs/emv-terminal-emulator/README.md` legal section and `SPEC-security-privacy.md`
2. **Summary** — terminal-side EMV phase engine (`emv terminal`), host simulator, scheme profiles, golden CI, integration (Lua/TCP/sim export), trace/replay
3. **Testing** — `./pm3 --offline -c 'emv test'` and `emv terminal test --golden` (6/6, no USB)
4. **Docs** — `docs/emv-terminal-emulator/`, `doc/emv_notes.md`, `doc/emv_pcap_format.md`
5. **Not included** — PCI certification, production acquirer connectivity, firmware WTX (deferred F-027)

---

## Pre-merge checklist

- [ ] `CC=gcc make -C client` clean build
- [ ] `./pm3 --offline -c 'emv test'` passes
- [ ] `./pm3 --offline -c 'emv terminal test --golden'` — 6/6 OK
- [ ] Legal banner + README disclaimer reviewed
- [ ] No real PAN/keys in fixtures or examples
- [ ] Root `CHANGELOG.md` entry added (see unreleased section)
- [ ] Squash or conventional commit history acceptable to upstream maintainers

---

## After upstream merge

Close stacked PRs #1, #3, #4, #5 on the fork (superseded by upstream PR).  
Tag locally if desired: `emv-term-v2.3` per [MILESTONES-v2.md](./MILESTONES-v2.md).
