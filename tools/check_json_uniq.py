#!/usr/bin/env python3
"""Check the AID resource files for duplicate entries.

client/resources/aid_desfire.json and aidlist.json are looked up by AID, and
the lookup returns the FIRST match (see find_aiddf_entry() in
client/src/mifare/aiddesfire.c). A second entry with the same AID is therefore
dead data: nothing can ever print it.

One exception is legitimate. aidsearch.c matches a card's actual response
against "ResponseRegex" to choose between entries that share an AID, so a group
whose members all carry a distinct ResponseRegex is disambiguated at runtime and
is allowed. That is how Apple, Google and Samsung all live on OSE.VAS.01.

Run with no arguments from anywhere in the tree, or pass files explicitly.
Exits non-zero when a real duplicate is found.
"""

import json
import os
import sys
from collections import defaultdict

DEFAULT_FILES = [
    "client/resources/aid_desfire.json",
    "client/resources/aidlist.json",
]

DISAMBIGUATOR = "ResponseRegex"


def repo_root():
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.dirname(here)


def check(path):
    """Return the number of offending AID groups in one file."""
    try:
        with open(path, encoding="utf-8") as fd:
            data = json.load(fd)
    except FileNotFoundError:
        print("  %s: not found, skipped" % path)
        return 0
    except json.JSONDecodeError as exc:
        print("  %s: invalid json, line %d: %s" % (path, exc.lineno, exc.msg))
        return 1

    if not isinstance(data, list):
        print("  %s: root is not an array" % path)
        return 1

    groups = defaultdict(list)
    for idx, entry in enumerate(data):
        if not isinstance(entry, dict) or "AID" not in entry:
            continue
        groups[str(entry["AID"]).upper()].append((idx, entry))

    bad = 0
    allowed = 0

    for aid, members in sorted(groups.items()):
        if len(members) < 2:
            continue

        regexes = [e.get(DISAMBIGUATOR, "") for _, e in members]
        if all(regexes) and len(set(regexes)) == len(regexes):
            allowed += 1
            print("  %s: AID %s appears %d times, disambiguated by %s ( allowed )"
                  % (path, aid, len(members), DISAMBIGUATOR))
            continue

        bad += 1
        print("  %s: AID %s appears %d times and is NOT disambiguated" % (path, aid, len(members)))
        for idx, entry in members:
            print("      index %-5d %-34s %s" % (idx,
                                                 entry.get("Name", ""),
                                                 entry.get("Vendor", "")))
        print("      only the first is reachable. Merge them, or give each a distinct %s"
              % DISAMBIGUATOR)

    if len(groups):
        print("  %s: %d entries, %d duplicate group(s) allowed, %d rejected"
              % (path, len(data), allowed, bad))
    return bad


def main():
    files = sys.argv[1:]
    if not files:
        root = repo_root()
        files = [os.path.join(root, f) for f in DEFAULT_FILES]

    print("Checking AID resource files for duplicate entries")
    total = sum(check(f) for f in files)

    if total:
        print("\nFAIL: %d duplicate AID group(s)" % total)
        return 1

    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
