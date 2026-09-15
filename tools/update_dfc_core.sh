#!/usr/bin/env bash
set -euo pipefail

mode=update
if [[ "${1:-}" == "--check" ]]; then
    mode=check
    shift
fi

source_repo="${1:-../dfc-core}"
root="$(git rev-parse --show-toplevel)"
dest="$root/common/dfc-core"

if ! git -C "$source_repo" rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "dfc-core repository not found: $source_repo" >&2
    exit 1
fi

revision="$(git -C "$source_repo" rev-parse HEAD)"

check_file() {
    local relative="$1"
    cmp -s "$source_repo/$relative" "$dest/$relative" || {
        echo "vendored dfc-core differs: $relative" >&2
        return 1
    }
}

if [[ "$mode" == "check" ]]; then
    status=0
    while IFS= read -r relative; do
        check_file "$relative" || status=1
    done < <(
        cd "$source_repo"
        find src -type f \( -name '*.c' -o -name '*.h' \) -print | sort
        printf '%s\n' LICENSE port/dfc_bytebuf.h port/dfc_port.h
    )

    if [[ "$(cat "$dest/REVISION")" != "$revision" ]]; then
        echo "vendored dfc-core revision differs" >&2
        status=1
    fi
    exit "$status"
fi

mkdir -p "$dest/src" "$dest/port"
find "$dest/src" -type f \( -name '*.c' -o -name '*.h' \) -delete
cp "$source_repo"/src/*.c "$source_repo"/src/*.h "$dest/src/"
cp "$source_repo/port/dfc_bytebuf.h" "$source_repo/port/dfc_port.h" "$dest/port/"
cp "$source_repo/LICENSE" "$dest/LICENSE"
printf '%s\n' "$revision" > "$dest/REVISION"

echo "Vendored dfc-core $revision"
