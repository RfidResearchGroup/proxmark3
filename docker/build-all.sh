#!/bin/bash
# (Need bash because of Bash Arrays)

FAILED=()
TOTAL=0

for os in archlinux debian-13-trixie debian-13-trixie-arm64 debian-13-trixie-armhf debian-14-forky fedora-41 fedora-42 fedora-43 homebrew kali opensuse-leap opensuse-tumbleweed parrot-core-latest ubuntu-22.04 ubuntu-24.04 ubuntu-24.10 ubuntu-25.04 ubuntu-25.10; do
  echo -e "\n\n================= Building for $os ======================\n"
  TOTAL=$((TOTAL + 1))

  # a name in the list above with no directory is drift, not something to skip quietly
  if [ ! -d "$os" ]; then
    echo "no docker/$os directory"
    FAILED+=("$os (no such directory)")
    continue
  fi

  (  cd "$os" && ../build.sh ) || FAILED+=("$os")
done

echo -e "\n\n================= Summary ======================\n"

if [ ${#FAILED[@]} -gt 0 ]; then
  echo "${#FAILED[@]} of $TOTAL image(s) failed to build:"
  printf '  %s\n' "${FAILED[@]}"
  exit 1
fi

echo "all $TOTAL images built"
