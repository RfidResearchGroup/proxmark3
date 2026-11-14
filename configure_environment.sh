#!/usr/bin/env bash
#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------
# First-run environment check for a freshly cloned repo: host compilers, ARM
# toolchain, client libraries, Python venv + requirements, device access.
#
# Reports by default and changes nothing, except that it offers to create a
# Python venv when no venv is found at all. Pass --install to let it install
# the missing packages too.
#-----------------------------------------------------------------------------

set -u

PM3PATH="$(cd "$(dirname "$0")" && pwd)"
cd "$PM3PATH" || exit 1

LANG=C

# --- options -----------------------------------------------------------------

DO_INSTALL=false
ASSUME_YES=false
WANT_EXTRAS=false
USE_COLOR=auto
VENV_OPT=""
NO_VENV=false

usage() {
    cat <<USAGE
Usage: ./configure_environment.sh [options]

Checks that this machine can build the Proxmark3 client and firmware, that the
chosen PLATFORM matches your device, and that the Python side (venv +
requirements) is in place. Run it once after cloning.

'make configure' runs the same thing. Call this script directly when make itself
refuses to start, e.g. after a typo in PLATFORM, since make stops on that before
it could run any target.

Options:
  --install        install what is missing (system packages via the detected
                   package manager, venv, Python requirements). Asks first.
  -y, --yes        don't ask, assume yes. Only meaningful with --install.
  --extras         also consider the optional requirement files
                   (fpga/, tools/ePassport/, tools/btaddon/).
  --venv PATH      use this venv instead of searching for one.
  --no-venv        don't look for or offer a venv, check the system python.
  --no-color       plain output.
  -h, --help       this text.

Environment:
  PM3_VENV         same as --venv.
  CROSS            ARM toolchain prefix, default arm-none-eabi-
  CC               host C compiler used for the library probes, default gcc

Exit status: 0 when everything required is present, 1 when something required
is missing, 2 on a usage error.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --install)  DO_INSTALL=true ;;
        -y|--yes)   ASSUME_YES=true ;;
        --extras)   WANT_EXTRAS=true ;;
        --no-color) USE_COLOR=false ;;
        --no-venv)  NO_VENV=true ;;
        --venv)
            shift
            [ $# -gt 0 ] || { echo "--venv needs a path" >&2; exit 2; }
            VENV_OPT="$1"
            ;;
        --venv=*)   VENV_OPT="${1#--venv=}" ;;
        -h|--help)  usage; exit 0 ;;
        *)
            echo "unknown option: $1" >&2
            echo "try: ./configure_environment.sh --help" >&2
            exit 2
            ;;
    esac
    shift
done

[ -n "$VENV_OPT" ] || VENV_OPT="${PM3_VENV:-}"

# --- output ------------------------------------------------------------------

if [ "$USE_COLOR" = "auto" ]; then
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
        USE_COLOR=true
    else
        USE_COLOR=false
    fi
fi

if [ "$USE_COLOR" = "true" ]; then
    C_RST=$'\033[0m'
    C_RED=$'\033[31m'
    C_GRN=$'\033[32m'
    C_YEL=$'\033[33m'
    C_CYA=$'\033[36m'
    C_BLD=$'\033[1m'
else
    C_RST=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYA=""; C_BLD=""
fi

T_OK="[ ${C_GRN}ok${C_RST}   ]"
T_FAIL="[ ${C_RED}fail${C_RST} ]"
T_WARN="[ ${C_YEL}warn${C_RST} ]"
T_SKIP="[ skip ]"
T_INFO="[ ${C_CYA}info${C_RST} ]"

N_OK=0
N_FAIL=0
N_WARN=0

MISSING_REQ=""
MISSING_OPT=""
NEED_ACCESSRIGHTS=false
NEED_UDEV=false
DEV_GROUP=""

section()  { printf '\n%s%s%s\n' "$C_BLD" "$1" "$C_RST"; }
res_ok()   { printf '%s %s\n' "$T_OK"   "$1"; N_OK=$((N_OK + 1)); }
res_warn() { printf '%s %s\n' "$T_WARN" "$1"; N_WARN=$((N_WARN + 1)); }
res_skip() { printf '%s %s\n' "$T_SKIP" "$1"; }
res_info() { printf '%s %s\n' "$T_INFO" "$1"; }
res_hint() { printf '         %s\n' "$1"; }

res_fail() {
    printf '%s %s\n' "$T_FAIL" "$1"
    N_FAIL=$((N_FAIL + 1))
}

# miss_req KEY MESSAGE - required, counts as a failure
miss_req() {
    [ "$1" = "-" ] || MISSING_REQ="$MISSING_REQ $1"
    res_fail "$2"
}

# miss_opt KEY MESSAGE - optional, only disables a feature
miss_opt() {
    [ "$1" = "-" ] || MISSING_OPT="$MISSING_OPT $1"
    res_warn "$2"
}

# miss_note KEY MESSAGE - off by default anyway, just mention the package
miss_note() {
    [ "$1" = "-" ] || MISSING_OPT="$MISSING_OPT $1"
    res_skip "$2"
}

# ask QUESTION - true on yes. Never blocks when there is no terminal.
ask() {
    if [ "$ASSUME_YES" = "true" ]; then
        printf '%s [y/N] y\n' "$1"
        return 0
    fi

    if [ ! -t 0 ]; then
        return 1
    fi

    local reply=""
    printf '%s [y/N] ' "$1"
    read -r reply || return 1

    case "$reply" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

first_line() { "$@" 2>/dev/null | head -n 1; }

# --- platform detection ------------------------------------------------------

OS="$(uname -s)"
DISTRO=""
DISTRO_NAME=""
PKG_MGR=""
IS_WSL=false

case "$OS" in
    Linux)
        if [ -r /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
            IS_WSL=true
        fi

        if [ -r /etc/os-release ]; then
            DISTRO="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")"
            DISTRO_NAME="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$ID}")"
            DISTRO_LIKE="$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")"
        else
            DISTRO_LIKE=""
        fi

        case " $DISTRO $DISTRO_LIKE " in
            *" nixos "*)                      PKG_MGR="nix" ;;
            *" debian "*|*" ubuntu "*)        PKG_MGR="apt" ;;
            *" arch "*|*" archlinux "*)       PKG_MGR="pacman" ;;
            *" fedora "*|*" rhel "*|*" centos "*) PKG_MGR="dnf" ;;
            *" suse "*|*" opensuse "*)        PKG_MGR="zypper" ;;
        esac

        # fall back on whatever is actually installed
        if [ -z "$PKG_MGR" ]; then
            for m in apt-get pacman dnf zypper; do
                if have "$m"; then
                    case "$m" in
                        apt-get) PKG_MGR="apt" ;;
                        *)       PKG_MGR="$m" ;;
                    esac
                    break
                fi
            done
        fi
        ;;
    Darwin)
        DISTRO="macos"
        DISTRO_NAME="macOS $(sw_vers -productVersion 2>/dev/null)"
        if have brew; then
            PKG_MGR="brew"
        elif have port; then
            PKG_MGR="port"
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        DISTRO="windows"
        DISTRO_NAME="$OS (ProxSpace / MSYS)"
        ;;
    *)
        DISTRO_NAME="$OS"
        ;;
esac

[ -n "$DISTRO_NAME" ] || DISTRO_NAME="$OS"
[ "$IS_WSL" = "true" ] && DISTRO_NAME="$DISTRO_NAME (WSL)"

# pkg_for KEY - package name for the detected package manager, empty if none
pkg_for() {
    case "$PKG_MGR" in
    apt)
        case "$1" in
            cc|cxx|make)  echo "build-essential" ;;
            pkgconfig)    echo "pkg-config" ;;
            git)          echo "git ca-certificates" ;;
            cmake)        echo "cmake" ;;
            clang)        echo "clang" ;;
            armgcc)       echo "gcc-arm-none-eabi" ;;
            armlibc)      echo "libnewlib-dev" ;;
            readline)     echo "libreadline-dev" ;;
            bzip2)        echo "libbz2-dev" ;;
            lz4)          echo "liblz4-dev" ;;
            openssl)      echo "libssl-dev" ;;
            zlib)         echo "zlib1g-dev" ;;
            bluez)        echo "libbluetooth-dev" ;;
            pythondev)    echo "libpython3-dev" ;;
            qt)           echo "qt6-base-dev" ;;
            gd)           echo "libgd-dev" ;;
            opencl)       echo "ocl-icd-opencl-dev" ;;
            python3)      echo "python3" ;;
            venv)         echo "python3-venv" ;;
            pip)          echo "python3-pip" ;;
            astyle)       echo "astyle" ;;
            recode)       echo "recode" ;;
        esac ;;
    pacman)
        case "$1" in
            cc|cxx|make)  echo "base-devel" ;;
            pkgconfig)    echo "pkgconf" ;;
            git)          echo "git" ;;
            cmake)        echo "cmake" ;;
            clang)        echo "clang" ;;
            armgcc)       echo "arm-none-eabi-gcc" ;;
            armlibc)      echo "arm-none-eabi-newlib" ;;
            readline)     echo "readline" ;;
            bzip2)        echo "bzip2" ;;
            lz4)          echo "lz4" ;;
            openssl)      echo "openssl" ;;
            zlib)         echo "zlib" ;;
            bluez)        echo "bluez bluez-libs" ;;
            pythondev)    echo "python" ;;
            qt)           echo "qt6-base" ;;
            gd)           echo "gd" ;;
            opencl)       echo "ocl-icd" ;;
            python3)      echo "python" ;;
            pip)          echo "python-pip" ;;
            astyle)       echo "astyle" ;;
            recode)       echo "recode" ;;
        esac ;;
    dnf)
        case "$1" in
            cc)           echo "gcc" ;;
            cxx)          echo "gcc-c++" ;;
            make)         echo "make" ;;
            pkgconfig)    echo "pkgconf-pkg-config" ;;
            git)          echo "git" ;;
            cmake)        echo "cmake" ;;
            clang)        echo "clang" ;;
            armgcc)       echo "arm-none-eabi-gcc-cs" ;;
            armlibc)      echo "arm-none-eabi-newlib" ;;
            readline)     echo "readline-devel" ;;
            bzip2)        echo "bzip2-devel" ;;
            lz4)          echo "lz4-devel" ;;
            openssl)      echo "openssl-devel" ;;
            zlib)         echo "zlib-ng-compat-devel" ;;
            bluez)        echo "bluez-libs-devel" ;;
            pythondev)    echo "python3-devel" ;;
            qt)           echo "qt6-qtbase-devel" ;;
            gd)           echo "gd-devel" ;;
            opencl)       echo "mesa-libOpenCL ocl-icd-devel" ;;
            python3)      echo "python3" ;;
            pip)          echo "python3-pip" ;;
            astyle)       echo "astyle" ;;
            recode)       echo "recode" ;;
        esac ;;
    zypper)
        case "$1" in
            cc|cxx)       echo "gcc-c++" ;;
            make)         echo "patterns-devel-base-devel_basis" ;;
            pkgconfig)    echo "pkg-config" ;;
            git)          echo "git" ;;
            cmake)        echo "cmake" ;;
            clang)        echo "clang" ;;
            armgcc)       echo "cross-arm-none-gcc12" ;;
            armlibc)      echo "cross-arm-none-newlib-devel" ;;
            readline)     echo "readline-devel" ;;
            bzip2)        echo "libbz2-devel" ;;
            lz4)          echo "liblz4-devel" ;;
            openssl)      echo "libopenssl-devel" ;;
            zlib)         echo "zlib-devel" ;;
            bluez)        echo "bluez-devel" ;;
            pythondev)    echo "python3-devel" ;;
            qt)           echo "qt6-core-devel qt6-widgets-devel" ;;
            gd)           echo "gd-devel" ;;
            opencl)       echo "ocl-icd-devel" ;;
            python3)      echo "python3" ;;
            pip)          echo "python3-pip" ;;
            astyle)       echo "astyle" ;;
            recode)       echo "recode" ;;
        esac ;;
    brew)
        case "$1" in
            pkgconfig)    echo "pkgconf" ;;
            git)          echo "git" ;;
            cmake)        echo "cmake" ;;
            armgcc)       echo "RfidResearchGroup/proxmark3/arm-none-eabi-gcc" ;;
            readline)     echo "readline" ;;
            lz4)          echo "lz4" ;;
            openssl)      echo "openssl" ;;
            zlib)         echo "zlib" ;;
            qt)           echo "qt" ;;
            gd)           echo "gd" ;;
            python3)      echo "python3" ;;
            astyle)       echo "astyle" ;;
            recode)       echo "recode" ;;
        esac ;;
    port)
        case "$1" in
            pkgconfig)    echo "pkgconfig" ;;
            git)          echo "git" ;;
            cmake)        echo "cmake" ;;
            armgcc)       echo "arm-none-eabi-gcc arm-none-eabi-binutils" ;;
            readline)     echo "readline" ;;
            bzip2)        echo "bzip2" ;;
            lz4)          echo "lz4" ;;
            openssl)      echo "openssl11" ;;
            zlib)         echo "zlib" ;;
            qt)           echo "qt6 qt6-qtbase" ;;
            gd)           echo "gd2" ;;
            python3)      echo "python312" ;;
            astyle)       echo "astyle" ;;
            recode)       echo "recode" ;;
        esac ;;
    esac
}

pkg_install_cmd() {
    case "$PKG_MGR" in
        apt)    echo "sudo apt-get install --no-install-recommends $*" ;;
        pacman) echo "sudo pacman -Syu --needed $*" ;;
        dnf)    echo "sudo dnf install $*" ;;
        zypper) echo "sudo zypper install $*" ;;
        brew)   echo "brew install $*" ;;
        port)   echo "sudo port install $*" ;;
        nix)    echo "nix-shell tools/shell.nix" ;;
        *)      echo "" ;;
    esac
}

# resolve keys to package names, dropping the ones this platform has no name for
pkgs_for_keys() {
    local key out=""
    for key in $(echo "$*" | tr ' ' '\n' | sort -u); do
        [ -n "$key" ] || continue
        local p
        p="$(pkg_for "$key")"
        [ -n "$p" ] && out="$out $p"
    done
    echo "$out" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/^ *//; s/ *$//'
}

# --- library probes ----------------------------------------------------------

PROBE_DIR=""
cleanup() { [ -n "$PROBE_DIR" ] && rm -rf "$PROBE_DIR"; }
trap cleanup EXIT HUP INT TERM

CC="${CC:-gcc}"
have "$CC" || CC="cc"
have "$CC" || CC="clang"

# cc_probe HEADER [LDFLAGS...] - can we compile and link against it?
cc_probe() {
    have "$CC" || return 2

    if [ -z "$PROBE_DIR" ]; then
        PROBE_DIR="$(mktemp -d 2>/dev/null)" || return 2
    fi

    local hdr="$1"
    shift
    printf '#include <%s>\nint main(void) { return 0; }\n' "$hdr" > "$PROBE_DIR/probe.c"
    "$CC" "$PROBE_DIR/probe.c" -o "$PROBE_DIR/probe.out" "$@" >/dev/null 2>&1
}

pc_exists() { have pkg-config && pkg-config --exists "$@" 2>/dev/null; }
pc_ver()    { pkg-config --modversion "$1" 2>/dev/null | head -n 1; }

# check_cmd KEY COMMAND LABEL REQUIRED
check_cmd() {
    local key="$1" cmd="$2" label="$3" required="$4"

    if have "$cmd"; then
        local v
        v="$(first_line "$cmd" --version | sed 's/^[^0-9]*\([0-9][0-9.]*\).*/\1/')"
        if [ -n "$v" ]; then
            res_ok "$label - $cmd $v"
        else
            res_ok "$label - $cmd"
        fi
        return 0
    fi

    case "$required" in
        req)  miss_req  "$key" "$label - '$cmd' not found" ;;
        note) miss_note "$key" "$label - '$cmd' not found" ;;
        *)    miss_opt  "$key" "$label - '$cmd' not found" ;;
    esac
    return 1
}

# check_lib KEY LABEL REQUIRED PCNAME HEADER [LDFLAGS...]
check_lib() {
    local key="$1" label="$2" required="$3" pcname="$4" hdr="$5"
    shift 5

    if [ -n "$pcname" ] && pc_exists "$pcname"; then
        res_ok "$label - $(pc_ver "$pcname")"
        return 0
    fi

    if [ -n "$hdr" ] && cc_probe "$hdr" "$@"; then
        res_ok "$label"
        return 0
    fi

    local why="not found"
    if [ -n "$hdr" ] && ! have "$CC"; then
        why="not found (no C compiler to probe with)"
    fi

    case "$required" in
        req)  miss_req  "$key" "$label - $why" ;;
        note) miss_note "$key" "$label - $why" ;;
        *)    miss_opt  "$key" "$label - $why" ;;
    esac
    return 1
}

#-----------------------------------------------------------------------------
printf '%s\n' "${C_BLD}Proxmark3 environment check${C_RST}"
printf '%s\n' "  repo     : $PM3PATH"
printf '%s\n' "  system   : $DISTRO_NAME"
printf '%s\n' "  packages : ${PKG_MGR:-unknown package manager}"

# --- 1. repo sanity ----------------------------------------------------------

section "Repository"

if [ -f "$PM3PATH/Makefile" ] && [ -d "$PM3PATH/armsrc" ] && [ -d "$PM3PATH/client" ]; then
    res_ok "repo layout looks right"
else
    res_fail "this does not look like a proxmark3 checkout"
    res_hint "run the script from the root of the clone"
fi

if have git && git -C "$PM3PATH" rev-parse --git-dir >/dev/null 2>&1; then
    res_ok "git clone - $(git -C "$PM3PATH" rev-parse --short HEAD 2>/dev/null)"
else
    res_warn "not a git clone - the client will report an unknown version"
    res_hint "builds work, but 'hw version' cannot show the commit"
fi

# the ARM build has no mkdir for its object dirs, they live in git via .dummy
DUMMY_MISSING=""
for d in armsrc/obj/.dummy armsrc/obj/Standalone/.dummy bootrom/obj/.dummy; do
    [ -f "$PM3PATH/$d" ] || DUMMY_MISSING="$DUMMY_MISSING $d"
done

if [ -z "$DUMMY_MISSING" ]; then
    res_ok "firmware object directories present"
else
    res_fail "missing tracked placeholder(s):$DUMMY_MISSING"
    res_hint "the ARM build cannot create these directories, restore them with:"
    res_hint "  git checkout --$DUMMY_MISSING"
fi


# --- 2. which device --------------------------------------------------------

section "Device / platform"

PLATFORM_KNOWN="PM3RDV4 PM3GENERIC PM3ICOPYX PM3ULTIMATE PM5"
EXTRAS_KNOWN="SMARTCARD FLASH BTADDON FPC_USART_DEV BWM NO_LOWBATT_SHUTDOWN NO_LOWBATT_BEEP"

# mk_var FILE NAME - value of an uncommented NAME= assignment, last one wins
mk_var() {
    [ -f "$1" ] || return 0
    sed -n "s/^[[:space:]]*$2[[:space:]]*[:+?]*=[[:space:]]*//p" "$1" \
        | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//' \
        | tail -n 1
}

in_list() {
    local needle="$1" item
    for item in $2; do
        [ "$item" = "$needle" ] && return 0
    done
    return 1
}

platform_cheatsheet() {
    res_hint "PM3RDV4      Proxmark3 RDV4                                 (the default)"
    res_hint "PM3GENERIC   Proxmark3 RDV1, RDV2, Easy, rysccorps, clones"
    res_hint "PM3ICOPYX    iCopy-X and Proxmark3 Max, with PLATFORM_EXTRAS=FLASH"
    res_hint "PM3ULTIMATE  Proxmark3 Ultimate (XC2S50)"
    res_hint "PM5          Proxmark5 Iceman Edition (Artery AT32F435/437)"
    res_hint "full table, including the standalone modes: make PLATFORM="
}

PLATFORM_FILE="$PM3PATH/Makefile.platform"
PLATFORM_SRC=""
PLATFORM_VAL=""
EXTRAS_VAL=""
STANDALONE_VAL=""
LED_ORDER_VAL=""
SKIP_CEP_VAL=""

if [ -f "$PLATFORM_FILE" ]; then
    # a plain PLATFORM= in the file beats the environment, same as make sees it
    PLATFORM_VAL="$(mk_var "$PLATFORM_FILE" PLATFORM)"
    EXTRAS_VAL="$(mk_var "$PLATFORM_FILE" PLATFORM_EXTRAS)"
    STANDALONE_VAL="$(mk_var "$PLATFORM_FILE" STANDALONE)"
    LED_ORDER_VAL="$(mk_var "$PLATFORM_FILE" LED_ORDER)"
    SKIP_CEP_VAL="$(mk_var "$PLATFORM_FILE" SKIP_CEP)"
    PLATFORM_SRC="Makefile.platform"
fi

if [ -z "$PLATFORM_VAL" ] && [ -n "${PLATFORM:-}" ]; then
    PLATFORM_VAL="$PLATFORM"
    EXTRAS_VAL="${PLATFORM_EXTRAS:-}"
    PLATFORM_SRC="environment"
fi

if [ -z "$PLATFORM_VAL" ]; then
    PLATFORM_VAL="PM3RDV4"
    PLATFORM_SRC="default"
fi

if in_list "$PLATFORM_VAL" "$PLATFORM_KNOWN"; then
    # with no file at all the warning further down says it better
    if [ "$PLATFORM_SRC" != "default" ]; then
        res_ok "PLATFORM=$PLATFORM_VAL (from $PLATFORM_SRC)"
    fi
elif [ "$PLATFORM_VAL" = "PM3OTHER" ]; then
    res_warn "PLATFORM=PM3OTHER is deprecated, use PM3GENERIC instead"
else
    res_fail "PLATFORM=$PLATFORM_VAL is not a known platform, the firmware build will stop"
    platform_cheatsheet
fi

if [ -n "$EXTRAS_VAL" ]; then
    EXTRAS_BAD=""
    for tok in $EXTRAS_VAL; do
        if ! in_list "$tok" "$EXTRAS_KNOWN"; then
            res_fail "PLATFORM_EXTRAS token '$tok' is not recognised"
            EXTRAS_BAD="yes"
            continue
        fi

        case "$tok" in
            BWM|NO_LOWBATT_SHUTDOWN|NO_LOWBATT_BEEP)
                if [ "$PLATFORM_VAL" != "PM5" ]; then
                    res_fail "PLATFORM_EXTRAS=$tok is PM5 only, but PLATFORM=$PLATFORM_VAL"
                    EXTRAS_BAD="yes"
                fi
                ;;
            BTADDON|FPC_USART_DEV)
                if [ "$PLATFORM_VAL" = "PM5" ]; then
                    res_fail "PLATFORM_EXTRAS=$tok is not available on PM5"
                    EXTRAS_BAD="yes"
                fi
                ;;
        esac
    done

    [ -z "$EXTRAS_BAD" ] && res_ok "PLATFORM_EXTRAS=$EXTRAS_VAL"
fi

if [ -n "$STANDALONE_VAL" ]; then
    res_info "STANDALONE=$STANDALONE_VAL"
    res_hint "'make PLATFORM=' lists which modes each platform supports"
fi

if [ -n "$LED_ORDER_VAL" ] && [ "$PLATFORM_VAL" != "PM3GENERIC" ]; then
    res_warn "LED_ORDER=$LED_ORDER_VAL only applies to PLATFORM=PM3GENERIC, it is ignored here"
fi

if [ "$SKIP_CEP_VAL" = "1" ] && [ "$PLATFORM_VAL" != "PM5" ]; then
    res_fail "SKIP_CEP=1 is PM5 only, but PLATFORM=$PLATFORM_VAL"
fi

if [ "$PLATFORM_VAL" = "PM5" ]; then
    res_info "PM5 notes: doc/md/PM5_Start_Here/Getting_Started_With_PM5.md"
fi

# no Makefile.platform at all - offer to write one, the firmware is device specific
if [ ! -f "$PLATFORM_FILE" ]; then
    if [ "$PLATFORM_SRC" = "environment" ]; then
        res_warn "no Makefile.platform, PLATFORM=$PLATFORM_VAL comes from the environment"
        res_hint "it has to be set for every make, put it in Makefile.platform instead"
    else
        res_warn "no Makefile.platform, every build will be for PLATFORM=PM3RDV4"
        res_hint "flashing an RDV4 image to another board gives a non-working device"
    fi

    platform_cheatsheet

    if [ -t 0 ] && [ "$ASSUME_YES" != "true" ]; then
        printf '\n         Which device do you have?\n'
        printf '           1) Proxmark3 RDV4\n'
        printf '           2) Proxmark3 RDV4 with the Blue Shark BT add-on\n'
        printf '           3) Proxmark3 RDV1 / RDV2 / Easy / generic clone\n'
        printf '           4) Proxmark5 Iceman Edition\n'
        printf '           5) Proxmark5 with the Battery Wireless Mod\n'
        printf '           6) iCopy-X or Proxmark3 Max\n'
        printf '           7) Proxmark3 Ultimate\n'
        printf '           0) skip, I will write Makefile.platform myself\n'
        printf '         choice [0]: '

        PLT_CHOICE=""
        read -r PLT_CHOICE || PLT_CHOICE=""

        NEW_PLT=""
        NEW_EXTRAS=""
        case "$PLT_CHOICE" in
            1) NEW_PLT="PM3RDV4" ;;
            2) NEW_PLT="PM3RDV4";    NEW_EXTRAS="BTADDON" ;;
            3) NEW_PLT="PM3GENERIC" ;;
            4) NEW_PLT="PM5" ;;
            5) NEW_PLT="PM5";        NEW_EXTRAS="BWM" ;;
            6) NEW_PLT="PM3ICOPYX";  NEW_EXTRAS="FLASH" ;;
            7) NEW_PLT="PM3ULTIMATE" ;;
            *) res_hint "skipped, see Makefile.platform.sample for every option" ;;
        esac

        if [ -n "$NEW_PLT" ]; then
            {
                echo "# Written by configure_environment.sh. See Makefile.platform.sample"
                echo "# for every available option, or run 'make PLATFORM=' for the full list."
                echo "PLATFORM=$NEW_PLT"
                [ -n "$NEW_EXTRAS" ] && echo "PLATFORM_EXTRAS=$NEW_EXTRAS"
            } > "$PLATFORM_FILE"

            PLATFORM_VAL="$NEW_PLT"
            EXTRAS_VAL="$NEW_EXTRAS"
            res_ok "wrote Makefile.platform - PLATFORM=$NEW_PLT${NEW_EXTRAS:+ PLATFORM_EXTRAS=$NEW_EXTRAS}"
        fi
    fi
fi

# a changed platform needs the object files rebuilt, make handles it via this cache
if [ -f "$PM3PATH/.Makefile.options.cache" ]; then
    CACHED_PLT="$(mk_var "$PM3PATH/.Makefile.options.cache" CACHED_PLATFORM)"
    if [ -n "$CACHED_PLT" ] && [ "$CACHED_PLT" != "$PLATFORM_VAL" ]; then
        res_info "last build was for $CACHED_PLT, make will rebuild what the change affects"
    fi
fi

# --- 3. host toolchain -------------------------------------------------------

section "Host toolchain"

if have make; then
    if first_line make --version | grep -q GNU; then
        res_ok "make - $(first_line make --version)"
    else
        miss_req "make" "make is not GNU make - $(first_line make --version)"
        res_hint "the build needs GNU make, try gmake or install it"
    fi
else
    miss_req "make" "make - not found"
fi

check_cmd cc  gcc        "host C compiler"   req
check_cmd cxx g++        "host C++ compiler" req
check_cmd pkgconfig pkg-config "pkg-config"  req
check_cmd git git        "git"               req

if have gcc; then
    GCC_MAJOR="$(gcc -dumpfullversion -dumpversion 2>/dev/null | cut -d. -f1)"
    case "$GCC_MAJOR" in
        ''|*[!0-9]*) : ;;
        *)
            if [ "$GCC_MAJOR" -lt 8 ]; then
                res_warn "gcc $GCC_MAJOR is older than 8 - Qt6 will not build"
                res_hint "build with 'make SKIPQT6=1', or install a newer gcc"
            fi
            ;;
    esac
fi

check_cmd clang clang "second compiler (optional, for extra warnings)" note
check_cmd cmake cmake "cmake (optional, alternative client build)"     note

# --- 4. ARM toolchain --------------------------------------------------------

section "ARM firmware toolchain"

CROSS="${CROSS:-arm-none-eabi-}"

if have "${CROSS}gcc"; then
    res_ok "${CROSS}gcc - $(first_line "${CROSS}gcc" -dumpversion)"

    ARM_LIBC="$("${CROSS}gcc" -print-file-name=libc.a 2>/dev/null)"
    if [ -n "$ARM_LIBC" ] && [ "$ARM_LIBC" != "libc.a" ] && [ -f "$ARM_LIBC" ]; then
        res_ok "ARM C library - $ARM_LIBC"
    else
        miss_req "armlibc" "ARM C library not found - ${CROSS}gcc cannot link"
        res_hint "install newlib, or picolibc where newlib conflicts with the compiler"
    fi
else
    miss_req "armgcc" "${CROSS}gcc - not found, firmware cannot be built"
    res_hint "the host client alone still builds with 'make client'"
fi

for t in objcopy objdump; do
    if have "${CROSS}${t}"; then
        res_ok "${CROSS}${t}"
    else
        miss_req "armgcc" "${CROSS}${t} - not found"
    fi
done

# --- 5. client libraries -----------------------------------------------------

section "Client libraries (required)"

check_lib readline "readline"        req ""      readline/readline.h -lreadline
check_lib bzip2    "bzip2 (libbz2)"  req bzip2   bzlib.h             -lbz2
check_lib lz4      "lz4"             req liblz4  lz4.h               -llz4
check_lib openssl  "openssl (libcrypto, for mfd_aes_brute/mfulc_des_brute)" \
                                     req libcrypto openssl/evp.h     -lcrypto

section "Client libraries (optional, each one enables a feature)"

check_lib zlib  "zlib - compressed Google Smart Tap payloads" opt zlib zlib.h -lz
check_lib bluez "bluez - native Bluetooth support"            opt bluez "" || \
    res_hint "not available on every distro, the BT add-on also works over a serial port"

if pc_exists python3-embed; then
    res_ok "libpython3 - $(pc_ver python3-embed) (embedded Python scripting)"
elif pc_exists python3; then
    res_ok "libpython3 - $(pc_ver python3) (embedded Python scripting)"
else
    miss_opt pythondev "libpython3 - not found, Python scripts disabled in the client"
fi

if pc_exists Qt6Core Qt6Widgets Qt6Gui; then
    res_ok "Qt6 - $(pc_ver Qt6Core) (graphs, 'hw tune' plot)"
elif have qmake6; then
    res_ok "Qt6 - via qmake6 (graphs, 'hw tune' plot)"
elif pc_exists Qt5Core Qt5Widgets; then
    res_ok "Qt5 - $(pc_ver Qt5Core) (graphs, build with SKIPQT6=1)"
else
    miss_opt qt "Qt - not found, the graphical window is disabled"
fi

check_lib gd "libgd - NFC ePaper devices" opt gdlib gd.h -lgd
check_lib opencl "OpenCL - only for the optional crack5opencl tool" note OpenCL ""

section "Client libraries (bundled fallback, system copy only speeds up the build)"

for pair in "jansson:jansson" "whereami:whereami" "lua:lua5.4"; do
    nm="${pair%%:*}"
    pc="${pair##*:}"
    if pc_exists "$pc" || { [ "$nm" = "lua" ] && pc_exists lua-5.4; }; then
        res_ok "$nm - system copy found"
    elif [ "$nm" = "whereami" ] && [ -f /usr/include/whereami.h ]; then
        res_ok "whereami - system copy found"
    else
        res_skip "$nm - not installed, the bundled copy in client/deps will be used"
    fi
done

# --- 6. python environment ---------------------------------------------------

section "Python"

PYTHON3="${PYTHON3:-python3}"
VENV_DIR=""
VENV_PY=""
VENV_ORIGIN=""

venv_python() {
    if [ -x "$1/bin/python3" ]; then
        echo "$1/bin/python3"
    elif [ -x "$1/bin/python" ]; then
        echo "$1/bin/python"
    elif [ -x "$1/Scripts/python.exe" ]; then
        echo "$1/Scripts/python.exe"
    fi
}

if have "$PYTHON3"; then
    res_ok "python3 - $(first_line "$PYTHON3" --version)"

    if "$PYTHON3" -c 'import venv' >/dev/null 2>&1; then
        res_ok "venv module available"
    else
        miss_opt venv "python3 'venv' module missing - cannot create a virtualenv"
    fi

    if "$PYTHON3" -m pip --version >/dev/null 2>&1; then
        res_ok "pip available"
    else
        miss_opt pip "pip not available for $PYTHON3"
    fi
else
    miss_opt python3 "python3 - not found"
    res_hint "only the Python-based tools and client scripting need it"
fi

if [ "$NO_VENV" = "true" ]; then
    res_skip "venv search disabled (--no-venv), checking the python3 on PATH"
    VENV_PY="$(have "$PYTHON3" && command -v "$PYTHON3")"
    VENV_ORIGIN="system"
else
    for cand_pair in \
        "${VENV_OPT}:asked for" \
        "${VIRTUAL_ENV:-}:currently active" \
        "$PM3PATH/venv:in the repo" \
        "$HOME/.venv/proxmark3:in \$HOME/.venv"
    do
        cand="${cand_pair%%:*}"
        why="${cand_pair#*:}"
        [ -n "$cand" ] || continue

        if [ -f "$cand/pyvenv.cfg" ]; then
            VENV_DIR="$cand"
            VENV_ORIGIN="$why"
            break
        fi

        if [ "$why" = "asked for" ]; then
            res_fail "no venv at $cand"
            res_hint "create it with: $PYTHON3 -m venv \"$cand\""
            break
        fi
    done
fi

if [ -n "$VENV_DIR" ]; then
    VENV_PY="$(venv_python "$VENV_DIR")"
    if [ -n "$VENV_PY" ]; then
        res_ok "venv $VENV_ORIGIN - $VENV_DIR ($("$VENV_PY" --version 2>&1))"
    else
        res_fail "venv at $VENV_DIR has no usable interpreter"
        res_hint "delete it and let this script create a new one"
        VENV_DIR=""
    fi
fi

CREATE_VENV_AT=""
if [ "$NO_VENV" != "true" ] && [ -z "$VENV_DIR" ] && [ -z "$VENV_OPT" ]; then
    res_warn "no Python venv found"
    res_hint "the Python tools and 'make check' want the packages in tools/requirements.txt,"
    res_hint "and most distros refuse a system-wide pip install (PEP 668)"

    if have "$PYTHON3" && "$PYTHON3" -c 'import venv' >/dev/null 2>&1; then
        if ask "         Create one in the repo folder, at $PM3PATH/venv?"; then
            CREATE_VENV_AT="$PM3PATH/venv"
        else
            res_hint "skipped. Create one later with: $PYTHON3 -m venv venv"
            res_hint "or point this script at an existing one: --venv /path/to/venv"
        fi
    fi
fi

if [ -n "$CREATE_VENV_AT" ]; then
    printf '         creating venv at %s ...\n' "$CREATE_VENV_AT"
    if "$PYTHON3" -m venv "$CREATE_VENV_AT"; then
        VENV_DIR="$CREATE_VENV_AT"
        VENV_ORIGIN="just created"
        VENV_PY="$(venv_python "$VENV_DIR")"
        res_ok "venv created - $VENV_DIR"
        res_hint "activate it with: source ${VENV_DIR#"$PM3PATH"/}/bin/activate"
    else
        res_fail "could not create a venv at $CREATE_VENV_AT"
    fi
fi

# requirements
REQ_FILES="tools/requirements.txt"
REQ_EXTRA="fpga/requirements.txt tools/ePassport/requirements.txt tools/btaddon/requirements.txt"

check_requirements() {
    local py="$1" reqfile="$2" required="$3" out line

    if [ ! -f "$PM3PATH/$reqfile" ]; then
        return 0
    fi

    if [ -z "$py" ]; then
        res_skip "$reqfile - no interpreter to check against"
        return 0
    fi

    out="$("$py" -I - "$PM3PATH/$reqfile" <<'PYEOF'
import re
import sys

try:
    from importlib.metadata import PackageNotFoundError, version
except ImportError:
    print("SKIP metadata api unavailable")
    sys.exit(0)


def as_tuple(s):
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[._-]+", s))


def aligned(a, b):
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


SPEC = re.compile(r"^([A-Za-z0-9._-]+)\s*(==|>=|<=|~=|>|<)?\s*([0-9][^\s,]*)?")

for path in sys.argv[1:]:
    with open(path) as fd:
        for raw in fd:
            text = raw.split("#", 1)[0].split(";", 1)[0].strip()
            if not text:
                continue

            m = SPEC.match(text)
            if m is None:
                print("SKIP", text)
                continue

            name, op, want = m.group(1), m.group(2), m.group(3)
            try:
                got = version(name)
            except PackageNotFoundError:
                print("MISSING", name, (op or "") + (want or ""))
                continue
            except Exception:
                print("SKIP", name)
                continue

            have, need = aligned(as_tuple(got), as_tuple(want))
            if op == "==" and have != need:
                print("OTHER", name, got, op + want)
            elif op in (">=", "~=") and have < need:
                print("OLD", name, got, op + want)
            else:
                print("OK", name, got)
PYEOF
)"

    local n_missing=0 n_other=0 n_ok=0 names=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in
            OK*)      n_ok=$((n_ok + 1)) ;;
            MISSING*) n_missing=$((n_missing + 1)); names="$names $(echo "$line" | cut -d' ' -f2)" ;;
            OLD*|OTHER*) n_other=$((n_other + 1)); names="$names $(echo "$line" | cut -d' ' -f2)" ;;
            SKIP*)    ;;
        esac
    done <<EOT
$out
EOT

    if [ "$n_missing" -eq 0 ] && [ "$n_other" -eq 0 ]; then
        res_ok "$reqfile - all $n_ok package(s) installed"
        return 0
    fi

    local msg="$reqfile - $n_missing missing, $n_other at another version:$names"
    if [ "$required" = "req" ]; then
        res_warn "$msg"
    else
        res_skip "$msg"
    fi

    res_hint "install with: ${py#"$PM3PATH"/} -m pip install -r $reqfile"
    return 1
}

PIP_TODO=""
if check_requirements "$VENV_PY" "$REQ_FILES" req; then
    :
else
    PIP_TODO="$REQ_FILES"
fi

if [ "$WANT_EXTRAS" = "true" ]; then
    for f in $REQ_EXTRA; do
        check_requirements "$VENV_PY" "$f" opt || PIP_TODO="$PIP_TODO $f"
    done
else
    res_info "optional requirement files not checked - rerun with --extras"
    res_hint "$REQ_EXTRA"
fi

if have uv; then
    res_ok "uv - $(first_line uv --version) (tools/pm3_tests.sh uses it when present)"
else
    res_skip "uv not installed - tools/pm3_tests.sh falls back to python3"
fi

# --- 7. device access --------------------------------------------------------

section "Device access"

if [ "$OS" = "Linux" ]; then
    if [ -f /etc/arch-release ]; then
        DEV_GROUP="uucp"
    else
        DEV_GROUP="dialout"
    fi

    if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx "$DEV_GROUP"; then
        res_ok "user is in the '$DEV_GROUP' group"
    else
        res_warn "user is not in the '$DEV_GROUP' group - /dev/ttyACM0 will be denied"
        res_hint "fix with: make accessrights   (then log out and back in)"
        NEED_ACCESSRIGHTS=true
    fi

    if [ -f /etc/udev/rules.d/77-pm3-usb-device-blacklist.rules ] || \
       [ -f /lib/udev/rules.d/77-pm3-usb-device-blacklist.rules ]; then
        res_ok "udev rule 77-pm3-usb-device-blacklist.rules installed"
    else
        res_warn "udev rule not installed"
        res_hint "fix with: make udev"
        NEED_UDEV=true
    fi

    if have systemctl && systemctl is-active --quiet ModemManager 2>/dev/null; then
        res_warn "ModemManager is running - it can brick the Proxmark3 while flashing"
        res_hint "read doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md"
        res_hint "the udev rule above only helps when ModemManager is not in strict mode"
    else
        res_ok "ModemManager not running"
    fi

    PM3_PORT=""
    for p in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyS* ; do
        [ -c "$p" ] || continue
        case "$p" in /dev/ttyACM*) PM3_PORT="$p"; break ;; esac
    done

    if [ -n "$PM3_PORT" ]; then
        if [ -r "$PM3_PORT" ] && [ -w "$PM3_PORT" ]; then
            res_ok "$PM3_PORT present and read/writable"
        else
            res_warn "$PM3_PORT present but not read/writable by this user"
        fi
    else
        res_info "no /dev/ttyACM* found - plug the Proxmark3 in and rerun to check access"
    fi

    if [ "$IS_WSL" = "true" ]; then
        res_info "WSL - USB devices need usbipd-win on the Windows side"
        res_hint "doc/md/Installation_Instructions/Windows-WSL2-Installation-Instructions.md"
    fi
else
    res_skip "device access checks are Linux only"
fi

# --- 8. developer extras -----------------------------------------------------

section "Developer extras (only needed to submit changes)"

check_cmd astyle astyle "astyle - 'make style' source formatting" note
check_cmd recode recode "recode - 'make miscchecks' encoding checks" note

# --- install -----------------------------------------------------------------

INSTALL_KEYS="$MISSING_REQ $MISSING_OPT"
INSTALL_PKGS=""
# nix and unrecognised systems resolve to no package names at all, so the keys,
# not the names, decide whether there is anything to report
ANY_MISSING="$(echo "$INSTALL_KEYS" | tr -d ' ')"
[ -n "$ANY_MISSING" ] && INSTALL_PKGS="$(pkgs_for_keys "$INSTALL_KEYS")"

if [ -n "$ANY_MISSING" ]; then
    if [ -n "$(echo "$MISSING_REQ" | tr -d ' ')" ]; then
        section "Packages to install"
    else
        section "Optional packages, nothing here blocks the build"
    fi

    if [ "$PKG_MGR" = "nix" ]; then
        printf '  %s\n' "nix-shell tools/shell.nix"
        printf '  %s\n' "brings in everything needed to build the client and the firmware"
    elif [ -z "$INSTALL_PKGS" ]; then
        printf '  %s\n' "no package names known for this system"
        printf '  %s\n' "install the items marked fail or warn above, see doc/md/Installation_Instructions/"
    else
        printf '  %s\n' "$(pkg_install_cmd "$INSTALL_PKGS")"
    fi

    if [ "$DO_INSTALL" = "true" ] && [ -n "$INSTALL_PKGS" ] && [ "$PKG_MGR" != "nix" ]; then
        echo
        if ask "Run that now?"; then
            case "$PKG_MGR" in
                apt)    sudo apt-get install --no-install-recommends $INSTALL_PKGS ;;
                pacman) sudo pacman -Syu --needed $INSTALL_PKGS ;;
                dnf)    sudo dnf install $INSTALL_PKGS ;;
                zypper) sudo zypper install $INSTALL_PKGS ;;
                brew)   brew install $INSTALL_PKGS ;;
                port)   sudo port install $INSTALL_PKGS ;;
            esac
            res_info "rerun ./configure_environment.sh to confirm"
        fi
    fi
fi

if [ -n "$(echo "$PIP_TODO" | tr -d ' ')" ] && [ -n "$VENV_PY" ]; then
    if [ "$DO_INSTALL" = "true" ] || [ "$VENV_ORIGIN" = "just created" ]; then
        section "Python requirements"
        for f in $PIP_TODO; do
            printf '  %s\n' "$VENV_PY -m pip install -r $f"
        done

        if ask "Install them into $VENV_DIR?"; then
            for f in $PIP_TODO; do
                "$VENV_PY" -m pip install -r "$PM3PATH/$f" || res_warn "pip failed for $f"
            done
            res_info "rerun ./configure_environment.sh to confirm"
        fi
    fi
fi

# --- summary -----------------------------------------------------------------

section "Summary"

printf '  passed   : %s\n' "$N_OK"
printf '  warnings : %s%s\n' "$N_WARN" "$([ "$N_WARN" -gt 0 ] && echo '  (optional features will be disabled)')"
printf '  failures : %s%s\n' "$N_FAIL" "$([ "$N_FAIL" -gt 0 ] && echo '  (the build will not complete)')"
echo

if [ "$N_FAIL" -gt 0 ]; then
    printf '%s\n' "${C_RED}Something required is missing.${C_RST} Install the packages listed above and rerun."
    exit 1
fi

printf '%s\n' "${C_GRN}Ready to build.${C_RST}"
printf '%s\n' "  make clean && make -j        build client and firmware"
printf '%s\n' "  make check                   run the offline tests"
if [ "$NEED_ACCESSRIGHTS" = "true" ]; then
    printf '%s\n' "  make accessrights            add yourself to the '$DEV_GROUP' group"
fi

if [ "$NEED_UDEV" = "true" ]; then
    printf '%s\n' "  make udev                    keep ModemManager off the device"
fi
printf '%s\n' "  ./pm3                        start the client"
echo
printf '%s\n' "More detail in doc/md/Use_of_Proxmark/0_Compilation-Instructions.md"

exit 0
