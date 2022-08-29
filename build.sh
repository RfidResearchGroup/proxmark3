#!/usr/bin/env bash
cd "$(dirname "$0")" || exit $?

BREW_TAP="RfidResearchGroup/proxmark3"

DISTRO="unknown"
DEPENDENCIES=()

function info {
    echo -e "\x1b[0m[\x1b[33m=\x1b[0m] ${*:1}\x1b[0m"
}

function warn {
    echo -e "\x1b[0m[\x1b[36m!\x1b[0m] ${*:1}\x1b[0m"
}

function error {
    echo -e "\x1b[0m[\x1b[31m-\x1b[0m] \x1b[31m${*:1}\x1b[0m"
}

function ask {
    echo -e "\x1b[0m[\x1b[34m?\x1b[0m] ${*:1}\x1b[0m"
}

function askn {
    echo -en "\x1b[0m[\x1b[34m?\x1b[0m] ${*:1}\x1b[0m"
}

function pkgmgr_brew() {
    MACOS_PKGMGR="brew"
    DEPENDENCIES=(readline qt5 pkgconfig coreutils RfidResearchGroup/proxmark3/arm-none-eabi-gcc)
}

function pkgmgr_port() {
    MACOS_PKGMGR="port"
    DEPENDENCIES=(readline qt5 qt5-qtbase pkgconfig arm-none-eabi-gcc arm-none-eabi-binutils lua52 coreutils openssl@3)
}

function os {
    if [[ "$(uname -s)" == "Linux" ]]; then
        # This is how neofetch finds distro
        # hacky but it works
        source /etc/os-release
        case "${ID}" in
            "arch")
                DISTRO="arch"
                DEPENDENCIES=(git base-devel readline bzip2 arm-none-eabi-gcc arm-none-eabi-newlib qt5-base bluez python)
                ;;
            "ubuntu"|"debian")
                DISTRO="debian"
                DEPENDENCIES=(git ca-certificates build-essential pkg-config libreadline-dev gcc-m-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev libpython3-dev libssl-dev)
                ;;
            "fedora")
                DISTRO="fedora"
                DEPENDENCIES=(git make gcc gcc-c++ arm-none-eabi-gcc-cs arm-none-eabi-newlib readline-devel bzip2-devel qt5-qtbase-devel bluez-libs-devel python3-devel libatomic openssl-devel)
                ;;
            "opensuse")
                DISTRO="suse"
                DEPENDENCIES=(git patterns-devel-base-devel_basis gcc-c++ readline-devel libbz2-devel cross-arm-none-gcc9 cross-arm-none-newlib-devel python3-devel libqt5-qtbase-devel libopenssl-devel)
                ;;
        esac
        info "Building for ${NAME}"
        unset TMP_DISTRO
    else
        DISTRO="macos"
        echo
        if [[ -x $(command -v brew) ]] && [[ -x $(command -v port) ]]; then
            warn "Both Homebrew and MacPorts are installed."
            ask "Would you prefer to use"
            ask "  1: Homebrew (brew)"
            ask "  2: MacPorts (port)"
            askn "Enter a selection: "
            read -r PKG_MGR_RESPONSE
            case "${PKG_MGR_RESPONSE,,}" in 
                "port"|"2")
                    pkgmgr_port
                    ;;
                "y"|"brew"|"1"|*)
                    pkgmgr_brew
                    ;;
            esac
            echo
        elif [[ -x $(command -v port) ]]; then
            pkgmgr_port;
        elif [[ -x $(command -v brew) ]]; then
            pkgmgr_brew;
        else
            error "No supported package manager installed."
            info "Please install a supported package manager (only one is needed):"
            info "  Homebrew: https://brew.sh/"
            info "  MacPorts: https://www.macports.org/install.php"
            exit 1
        fi
        info "Building for macOS"
        info "Using ${MACOS_PKGMGR}"
    fi
}

function ensureInstalled {
    case "${DISTRO}" in
        "arch") 
            # --no-confirm is dangerous on macos
            sudo pacman -Sy "$@" --needed
            ;;
        "debian") 
            sudo apt-get update
            sudo apt-get install --no-install-recommends -y "$@"
            ;;
        "fedora") 
            sudo dnf install -y "$@"
            ;;
        "suse") 
            sudo zypper install "$@"
            ;;
        "macos")
            case "${MACOS_PKGMGR}" in 
                "brew")
                    brew install "$@"
                    ;;
                "port")
                    sudo port install "$@"
                    ;;
            esac
            ;;
        esac
}

function installDeps {
    info "This script will install the following packages:"
    info "  ${DEPENDENCIES[*]}"
    askn "Are you okay with this [Y/n]: "
    read -r INSTALL_DEPS_RESPONSE
    if [[ ${INSTALL_DEPS_RESPONSE,,} == "n" ]]; then
        exit 0
    fi
    echo
    if [[ "${MACOS_PKGMGR}" == "brew" ]]; then
        info "Tapping ${BREW_TAP}"
        brew tap "${BREW_TAP}"
    fi
    ensureInstalled "${DEPENDENCIES[@]}"
}

echo
info "PM3 build script"
os

echo
installDeps

cloneRepo