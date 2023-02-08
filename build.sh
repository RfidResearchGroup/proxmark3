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
    DEPENDENCIES=(readline qt5 qt5-qtbase pkgconfig arm-none-eabi-gcc arm-none-eabi-binutils lua52 coreutils openssl@3 python39 cython39)
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
            case "$(tr '[:upper:]' '[:lower:]' <<< "${PKG_MGR_RESPONSE}")" in 
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

function askInstall {
    echo
    info "The following dependencies are required to be installed:"
    info "  ${DEPENDENCIES[*]}"
    if [[ "${MACOS_PKGMGR}" == "brew" ]]; then
        info "The following tap needs to be added to brew:"
        info "  ${BREW_TAP}"
    fi
    # TODO: better communicate to the user that saying no will cancel the installation
    askn "Would you like to install them automatically? [Y/n]: "
    read -r INSTALL_DEPS_RESPONSE
    if [[ $(tr '[:upper:]' '[:lower:]' <<< "${INSTALL_DEPS_RESPONSE}") == "n" ]]; then
        error "Missing dependencies"
        error "Exiting."
        exit 1
    fi
}

function logInstallFailedAndExit {
    error "Package manager command unsuccessful"
    exit 1
}

function installDeps {
    case "${DISTRO}" in
        "arch") 
            # Pacman -Q doesn't check groups
            mapfile -t REAL_DEPENDENCIES <<< "$(pacman -Sgq base-devel)"
            for i in "${DEPENDENCIES[@]}"; do
                [[ "${i}" != "base-devel" ]] && REAL_DEPENDENCIES+=("${i}")
            done
            if ! pacman -Qq "${REAL_DEPENDENCIES[@]}" &> /dev/null && askInstall; then
                # --no-confirm is dangerous with pacman
                sudo pacman -Sy "${DEPENDENCIES[@]}" --needed || logInstallFailedAndExit
            fi
            ;;
        "debian")
            if ! dpkg -s "${DEPENDENCIES[@]}" &> /dev/null && askInstall; then
                sudo apt-get update || logInstallFailedAndExit
                sudo apt-get install --no-install-recommends -y "${DEPENDENCIES[@]}" || logInstallFailedAndExit
            fi
            ;;
        "fedora") 
            # if ; then
            #     askInstall && sudo dnf install -y "${DEPENDENCIES[@]}" || logInstallFailedAndExit
            # fi
            ;;
        "suse") 
            sudo zypper install "${DEPENDENCIES[@]}" || logInstallFailedAndExit
            ;;
        "macos")
            case "${MACOS_PKGMGR}" in 
                "brew")
                    if ! brew list "${DEPENDENCIES[@]}" &> /dev/null && askInstall; then 
                        if brew tap | grep "${BREW_TAP}"; then
                            brew tap "${BREW_TAP}" || logInstallFailedAndExit
                        fi                    
                        brew install "${DEPENDENCIES[@]}" || logInstallFailedAndExit
                    fi
                    ;;
                "port")
                    # Port has no propper way of checking if a package is installed
                    # This is incredibly frustrating
                    NEEDS_INSTALLATION=()
                    INSTALLED=$(port installed "${DEPENDENCIES[@]}" | tail -n +2 | sed "s/^  //" | cut -d " " -f 1)
                    for package in "${INSTALLED[@]}"; do
                        # Hack to see if a string is in an array
                        # shellcheck disable=SC2076 # Intentionally not a regex check
                        if ! [[ " ${DEPENDENCIES[*]} " =~ " ${package} " ]]; then
                            NEEDS_INSTALLATION+=("${package}")
                        fi
                    done
                    if [[ -n "${NEEDS_INSTALLATION[*]}" ]] && askInstall; then
                        sudo port install "${NEEDS_INSTALLATION[@]}" || logInstallFailedAndExit
                    fi

                    # Set python version defaults
                    # TODO: Check if we've already done this
                    info "python39 and cython39 are required to be set as defaults."
                    info "This will create symlinks in /opt/local/lib/pkgconfig and run port select."
                    # TODO: better communicate to the user that saying no will cancel the installation
                    askn "Are you okay with this [Y/n]: "
                    read -r SET_DEFAULTS_RESPONSE
                    if [[ $(tr '[:upper:]' '[:lower:]' <<< "${SET_DEFAULTS_RESPONSE}") == "n" ]]; then
                        error "Did not set package defaults"
                        error "Exiting."
                        exit 1
                    fi
                    sudo port select --set python python39
                    sudo port select --set python3 python39
                    sudo port select --set cython cython39
                    sudo ln -svf /opt/local/lib/pkgconfig/python3.pc  /opt/local/lib/pkgconfig/python-3.9.pc
                    sudo ln -svf /opt/local/lib/pkgconfig/python3-embed.pc  /opt/local/lib/pkgconfig/python-3.9-embed.pc
                    ;;
            esac
            ;;
    esac
}

function askUseDir {
    echo
    info "Found proxmark3 repository:"
    info "  ${DEPENDENCIES[*]}"
    if [[ "${MACOS_PKGMGR}" == "brew" ]]; then
        info "The following tap needs to be added to brew:"
        info "  ${BREW_TAP}"
    fi
}

function checkRepo {
    for i in "$(dirname $0)" "$(pwd)"; do
        ORIGIN=$(git remote get-url origin | tr '[:upper:]' '[:lower:]')
        # Lazy checking
        if [[ "${ORIGIN}" =~ git@github.com:rfidresearchgroup/proxmark3 ]] || [[ "${ORIGIN}" =~ https://github.com/rfidresearchgroup/proxmark3 ]]; then
            POTENTIAL_WORKDIR=$(git rev-parse --show-toplevel)
        fi
    done;
}

echo
info "PM3 build script"
os

installDeps

checkRepo