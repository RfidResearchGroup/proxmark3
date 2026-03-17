with import <nixpkgs> { };

mkShell {
  nativeBuildInputs = [
    pkg-config
    gcc-arm-embedded
    udevCheckHook
    readline
    bzip2
    openssl
    jansson
    gd
    lz4
    whereami
    lua
    bluez5
    python3
    qt6Packages.qtbase
    qt6Packages.wrapQtAppsHook
  ];
}
