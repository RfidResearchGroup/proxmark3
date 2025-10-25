Packaging notes
----------------

This directory contains skeleton notes and helper scripts for packaging the `pm3-gui` package.

Current artifacts:

- GitHub Actions workflow builds a wheel for the `gui/` package and uploads it as an artifact.
- If you want to produce a standalone Linux AppImage or .deb, add the appropriate build steps. Example options:
  - AppImage: use `linuxdeploy` + `linuxdeployqt` or `appimage-builder` to bundle Python, Qt and dependencies.
  - .deb: create a debian/ control files and use `dpkg-deb` to build a package; consider using fpm for convenience.

Security notes
--------------

Packaging desktop applications that interact with devices often requires bundling native libraries and handling udev rules and permissions carefully. Prefer documenting the udev rules and asking users to install them explicitly or provide a secure pkexec helper which we include as `gui/scripts/install-udev.sh`.
