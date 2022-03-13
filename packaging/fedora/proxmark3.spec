Name:           proxmark3
Version:        4.14831.1
Release:        1%{?dist}
Summary:        The Swiss Army Knife of RFID Research - RRG/Iceman repo

License:        GPLv3+
URL:            https://github.com/RfidResearchGroup/proxmark3
Source0:        https://github.com/s00se/proxmark3/archive/refs/tags/v%{version}.tar.gz

BuildRequires:	make, gcc, g++, readline-devel, arm-none-eabi-gcc, arm-none-eabi-newlib, bzip2-devel, libatomic, openssl-devel, python3-devel, jansson-devel, bluez-libs-devel, qt5-qtbase-devel
Requires:	bzip2-libs, readline, python3, bluez, qt5-qtbase

%description
The Swiss Army Knife of RFID Research - RRG/Iceman repo

%global debug_package %{nil}
%define __strip /bin/true

%prep
%autosetup

%build
make clean
make PLATFORM=PM3GENERIC SKIPLUASYSTEM=1

%install
make install PREFIX=%{buildroot}/usr UDEV_PREFIX=%{buildroot}/etc/udev/rules.d/

%files
%{_sysconfdir}/udev/rules.d/77-pm3-usb-device-blacklist.rules
%{_bindir}/pm3
%{_bindir}/pm3-flash
%{_bindir}/pm3-flash-all
%{_bindir}/pm3-flash-bootrom
%{_bindir}/pm3-flash-fullimage
%{_bindir}/proxmark3
%{_docdir}/proxmark3
%{_datadir}/proxmark3

%license LICENSE.txt
%doc doc/ AUTHORS.md CHANGELOG.md COMPILING.txt CONTRIBUTING.md README.md

%changelog
* Wed Feb 16 2022 Marlin Soose <marlin.soose@laro.se> - 4.14831.1
- Initial version of the package
