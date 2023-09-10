FROM archlinux:base

ENV LANG C
RUN pacman -Syu --noconfirm
RUN pacman-db-upgrade
# qt5-base skipped
# bluez skipped, can't be installed in docker
RUN pacman -S --noconfirm sudo git base-devel cmake libusb readline bzip2 lz4 arm-none-eabi-gcc arm-none-eabi-newlib python --needed

RUN pacman -S --noconfirm python-pip

# OpenCL for hitag2crack
RUN pacman -S --noconfirm ocl-icd

# Create rrg user
RUN useradd -ms /bin/bash rrg
RUN passwd -d rrg
RUN printf 'rrg ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

RUN git clone https://aur.archlinux.org/package-query.git && cd package-query && makepkg -si --noconfirm --needed && cd .. && rm -rf package-query

CMD ["/bin/bash"]
