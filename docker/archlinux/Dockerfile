FROM archlinux:base

ENV LANG=C
RUN pacman -Syu --noconfirm
RUN pacman-db-upgrade
# qt5-base skipped
# bluez skipped, can't be installed in docker
RUN pacman -S --noconfirm sudo git base-devel cmake libusb readline bzip2 lz4 gd arm-none-eabi-gcc arm-none-eabi-newlib python --needed

RUN pacman -S --noconfirm python-pip

# OpenCL for hitag2crack
RUN pacman -S --noconfirm ocl-icd

# Create rrg user
RUN useradd -ms /bin/bash rrg
RUN passwd -d rrg
ARG UART_GID
# dialout group may already exist on another numeric ID than on host
RUN if [ -n "${UART_GID}" ]; then \
    groupadd -g ${UART_GID} mydialout || true; \
    usermod -aG ${UART_GID} rrg; \
  fi
RUN printf 'rrg ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

RUN git clone https://aur.archlinux.org/package-query.git && cd package-query && makepkg -si --noconfirm --needed && cd .. && rm -rf package-query

CMD ["/bin/bash"]
