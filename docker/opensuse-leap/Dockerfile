FROM opensuse/leap

ENV LANG=C.UTF-8

RUN zypper --non-interactive install --no-recommends shadow sudo git patterns-devel-base-devel_basis cmake gcc15 gcc15-c++ readline-devel libbz2-devel liblz4-devel bluez-devel python3-devel libopenssl-devel gd-devel

RUN zypper --non-interactive install ocl-icd-devel

ARG SKIPQT=false
RUN if [ "${SKIPQT}" = "false" ]; then \
      zypper --non-interactive install qt6-core-devel qt6-widgets-devel; \
    fi

RUN zypper addrepo https://download.opensuse.org/repositories/home:wkazubski/15.6/home:wkazubski.repo && \
    zypper --gpg-auto-import-keys refresh && \
    zypper --non-interactive install cross-arm-none-eabi-gcc15 cross-arm-none-eabi-newlib

# Set GCC 15 as default, else it's GCC 7 ?!
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-15 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-15 100 && \
    update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-15 100 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-15 100

# uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Create rrg user
RUN useradd -ms /bin/bash rrg
RUN passwd -d rrg
ARG UART_GID
# dialout group may already exist on another numeric ID than on host
RUN if [ -n "${UART_GID}" ]; then \
    groupadd -g ${UART_GID} mydialout || true; \
    usermod -aG ${UART_GID} rrg; \
  fi
RUN printf 'rrg ALL=(ALL) NOPASSWD: ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

CMD ["/bin/bash"]
