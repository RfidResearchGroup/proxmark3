FROM debian:forky-slim

ENV LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt upgrade -y && \
    apt dist-upgrade -y && \
    apt install -y --no-install-recommends git ca-certificates build-essential cmake pkg-config libreadline-dev libbz2-dev liblz4-dev zlib1g-dev libbluetooth-dev libpython3-dev libssl-dev libgd-dev sudo && \
    apt clean

RUN apt install -y --no-install-recommends gcc-arm-none-eabi picolibc-arm-none-eabi && \
    apt clean

RUN apt install -y ocl-icd-opencl-dev && \
    apt clean

ARG SKIPQT=false
RUN if [ "${SKIPQT}" = "false" ]; then \
      apt install -y qt6-base-dev && \
      apt clean; \
    fi

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
RUN printf 'rrg ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

CMD ["/bin/bash"]
