FROM debian:forky-slim

ENV LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
# qtbase5-dev skipped
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends git ca-certificates build-essential cmake pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev libbz2-dev liblz4-dev libbluetooth-dev libpython3-dev libssl-dev libgd-dev sudo && \
    apt-get clean

RUN apt-get install -y opencl-dev && \
    apt-get clean

ARG SKIPQT=false
RUN if [ "${SKIPQT}" = "false" ]; then \
      apt-get install -y qt6-base-dev && \
      apt-get clean; \
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
