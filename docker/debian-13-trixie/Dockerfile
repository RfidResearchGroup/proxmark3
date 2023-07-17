FROM debian:trixie-slim

ENV LANG C
ENV DEBIAN_FRONTEND noninteractive
# qtbase5-dev skipped
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends git ca-certificates build-essential cmake pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev libbz2-dev liblz4-dev libbluetooth-dev libpython3-dev libssl-dev sudo && \
    apt-get clean

RUN apt-get install -y --no-install-recommends python3-minimal python3-pip python3-venv && \
    apt-get clean

RUN apt-get install -y opencl-dev && \
    apt-get clean

# Create rrg user
RUN useradd -ms /bin/bash rrg
RUN passwd -d rrg
RUN printf 'rrg ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

CMD ["/bin/bash"]
