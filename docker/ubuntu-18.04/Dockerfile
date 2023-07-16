FROM ubuntu:18.04

ENV LANG C
ENV DEBIAN_FRONTEND noninteractive
# qtbase5-dev skipped
# python3 skipped, not yet searchable with pkg-config python3
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends git ca-certificates build-essential cmake pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev libbz2-dev liblz4-dev libbluetooth-dev libssl-dev sudo && \
    apt-get clean

RUN apt-get install -y python3-minimal && \
    apt-get install -y python3-pip && \
    apt-get clean && \
    python3 -m pip install ansicolors sslcrypto

RUN apt-get install -y opencl-dev && \
    apt-get clean

# Create rrg user
RUN useradd -ms /bin/bash rrg
RUN passwd -d rrg
RUN printf 'rrg ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

CMD ["/bin/bash"]
