FROM homebrew/brew

ENV LANG=C

ARG UART_GID
# dialout group may already exist on another numeric ID than on host
RUN if [ -n "${UART_GID}" ]; then \
    sudo groupadd -g ${UART_GID} mydialout || true; \
    sudo usermod -aG ${UART_GID} linuxbrew; \
  fi

USER linuxbrew
WORKDIR "/home/linuxbrew"
RUN brew install cmake pkg-config bzip2 lz4 && rm -rf ~/.cache/Homebrew

CMD ["/bin/bash"]
