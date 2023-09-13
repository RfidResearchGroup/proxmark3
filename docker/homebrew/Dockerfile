FROM homebrew/brew

ENV LANG C

USER linuxbrew
WORKDIR "/home/linuxbrew"
RUN brew install cmake pkg-config bzip2 lz4 && rm -rf ~/.cache/Homebrew

CMD ["/bin/bash"]
