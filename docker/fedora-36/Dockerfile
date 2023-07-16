FROM fedora:36

ENV LANG C
# qt5-qtbase-devel skipped
RUN dnf install -y passwd sudo git make gcc gcc-c++ arm-none-eabi-gcc-cs arm-none-eabi-newlib readline-devel bzip2-devel lz4-devel bluez-libs-devel python3-devel openssl-devel libatomic findutils

RUN yum -y update
RUN yum -y install cmake python-pip
RUN python3 -m pip install ansicolors sslcrypto

RUN yum -y install mesa-libOpenCL ocl-icd-devel

# Create rrg user
RUN useradd -ms /bin/bash rrg
RUN passwd -d rrg
RUN printf 'rrg ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER rrg
WORKDIR "/home/rrg"

CMD ["/bin/bash"]
