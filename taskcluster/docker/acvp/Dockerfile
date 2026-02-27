FROM rust:1.90
LABEL maintainer="iaroslav.gridin@tuni.fi"

VOLUME /builds/worker/checkouts

# %include-run-task

# Install clang-19/llvm-19 from the official LLVM apt repository.
# Using apt.llvm.org rather than the Debian sid repo gives us a stable,
# versioned toolchain that tracks the Debian base image automatically.
RUN DISTRO=$(. /etc/os-release && echo "$VERSION_CODENAME") \
 && wget -qO /etc/apt/trusted.gpg.d/llvm.asc https://apt.llvm.org/llvm-snapshot.gpg.key \
 && printf "deb http://apt.llvm.org/%s/ llvm-toolchain-%s-19 main\n" "$DISTRO" "$DISTRO" \
      > /etc/apt/sources.list.d/llvm.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
    binutils \
    build-essential \
    clang-19 \
    git \
    gyp \
    libclang-rt-19-dev \
    locales \
    llvm-19 \
    mercurial \
    ninja-build \
    python-dev-is-python3 \
    python3-pip \
 && rm -rf /var/lib/apt/lists/*

ENV SHELL=/bin/bash
ENV USER=worker
ENV LOGNAME=worker
ENV HOME=/builds/worker
ENV HOSTNAME=taskcluster-worker
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV HOST=localhost
ENV DOMSUF=localdomain

RUN locale-gen $LANG \
 && DEBIAN_FRONTEND=noninteractive dpkg-reconfigure locales

RUN useradd -d $HOME -s $SHELL -m $USER
WORKDIR $HOME

RUN chown -R $USER: $HOME

ADD bin $HOME/bin
RUN chmod +x $HOME/bin/*

# Set a default command for debugging.
CMD ["/bin/bash", "--login"]
