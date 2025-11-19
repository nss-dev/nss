# Lean image for running the bulk of the NSS CI tests on taskcluster.
FROM ubuntu:jammy

VOLUME /builds/worker/checkouts
VOLUME /builds/worker/.cache
VOLUME /builds/worker/workspace

# %include-run-task

ENV DEBIAN_FRONTEND noninteractive
RUN dpkg --add-architecture i386
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    curl \
    g++-multilib \
    git \
    gyp \
    libxml2-utils \
    lib32z1-dev \
    linux-libc-dev:i386 \
    llvm-dev \
    locales \
    mercurial \
    ninja-build \
    pkg-config \
    sqlite3 \
    zlib1g-dev \
    python3 \
    python3-pip \
    rsync \
    iproute2 \
    libnss3-tools \
    expect \
    gnutls-bin \
    crypto-policies \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get autoremove -y && apt-get clean -y

ENV SHELL /bin/bash
ENV USER worker
ENV LOGNAME $USER
ENV HOME /builds/worker
ENV LANG en_US.UTF-8
ENV LC_ALL $LANG
ENV HOST localhost
ENV DOMSUF localdomain

RUN locale-gen $LANG \
 && dpkg-reconfigure locales

RUN useradd -d $HOME -s $SHELL -m $USER && \
    mkdir -p /builds/worker/workspace && \
    mkdir -p /builds/worker/artifacts && \
    chown -R $USER /builds/worker && \
    pip install tmt && \
    echo '#!/bin/bash\n\nexit 0' >/usr/bin/fakedora && \
    chmod +x /usr/bin/fakedora && \
    ln -s /usr/bin/fakedora /usr/bin/rpm && \
    ln -s /usr/bin/fakedora /usr/bin/dnf && \
    ln -s /usr/bin/fakedora /usr/local/bin/rhts-report-result && \
    ln -s /usr/bin/fakedora /usr/local/bin/tmt-file-submit && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    update-crypto-policies --set DEFAULT && \
    cd $HOME && \
    curl -L -o beakerlib.tgz 'https://github.com/beakerlib/beakerlib/archive/refs/tags/1.31.4.tar.gz' && \
    tar xf beakerlib.tgz && \
    cd beakerlib-* && \
    make install && \
    echo done
WORKDIR $HOME

# Set a default command for debugging.
CMD ["/bin/bash", "--login"]
