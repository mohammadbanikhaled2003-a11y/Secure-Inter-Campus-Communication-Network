FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install all required packages:
# OpenSSL 3, strongSwan (swanctl/charon), nginx, tcpdump, tshark, nmap, curl, python3, pyca/cryptography, iptables, iproute2, dnsutils
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    iproute2 \
    iputils-ping \
    iptables \
    net-tools \
    dnsutils \
    nmap \
    tcpdump \
    tshark \
    nano \
    vim \
    git \
    openssl \
    strongswan \
    strongswan-swanctl \
    libcharon-extra-plugins \
    nginx \
    python3 \
    python3-pip \
    python3-cryptography \
    python3-pytest \
    bsdextrautils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install testssl.sh 3.2.1
RUN git clone --depth 1 --branch v3.2 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Set working directory to project mount point
WORKDIR /work

CMD ["/bin/bash"]
