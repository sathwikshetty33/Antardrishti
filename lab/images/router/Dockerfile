FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      iproute2 iptables nftables tcpdump iputils-ping procps zstd \
    && rm -rf /var/lib/apt/lists/*
CMD ["sh", "-c", "sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1; exec sleep infinity"]
