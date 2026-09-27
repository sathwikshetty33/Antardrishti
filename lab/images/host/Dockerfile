# client side: every traffic generator runs here (host_a, and cli_gw for transport mode)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      iproute2 iptables tcpdump tcpreplay iputils-ping curl ca-certificates procps \
      python3 python3-pip python3-venv openssh-client rsync swaks baresip-core \
      dnsutils \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
