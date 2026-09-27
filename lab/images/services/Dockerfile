# server side: every app service runs here (host_b, and svc_gw for transport mode)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      iproute2 iptables tcpdump tcpreplay iputils-ping curl ca-certificates procps \
      python3 nginx \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
