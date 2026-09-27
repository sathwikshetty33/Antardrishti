FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      strongswan-charon strongswan-swanctl strongswan-pki \
      libstrongswan-standard-plugins libcharon-extra-plugins libstrongswan-extra-plugins libcharon-extauth-plugins \
      iproute2 iptables nftables conntrack tcpdump iputils-ping curl python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY entry.sh /entry.sh
RUN chmod +x /entry.sh
CMD ["/entry.sh"]
