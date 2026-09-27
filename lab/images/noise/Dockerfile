# non-ipsec background traffic: dns, ntp, plain http, icmp across the router
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      iproute2 iputils-ping curl dnsutils dnsmasq chrony python3 procps ntpsec-ntpdate \
    && rm -rf /var/lib/apt/lists/*
COPY serve.sh noise.py ikeinit.py /
RUN chmod +x /serve.sh
CMD ["sleep", "infinity"]
