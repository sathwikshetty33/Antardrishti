# server side: every app service runs here (host_b, and svc_gw for transport mode).
# identical image in both places so the only difference between modes is the mode.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections \
    && apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      iproute2 iptables tcpdump tcpreplay iputils-ping curl ca-certificates procps openssl \
      python3 nginx asterisk postfix dovecot-imapd prosody openssh-server rsync \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash lab && echo 'lab:lab-throwaway' | chpasswd \
    && mkdir -p /etc/lab/tls && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=lab.test" -addext "subjectAltName=DNS:lab.test,DNS:mail.lab.test,DNS:www.lab.test" \
      -keyout /etc/lab/tls/key.pem -out /etc/lab/tls/cert.pem
COPY conf/ /etc/lab/conf/
COPY serve.sh /serve.sh
RUN chmod +x /serve.sh
CMD ["/serve.sh"]
