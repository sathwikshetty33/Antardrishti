# client side: every traffic generator runs here (host_a, and cli_gw for transport mode)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      iproute2 iptables tcpdump tcpreplay iputils-ping curl ca-certificates procps \
      python3 python3-pip python3-venv openssh-client rsync swaks libnet-ssleay-perl \
      baresip-core espeak-ng sox dnsutils \
    && rm -rf /var/lib/apt/lists/*
# chrome (not playwright's chromium): h.264/aac in mse is needed for hls.js
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw
RUN pip install -q --break-system-packages playwright==1.55.0 slixmpp==1.10.0 \
    && playwright install --with-deps chrome \
    && rm -rf /var/lib/apt/lists/* /root/.cache
# speech-like call audio: tts sentences with natural pauses (8k and 48k mono)
COPY speech.txt /opt/voice/speech.txt
RUN cd /opt/voice && i=0 && while read -r l; do i=$((i+1)); \
      espeak-ng -s 150 -v en-us -w s$i.wav "$l"; done < speech.txt \
    && sox $(ls s*.wav | sort -V | sed 's/$/ /' | tr -d '\n') all.wav \
    && sox all.wav -r 8000 -c 1 -b 16 voice8k.wav pad 0.8 0.8 repeat 4 \
    && sox all.wav -r 48000 -c 1 -b 16 voice48k.wav pad 0.8 0.8 repeat 4 \
    && rm s*.wav all.wav
CMD ["sleep", "infinity"]
