#!/usr/bin/env bash
# installs host-side tools for the antardrishti lab
set -euo pipefail
cd "$(dirname "$0")/.."

export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get update -qq
sudo apt-get install -y -qq tshark tcpdump tcpreplay zstd jq iproute2 >/dev/null
# bridged lab traffic must bypass docker forward rules (preflight re-applies this)
sudo sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 || true
sudo usermod -aG wireshark "$USER" || true

python3 -m pip install -q -r lab/requirements.txt

mkdir -p dataset/raw dataset/external/whatsapp dataset/external/public
echo "bootstrap done: $(tshark --version | head -1)"
