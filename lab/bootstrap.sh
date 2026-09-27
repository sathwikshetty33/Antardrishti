#!/usr/bin/env bash
# installs host-side tools for the antardrishti lab
set -euo pipefail
cd "$(dirname "$0")/.."

export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get update -qq
sudo apt-get install -y -qq tshark tcpdump tcpreplay zstd jq iproute2 >/dev/null
command -v gh >/dev/null || sudo apt-get install -y -qq gh >/dev/null
# bridged lab traffic must bypass docker forward rules (preflight re-applies this)
sudo sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 || true
sudo usermod -aG wireshark "$USER" || true

python3 -m pip install -q -r lab/requirements.txt

mkdir -p dataset/raw dataset/external/whatsapp dataset/external/public

bash lab/cleanup.sh || true
# lab images and media: the pinned digests from lab/images.lock (the same on every shard).
# a refused pull is an error, never a local build or crawl: runs on them are rejected at merge
fail=""
bash lab/images.sh pull || fail="images"
media=$(awk '$1 == "media" {print $2}' lab/images.lock)
[ "$(cat lab/media/.digest 2>/dev/null)" = "$media" ] || bash lab/images.sh pull-media || fail="$fail media"
[ -s lab/media/bulk/f200.bin ] || bash lab/media.sh bulk
[ -z "$fail" ] || { echo "bootstrap: pinned $fail not pulled (package access: README, Lab images)"; exit 1; }
echo "bootstrap done: $(tshark --version | head -1)"
