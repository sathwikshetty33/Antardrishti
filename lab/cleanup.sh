#!/usr/bin/env bash
# docker hygiene for codespaces. after a restart this codespace can switch docker
# between two containerd stores (/var/lib/containerd and
# /var/lib/docker/containerd/daemon); the one no longer in use keeps every old
# image and silently fills the disk. removes only:
#   - the containerd store that no running containerd uses and no process has open
#   - containers docker lists but can no longer use (their layers are gone)
#   - build cache (lab images come pinned from ghcr)
# usage: bash lab/cleanup.sh
set -uo pipefail
before=$(df --output=avail -BG /workspaces | tail -1 | tr -dc 0-9)

# roots of the running containerd processes
active=""
for pid in $(pgrep -x containerd); do
  cfg=$(tr '\0' ' ' < /proc/$pid/cmdline | sed -n 's/.*--config \([^ ]*\).*/\1/p')
  root=$(sudo sed -n "s/^[[:space:]]*root[[:space:]]*=[[:space:]]*['\"]\(.*\)['\"].*/\1/p" "${cfg:-/etc/containerd/config.toml}" 2>/dev/null | head -1)
  active="$active ${root:-/var/lib/containerd}"
done
for store in /var/lib/containerd /var/lib/docker/containerd/daemon; do
  [ -d "$store" ] || continue
  case " $active " in *" $store "*) continue ;; esac
  if [ -z "$active" ] || [ "$(sudo lsof +D "$store" 2>/dev/null | wc -l)" != 0 ]; then continue; fi
  echo "removing unused containerd store $store ($(sudo du -sh "$store" 2>/dev/null | cut -f1))"
  sudo rm -rf "$store"
done

# containers whose layers are gone make every `docker ps` fail
if ! docker ps -aq >/dev/null 2>&1; then
  for id in $(sudo ls /var/lib/docker/containers 2>/dev/null); do docker rm -f "$id" >/dev/null 2>&1; done
fi
docker builder prune -af >/dev/null 2>&1
docker image prune -f >/dev/null 2>&1
after=$(df --output=avail -BG /workspaces | tail -1 | tr -dc 0-9)
echo "cleanup: ${before}G -> ${after}G free on /workspaces"
