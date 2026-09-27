#!/usr/bin/env bash
# lab images on ghcr.io: build and push once, pull the same digests everywhere.
#
#   bash lab/images.sh push    build, push to ghcr, write lab/images.lock (commit it)
#   bash lab/images.sh pull    pull every image by the digest in lab/images.lock and
#                              tag it antar/<name>; falls back to a local build
#   bash lab/images.sh build   local build only
#   bash lab/images.sh push-media | pull-media
#                              the media snapshot (hls ladders + mirrored pages) as an
#                              image, so every shard serves byte-identical content
#
# pushing needs a classic personal access token with write:packages in GHCR_TOKEN
# (fine-grained tokens do not work with ghcr.io); pulling falls back to GITHUB_TOKEN.
# packages are private by default; they carry org.opencontainers.image.source,
# so they link to this repo and teammates with repo access can pull them.
set -euo pipefail
cd "$(dirname "$0")"
owner=${GHCR_OWNER:-${GITHUB_REPOSITORY_OWNER:-sathwikshetty33}}
repo=${GHCR_REPO:-${GITHUB_REPOSITORY:-sathwikshetty33/SIH}}
base=ghcr.io/${owner,,}/antardrishti
imgs="gw router host services noise"
lock=images.lock
src="https://github.com/$repo"

build() {
  for i in $imgs; do
    docker build -q --label "org.opencontainers.image.source=$src" \
      --label "org.opencontainers.image.description=antardrishti lab image ($i)" \
      -t "antar/$i" "images/$i" >/dev/null
    echo "built antar/$i"
  done
}

# registry credentials live in a throwaway docker config for this invocation only,
# never in ~/.docker/config.json (docker would store the token there in plain text)
cfg=$(mktemp -d)
trap 'rm -rf "$cfg"' EXIT
dk() { docker --config "$cfg" "$@"; }

login() {
  tok=${GHCR_TOKEN:-${GITHUB_TOKEN:-}}
  [ -n "$tok" ] || { echo "no GHCR_TOKEN / GITHUB_TOKEN"; return 1; }
  echo "$tok" | dk login ghcr.io -u "${GITHUB_USER:-$owner}" --password-stdin >/dev/null 2>&1 \
    || { echo "ghcr login refused (need a classic token with write:packages to push, read:packages to pull)"; return 1; }
}

case "${1:-pull}" in
  build)
    build ;;
  push)
    build
    login
    tag=$(git rev-parse --short HEAD)
    : > "$lock.tmp"
    for i in $imgs; do
      docker tag "antar/$i" "$base-$i:$tag"
      dk push -q "$base-$i:$tag" >/dev/null
      # the registry digest, not a local name for the same image
      d=$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$base-$i:$tag" | grep "^$base-$i@" | head -1)
      echo "$i $d" >> "$lock.tmp"
      echo "pushed $d"
    done
    mv "$lock.tmp" "$lock" ;;
  pull)
    if [ ! -s "$lock" ]; then echo "no $lock: building locally"; build; exit 0; fi
    login 2>/dev/null || true
    grep -v '^media ' "$lock" | while read -r i d; do
      if docker image inspect "$d" >/dev/null 2>&1; then
        docker tag "$d" "antar/$i"
        echo "present $d"
      elif dk pull -q "$d" >/dev/null 2>&1; then
        docker tag "$d" "antar/$i"
        echo "pulled $d"
      else
        echo "pull failed for $d: building antar/$i locally (runs will record no registry digest)"
        docker build -q -t "antar/$i" "images/$i" >/dev/null
      fi
    done ;;
  push-media)
    login
    tag=$(git rev-parse --short HEAD)
    cat > media/Dockerfile <<'EOD'
FROM scratch
COPY hls /media/hls
COPY sites /media/sites
COPY ATTRIBUTION.md /media/ATTRIBUTION.md
EOD
    cp ATTRIBUTION.md media/ATTRIBUTION.md
    docker build -q --label "org.opencontainers.image.source=$src" -t "$base-media:$tag" -f media/Dockerfile media >/dev/null
    rm -f media/Dockerfile media/ATTRIBUTION.md
    dk push -q "$base-media:$tag" >/dev/null
    d=$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$base-media:$tag" | grep "^$base-media@" | head -1)
    grep -v '^media ' "$lock" > "$lock.tmp" 2>/dev/null || true
    echo "media $d" >> "$lock.tmp" && mv "$lock.tmp" "$lock"
    echo "pushed $d" ;;
  pull-media)
    d=$(awk '$1 == "media" {print $2}' "$lock")
    [ -n "$d" ] || { echo "no media digest in $lock: run lab/media.sh"; exit 1; }
    login 2>/dev/null || true
    dk pull -q "$d" >/dev/null
    cid=$(docker create "$d" /none)
    mkdir -p media && rm -rf media/hls media/sites
    docker cp "$cid:/media/hls" media/hls && docker cp "$cid:/media/sites" media/sites
    docker rm "$cid" >/dev/null
    echo "media from $d" ;;
  *)
    echo "usage: $0 push|pull|build|push-media|pull-media"; exit 2 ;;
esac
