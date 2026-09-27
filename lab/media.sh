#!/usr/bin/env bash
# one-time media prep for the services image, output in lab/media (gitignored,
# mounted at /srv/media). everything here is openly licensed:
#   big buck bunny, sintel (cc-by, blender foundation)
#   wikipedia / wikivoyage (cc-by-sa), python docs (psf), arch wiki (gfdl)
# usage: bash lab/media.sh [hls|sites|bulk|all]
set -euo pipefail
cd "$(dirname "$0")"
what=${1:-all}
mkdir -p media
docker run --rm -v "$PWD/media:/out" -v "$PWD/sites.txt:/sites.txt:ro" -e WHAT="$what" ubuntu:24.04 bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends ffmpeg wget curl unzip ca-certificates >/dev/null
cd /out

if [ "$WHAT" = hls ] || [ "$WHAT" = all ]; then
  mkdir -p src hls
  [ -s src/bbb.mp4 ] || { curl -sL -o src/bbb.zip https://download.blender.org/demo/movies/BBB/bbb_sunflower_1080p_30fps_normal.mp4.zip \
      && unzip -o -q src/bbb.zip -d src && mv src/bbb_sunflower_1080p_30fps_normal.mp4 src/bbb.mp4 && rm src/bbb.zip; }
  [ -s src/sintel.mkv ] || ffmpeg -loglevel error -y -i https://download.blender.org/durian/movies/Sintel.2010.1080p.mkv \
      -t 300 -map 0:v:0 -map 0:a:0 -c copy src/sintel.mkv
  # ladder: 240p 400k, 360p 800k, 480p 1400k, 720p 2800k, 1080p 5000k; 4 s segments, 2 s gop
  for v in bbb sintel; do
    s=src/$v.mp4; [ -f $s ] || s=src/$v.mkv
    [ -s hls/$v/master.m3u8 ] && continue
    mkdir -p hls/$v
    ffmpeg -loglevel error -y -t 300 -i $s -filter_complex \
      "[0:v]split=5[a][b][c][d][e];[a]scale=-2:240[v0];[b]scale=-2:360[v1];[c]scale=-2:480[v2];[d]scale=-2:720[v3];[e]scale=-2:1080[v4]" \
      -map "[v0]" -map "[v1]" -map "[v2]" -map "[v3]" -map "[v4]" -map 0:a:0 \
      -c:v libx264 -preset veryfast -profile:v main -force_key_frames "expr:gte(t,n_forced*2)" -sc_threshold 0 \
      -b:v:0 400k -maxrate:v:0 440k -bufsize:v:0 800k \
      -b:v:1 800k -maxrate:v:1 880k -bufsize:v:1 1600k \
      -b:v:2 1400k -maxrate:v:2 1540k -bufsize:v:2 2800k \
      -b:v:3 2800k -maxrate:v:3 3080k -bufsize:v:3 5600k \
      -b:v:4 5000k -maxrate:v:4 5500k -bufsize:v:4 10000k \
      -c:a aac -b:a 128k -ac 2 \
      -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_type mpegts \
      -master_pl_name master.m3u8 -var_stream_map "v:0,agroup:a v:1,agroup:a v:2,agroup:a v:3,agroup:a v:4,agroup:a a:0,agroup:a" \
      -hls_segment_filename "hls/$v/%v/seg%03d.ts" "hls/$v/%v/index.m3u8"
  done
  # sources are only needed to encode; drop them to save codespace storage
  rm -rf src
  curl -sL -o hls/hls.min.js https://cdn.jsdelivr.net/npm/hls.js@1.5.20/dist/hls.min.js
fi

if [ "$WHAT" = sites ] || [ "$WHAT" = all ]; then
  mkdir -p sites && cd sites
  while read -r u; do
    [ -z "$u" ] && continue
    case "$u" in \#*) continue;; esac
    wget -q -e robots=on --wait=0.3 --random-wait -U "antardrishti-lab-mirror/1.0 (research, one-time)" \
      -p -k -E -H -D wikipedia.org,wikimedia.org,wikivoyage.org,python.org,archlinux.org \
      --reject-regex "\.(webm|ogg|ogv|oga|opus|mp3|mp4|wav|flac|tiff?|pdf|djvu|mid)([?].*)?$|utm_content=original|/Special:|action=edit" \
      --quota=40m --timeout=20 --tries=2 "$u" || true
    # keep the heaviest page reasonable: a browser only loads what the page shows
    find . -type f -size +3M -delete
  done < /sites.txt
  cd ..
  : > sites/index.txt
  while read -r u; do
    [ -z "$u" ] && continue
    case "$u" in \#*) continue;; esac
    p=${u#https://}; p=${p%/}
    for c in "sites/$p" "sites/$p.html" "sites/$p/index.html"; do [ -f "$c" ] && { echo "/${c}" >> sites/index.txt; break; }; done
  done < /sites.txt
  echo "pages mirrored: $(wc -l < sites/index.txt)"
fi
if [ "$WHAT" = bulk ] || [ "$WHAT" = all ]; then
  # incompressible bulk-transfer files, shared read-only by every lab
  mkdir -p bulk
  for s in 10 25 50 100 200; do
    [ -s bulk/f$s.bin ] || head -c ${s}M /dev/urandom > bulk/f$s.bin
  done
fi
chmod -R a+rX /out
'
du -sh media/* 2>/dev/null
