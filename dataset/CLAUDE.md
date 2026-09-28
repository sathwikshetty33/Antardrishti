# Antardrishti — seeing through IPsec tunnels

*Antardrishti* (Sanskrit: "inner vision") — insight into what flows inside encrypted tunnels, without ever opening them.

Antardrishti is an AI-driven IPsec VPN analysis platform built for SIH 2026. It inspects
captured or live traffic, infers the IPsec configuration (IKE version, tunnel or transport
mode, cipher, integrity, DH group, PFS, SA lifetimes), predicts the traffic type inside
ESP, and produces a security assessment.

**This file covers phase 1 only: building the labelled training/testing dataset.**
Everything the analyzer later learns and is tested on comes from what we capture here,
so label correctness matters more than volume.

The analyzer is a passive observer on the wire. It never sees plaintext and never uses
keys. Plaintext captures and keys exist **only** in the dataset, as ground truth.

---

## 1. Environment: GitHub Codespaces

- The dev container (`.devcontainer/devcontainer.json`) must provide:
  - Ubuntu base image
  - Docker-in-Docker
  - Python 3.12
  - `"privileged": true` and `"capAdd": ["NET_ADMIN"]`
- Run every capture batch on a **4-core** machine with **one lab** (`--labs 1`, the
  default). Parallel labs failed the adversarial validation (section 12): they bias
  packet timing. There is no separate 2-core plan; a 2-core machine is fine for
  development.
- Budget. The free personal quota is 120 core-hours and 15 GB-month storage.
  - A 4-core machine burns 4 core-hours per hour of runtime.
  - Always print a time estimate (`--dry-run`) before starting a batch. It simulates the
    parallel schedule and prints wall-clock, core-hours and storage per shard.
  - Ask the user before starting anything estimated at more than 2 hours.
- Lab images come from ghcr.io, pinned by digest in `lab/images.lock`
  (`lab/images.sh pull`), so every shard runs identical images. The media snapshot (HLS
  ladders, mirrored pages) is pinned the same way (`lab/images.sh pull-media`, which
  records its digest in `lab/media/.digest`). A refused pull is an error, never a local
  build or crawl (runs on those are rejected at merge): bootstrap, preflight and every
  batch check the pins. Every run records the image and media digests it used.
- Docker's image store survives a codespace restart only when the codespace runs this
  repo's devcontainer (docker-in-docker keeps `/var/lib/docker` on a volume). Otherwise
  every restart costs an image pull or rebuild.
- After a restart Docker can switch between two containerd stores (`/var/lib/containerd`
  and `/var/lib/docker/containerd/daemon`); the unused one keeps every old image and
  silently fills the disk. `lab/cleanup.sh` removes only the store no running containerd
  uses (and stale containers and build cache); bootstrap and every batch run it, and a
  batch refuses to start with less than 5 GB free.
- One personal account can run **2 codespaces at a time**. A maintainer can drive a
  second codespace from the first with `gh codespace create / ssh / stop` and a classic
  token with the `codespace` scope (the devcontainer includes an SSH server for this).
  Codespaces on one account share that account's quota: they make a tier finish
  sooner, not cheaper.
- Package read access for codespaces is granted per package (Package settings, Manage
  Codespaces access, add this repository) and takes effect when a codespace starts:
  restart an existing codespace after granting it.
- The idle timeout stops codespaces, so the orchestrator must be **resumable**. It skips
  runs already marked `ok` in the manifest. Tell the user to raise the idle timeout to
  the maximum in their GitHub settings.
- Everything must live under `/workspaces/<repo>/`. Files elsewhere are lost on rebuild.
- Codespaces cannot load kernel modules. Features we need (XFRM, ESP, netem, NFLOG) either
  already exist in the host kernel or they don't. Phase 0 detects this. Never assume.

Suggested devcontainer:

```json
{
  "name": "antardrishti",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu-24.04",
  "features": {
    "ghcr.io/devcontainers/features/docker-in-docker:2": {},
    "ghcr.io/devcontainers/features/python:1": {"version": "3.12"}
  },
  "privileged": true,
  "capAdd": ["NET_ADMIN"],
  "hostRequirements": {"cpus": 2},
  "postCreateCommand": "bash lab/bootstrap.sh"
}
```

---

## 2. Repository layout

```
.devcontainer/devcontainer.json
lab/
  bootstrap.sh          # installs tshark, tcpdump, tcpreplay, zstd, python deps; pulls images + media
  compose.yaml          # one lab's containers (ANTAR_PREFIX selects the lab)
  topo.py               # wiring (veth + per-lab switch netns), routes, netem, strongswan deploy
  images/               # Dockerfiles: gw (strongSwan), host, router, services, noise
  images.sh images.lock # ghcr push / pull by pinned digest (lock file is committed)
  media.sh ATTRIBUTION.md # media prep (hls ladders, mirrored pages, bulk files) + licences
  swanctl/              # jinja2 templates for swanctl.conf and strongswan.conf
  preflight.py smoke.py # phase 0 capability checks, phase 1 per-mode smoke test
gen/                    # traffic generators, one module per app class (+ smoke.py)
capture/
  run.py                # orchestrator: plan -> run -> validate -> record (--labs, --slice)
  plan.py               # deterministic plan: runs, tunnel groups, splits, slices
  placement.py          # parallel-lab placement rules, shared state, schedule simulation
  observe.py pcap.py    # what happened: tshark + charon logs, minimal pcap reader
  matrix.yaml           # the experiment design (section 5)
  edge.yaml             # edge case definitions (section 6)
  netem.yaml            # network condition profiles
tools/
  coverage.py           # checks sufficiency targets (section 7), writes coverage.md
  checkmeta.py          # checks run folders against section 4
  merge.py              # merges manifests from several shards (section 5, tiers)
  annotate.py           # appends annotation lines to the manifest (section 4)
  advval.py             # adversarial validation of parallel labs (section 5)
  labels.py             # builds per-packet labels (section 8)
  export.py             # packs tiers into tar.zst for upload
dataset/
  raw/<run_id>/         # one folder per run (section 4)
  external/whatsapp/    # user-provided phone captures (see gen/chat)
  external/public/      # optional ISCX / VNAT non-VPN pcaps for replay
  manifest.jsonl        # one line per run attempt
  coverage.md           # generated
  README.md             # generated datasheet
```

**Never commit raw captures to git.** Add `dataset/raw/` and `dataset/external/` to
`.gitignore`. Commit `manifest.jsonl`, `coverage.md`, and `README.md` only. Export data
with `tools/export.py` (GitHub release assets, Kaggle, or Hugging Face).

**Back up every finished tier or slice before its codespace can go away.** A codespace
is deleted after its retention period, and quota can run out, so the captures must not
live only in a codespace:

1. `capture/run.py --tier <t> --slice i/n --status` must print COMPLETE.
2. `tools/export.py --tier <t> --slice i/n` packs the ok runs (checked against their
   meta.json checksums) plus their manifest lines into
   `dataset/export/<t>-slice-i-of-n-<commit>.tar.zst` and a `.sha256`.
3. Upload both files as assets of a **draft** GitHub release named `<t>-data` on
   `sathwikshetty33/SIH` (`gh release create <t>-data --draft`, then
   `gh release upload <t>-data <files>`). The repository is public, but a draft
   release is visible only to its collaborators, so the data stays private until the
   owner decides to publish. Assets must stay under GitHub's 2 GB per-file limit.
4. Merge the slices' manifests (`tools/merge.py`) and commit `dataset/manifest.jsonl`,
   `dataset/coverage.md` and `dataset/README.md` to `main`, and push.
5. Only after the upload is verified (download, `sha256sum -c`) may a shard codespace
   be deleted.

To get the data back anywhere: `gh release download <t>-data -R sathwikshetty33/SIH`,
then `sha256sum -c *.sha256` and unpack with `zstd -dc <file> | tar -x`. The adversarial
validation tiers (`avs`, `avp`) are backed up the same way as `av-data`.

---

## 3. Lab topology

```
host_a (10.1.0.0/24) -- gw_a == [router / tap] == gw_b -- host_b (10.2.0.0/24) -- internet (NAT)
                                    |
                                  noise (non-IPsec background traffic)
```

- **`gw_a` / `gw_b`**: strongSwan (swanctl + charon in the foreground). `gw_a` is the
  initiator.
- **`router`**: plain IP forwarding between the gateways, plus `tc netem`. **All outer
  captures happen here.** This is the analyzer's vantage point.
- **`host_b` side services**: the app servers. Self-hosted services are the default because
  they are reproducible and don't depend on the internet:
  - nginx serving HLS video and mirrored websites
  - Asterisk for VoIP
  - dovecot + postfix for email
  - prosody for XMPP chat
  - a bulk-file server
- **Tunnel mode**: clients run on `host_a`, servers on `host_b`. Traffic selectors cover the
  two subnets; `0.0.0.0/0` only in the internet-realism tier.
- **Transport mode**: only traffic between the gateways themselves is protected, so clients
  run on `gw_a` and the same services run on `gw_b`. Keep service versions identical in
  both modes so the only difference is the mode.
- **Dual stack everywhere**: IPv4 and IPv6 on every link. The outer family and inner family
  must be independently selectable.
- **`noise`**: DNS, NTP, plain HTTP and ICMP across the router, outside any tunnel. It
  satisfies the "normal communication" requirement and gives the protocol identifier
  negative examples.
- **Links** are veth pairs into bridges inside a per-lab switch network namespace, not
  docker networks. Every lab therefore has the same addresses, and MAC addresses are
  derived from the IP, so a run's lab cannot be read off the wire. The bridge ports carry
  no IPv6 (they would send router solicitations into the segments).
- **Parallel labs**: each lab has its own gateways, router, hosts, service and noise
  containers and its own switch namespace. Labs share only images and read-only mounts
  (media, generators, external pcaps). Container names are `antar<k>_<name>`.
- The gateways drop any plaintext toward the wan (only ESP/AH, IKE, ND/PMTU ICMP and
  IPsec-protected packets leave), so a tunnel that is down never leaks inner traffic
  into the outer capture.

---

## 4. What every run produces

`run_id` format: `{tier}-{scenario}-{confighash8}-r{rep}`, for example
`p0-voip-3fa9c1d2-r1`.

```
dataset/raw/<run_id>/
  outer.pcap.zst      # router, all traffic, snaplen 128 (payload is encrypted anyway)
  ike.pcap.zst        # router, full packets for UDP 500/4500; post-filter to IKE only
  inner.pcap.zst      # plaintext ground truth, snaplen 96
  charon_a.log  charon_b.log
  xfrm_a.txt  xfrm_b.txt   # `ip -s xfrm state` + `ip xfrm policy`, at start and end
  swanctl_a.conf  swanctl_b.conf
  schedule.json       # app start/stop times, relative to capture start
  meta.json
```

How to take each capture:

- **Outer:** `tcpdump -s 128 --time-stamp-precision nano` on both router interfaces.
- **IKE:** full snaplen for UDP 500 and 4500. If ESP-in-UDP makes this large, post-filter
  with `tshark -Y isakmp` and keep only IKE.
- **Inner, tunnel mode:** capture on `host_a eth0`.
- **Inner, transport mode:** use NFLOG on `gw_a` with an xfrm policy match
  (`-m policy --pol ipsec`) in both directions, then `tcpdump -i nflog:<n>`. Plain tcpdump
  on the gateway interface does not reliably show outbound plaintext.
- Compress with zstd after the run, never during.

`meta.json` must contain at least:

```json
{
  "run_id": "...", "tier": "p0", "scenario": "voip", "rep": 1, "seed": 1234,
  "split": "train",
  "config": {
    "ike_version": 2, "ike_proposal": "aes256-sha256-ecp256",
    "esp_proposal": "aes128gcm16-ecp256", "pfs": true, "dh": "ecp256",
    "mode": "tunnel", "outer_family": "v4", "inner_family": "v4",
    "encap": false, "auth": "psk", "aggressive": false, "esn": false,
    "replay_window": 32, "ike_rekey_s": 14400, "child_rekey_s": 3600,
    "dpd_delay_s": 0, "fragmentation": "yes"
  },
  "apps": ["voip"], "netem": "broadband",
  "capture_start": "before_tunnel",
  "noise": true, "replayed": false, "internet": false,
  "edge_case": null, "expected": {"esp": true, "ike_exchanges": ["IKE_SA_INIT", "IKE_AUTH"]},
  "observed": {"established": true, "notifies": [], "esp_packets": 5412,
               "ike_packets": 4, "child_rekeys": 0, "spis": ["c1a2...", "..."]},
  "ipsec_backend": "kernel", "strongswan_version": "...", "kernel": "...",
  "status": "ok", "duration_s": 90, "sha256": {"outer.pcap.zst": "..."},
  "group": "p0-traffic-3fa9c1d2-r1", "group_pos": 0, "group_size": 6,
  "lab_id": 0, "labs": 1, "timed": true, "timing_valid": true, "order": 17,
  "concurrency": {"max": 1, "mean": 1.0, "overlapping": []},
  "load": {"cpu_busy_mean": 41.0, "cpu_busy_max": 63.0, "loadavg_start": [], "loadavg_end": []},
  "machine": {"env": "codespaces", "account": "...", "codespace": "...", "cores": 4,
              "mem_gb": 16.4, "cpu": "...", "kernel": "..."},
  "images": {"digest_gw": "ghcr.io/...@sha256:...", "digest_media": "ghcr.io/...", "...": "..."},
  "plan": {"tier_seed": 1234, "design_sha": "...", "plan_sha": "...", "code": "..."}
}
```

`config` of set-A runs also records `esp_shape` (the wire shape) and `esp_aes_bits`
(the key size drawn for the tunnel).

- `timing_valid` is true only for a run of a timing-sensitive stage (`timed`: traffic,
  anchor, mixtures, chat, whatsapp, realism, public) captured alone on its machine
  (concurrency 1, no overlapping run). Edge, handshake and short runs are never
  timing-valid. The P0 traffic runs predate the field; the manifest annotates them
  `timing_valid: false` (3 parallel labs, section 12).
- After P0, `order` is the run's position in its slice's seeded order, and
  `plan.plan_sha` fingerprints the tier's plan: every slice of a tier must share it.
  `machine` names the environment, account and codespace (a batch started over ssh
  reads them from the codespace's env file). `observed.blocked` lists apps that
  reported a block (YouTube), `notes.dns` the resolvers of an internet run.
- The manifest holds one line per attempt, plus annotation lines written by
  `tools/annotate.py` (`{"annotation": {...}, "run_id", "tier", "stage", "reason",
  "ts"}`). An annotation never edits an attempt: readers merge it into its run's latest
  attempt recorded before it, and a later attempt stands on its own.

- `split` is assigned deterministically, never across a tunnel:
  - **Tunnels** (traffic, short and the other traffic-like stages): **25% test** per tier
    and stage, stratified by (mode, ESP wire shape). With the 32 set-A tunnels that is
    exactly one test tunnel per shape × mode pair (8 test tunnels, so 8 test runs per
    app). Inside a pair, family and NAT-T rotate: the two modes of a shape get opposite
    family and NAT-T, and every (family, NAT-T) combination is used equally. After P0, a
    stage with fewer test tunnels than (mode, shape) strata (the 8-config P1 stages give
    2) spreads them: modes alternate and shapes rotate per stage, so both modes reach
    test. All runs of a tunnel share its split, so train and test never share a tunnel's
    SAs, SPIs or keys.
  - **Handshake and edge runs**: 20% test per run, stratified by scenario, lowest hash.
  Never split windows or packets of one run across train and test.
- `expected` comes from the design. `observed` comes from charon logs and tshark on the
  capture (for example `isakmp.exchtype`, `isakmp.notify.msgtype`, ESP counts).

---

## 5. Experiment design

### Key idea: split the matrix

Different settings affect different parts of the traffic:

- **Mode, ESP cipher/integrity, outer IP family, and NAT-T** change ESP packet sizes, so
  they matter for traffic and config inference.
- **DH group, PFS, IKE version, and auth method** only change IKE and rekey messages.

Crossing everything with every app would cost hundreds of hours. Instead:

- **Set A (traffic):** full cross of the size-relevant settings, with every app.
- **Set B (handshake):** full cross of the IKE-relevant settings, with light traffic and
  forced rekeys.
- In set A, sample DH/PFS/auth randomly from strong values (seeded, recorded) for free
  diversity.

### Set A: size-relevant configs (32)

| Setting | Values |
|---|---|
| mode | tunnel, transport |
| esp (wire shape) | aes gcm16, aes-sha1, aes-sha256, aes-sha384 |
| outer_family | v4, v6 |
| encap (NAT-T) | off, on (`encap = yes`) |

The AES key size is invisible in ESP (same IV, ICV and block padding), so it is not
crossed: aes128 or aes256 is drawn per tunnel from the seed and recorded as
`config.esp_aes_bits`.

**Tunnel reuse.** The runs of one set-A config (one per app, or per combo in P1) share
one tunnel: it comes up once and each app still gets its own run and its own capture.
The group's first run (a seeded random app) is `before_tunnel` and captures the IKE
setup; the others are `mid_stream`: the capture starts on the established tunnel, so it
holds no IKE and ESP sequence numbers continue from the earlier runs. The overall
`mid_stream` share of traffic runs must stay at or above 15%. If a lab loses a tunnel
(resume, crash, another lab taking the group), it is rebuilt outside any capture.

### Set B: handshake configs (20)

| Setting | Values |
|---|---|
| dh | modp1024, modp2048, ecp256, ecp384, curve25519 |
| pfs | on (DH group appended to `esp_proposals`), off |
| auth | psk, cert (alternate RSA and ECDSA across reps) |

- IKEv2 only in set B. IKEv1 is covered in the edge cases.
- Use short lifetimes so rekeys happen inside the capture: child `rekey_time` 40–60 s,
  IKE `rekey_time` 90–120 s (randomized within range).
- Traffic is ping plus a small web loop. Capture 150 s.

PFS in strongSwan means a DH group in `esp_proposals`. The first CHILD_SA (created in
IKE_AUTH) never has its own DH exchange, so PFS is only visible in CREATE_CHILD_SA
rekeys. Set B must therefore **observe at least one CHILD rekey per run**, or the run is
invalid.

### App classes (live generators in `gen/`)

| class | generator | notes |
|---|---|---|
| voip | baresip or pjsua calling Asterisk | alternate G.711 (20 ms ptime) and Opus; random call lengths |
| video | Playwright + Chromium playing HLS (hls.js) from nginx | open-licence videos (Big Buck Bunny, Sintel) at 3+ bitrate ladders so ABR behaviour is real. **Never** use yt-dlp, which looks like bulk download |
| web | Playwright visiting mirrored sites, random think times 2–15 s | a mirror set of at least 30 pages of varied weight |
| email | swaks SMTP with STARTTLS + Python imaplib fetches | random attachment sizes 0–5 MB |
| icmp | ping with varied intervals (0.2–1 s) and sizes | |
| bulk | scp / rsync / curl of 10–200 MB files | some runs rate-limited |
| chat | (a) live: XMPP bot pair via prosody; (b) replay: WhatsApp pcaps from `dataset/external/whatsapp/` | see below |

**WhatsApp** cannot run in the lab. The user captures it on an Android test phone with
PCAPdroid and drops the pcaps into `dataset/external/whatsapp/`. To replay:

1. Split each pcap by direction.
2. Rewrite IPs and MACs with `tcprewrite`.
3. Replay client→server from `host_a` and server→client from `host_b` at the same
   moment with `tcpreplay`, preserving timing.
4. Mark `replayed: true`.

If the folder is empty, skip those runs and report the gap in `coverage.md`. **Never
synthesize fake WhatsApp traffic.**

**WhatsApp source (owner decision, 2026-09-28).** Instead of phone captures, the replay
uses two public CC BY 4.0 datasets of the ITC lab, University of Tehran (their packet
timestamps date Blend-60 to November and December 2021 and Audio-5 to March 2023):
- ITC-Net-Blend-60, the WhatsApp Messenger archive of all five scenarios (Mendeley: A
  10.17632/ssv23kfcgs.3, B 10.17632/3zggb53m4x.3, C 10.17632/gp8r347j38.3, D
  10.17632/mcmf627yh5.3, E 10.17632/gdtnnfyr7s.3): 22 files, 2.6 h.
- ITC-Net-Audio-5, the WhatsApp voice-call files (figshare
  10.6084/m9.figshare.24721035.v2): 100 files, 6.1 h.

`tools/whatsapp_prep.py` labels and cuts them. A sustained UDP media flow (at least 20 s
at 20 packets/s or more: UDP 3478 relays or peer to peer) is a call, labelled **voip**;
the rest of a Blend-60 file, 5 s away from any call, is messaging and media, labelled
**chat**; the call setup and teardown of an Audio-5 file are excluded. Each segment is
cut into 80 s chunks (a 90 s run leaves about 85 s for the replay after the tunnel setup,
so a chunk replays whole); a chunk under 30 s or with fewer than 150 packets is excluded.
Every source is Ethernet, so no link-type conversion is needed; the replay rewrites
addresses and MACs per run. Result: 59 chat chunks (1.27 h, 17 Blend-60 files),
43 voip chunks from Blend-60 calls (0.93 h, 10 files) and 274 voip chunks from
Audio-5 (5.37 h, all 100 files); 63 pieces excluded (48 remainders under 30 s,
15 sparse chunks). `dataset/external/whatsapp/manifest.jsonl` lists every chunk (source,
DOI, scenario, device, split, source file, offsets, label, packets, sha256),
`excluded.jsonl` the rest.

*Split by source.* Every chunk of a source file shares its split: Blend-60 scenario B (one
user, one phone, two ISPs) is test, scenarios A, C, D and E train; Audio-5 has no
scenarios, so its files are kept together by capturing device (hotspot address), and the
device 192.168.137.218 (20 of 100 files) is test. A test run replays only test sources.

*Runs.* The 16 planned `whatsapp` runs (no plan change): 8 replay chat chunks and 8 voip
chunks, two of each per wire shape and 2 of each among the 4 test runs
(`plan.replay_labels`). Voip runs alternate between the two datasets, and the runs of one
(label, split) take different source files (16 source files in all), preferring full
80 s chunks. The replay checks each chunk's sha256 first, and every run records
`replayed: true`, `label`, `source` and `replay` (DOI, scenario, device, split, source
file, offsets, chunk, sha256) in its meta.json.

Blend-60 mapping:

| file | split | call (s) | chat chunks | voip chunks | excluded |
|---|---|---|---|---|---|
| A_1 | train | - | 3 | 0 | 0 |
| A_2 | train | 8 to 544 | 0 | 7 | 2 |
| A_3 | train | - | 5 | 0 | 2 |
| A_4 | train | - | 1 | 0 | 4 |
| B_1 | test | 3 to 277 | 0 | 4 | 1 |
| B_2 | test | - | 6 | 0 | 0 |
| B_3 | test | - | 3 | 0 | 0 |
| C_1 | train | 269 to 429 | 3 | 2 | 3 |
| C_2 | train | 171 to 331 | 3 | 2 | 4 |
| C_3 | train | 189 to 429 | 2 | 3 | 3 |
| C_4 | train | - | 7 | 0 | 0 |
| D_1 | train | - | 4 | 0 | 2 |
| D_2 | train | 21 to 661 | 0 | 8 | 3 |
| D_3 | train | 27 to 563 | 0 | 7 | 2 |
| D_4 | train | - | 7 | 0 | 2 |
| D_5 | train | 0 to 235 | 1 | 3 | 1 |
| D_6 | train | 260 to 572 | 3 | 4 | 1 |
| D_7 | train | 14 to 253 | 0 | 3 | 1 |
| D_8 | train | - | 3 | 0 | 1 |
| E_1 | train | - | 3 | 0 | 0 |
| E_2 | train | - | 2 | 0 | 1 |
| E_3 | train | - | 3 | 0 | 2 |

### Per-run randomization (seeded, recorded in meta)

- **netem profile**, drawn uniformly from `netem.yaml`:
  - `lan` (none)
  - `broadband` (20 ms ±5, loss 0.1%)
  - `mobile` (60 ms ±20, loss 1%)
  - `congested` (120 ms ±40, loss 2%, rate 5 mbit)
- **capture_start**: from tunnel reuse (above), not drawn: the first run of a tunnel is
  `before_tunnel`, the rest are `mid_stream`. Handshake runs are always `before_tunnel`.
- **noise** on in 50% of runs.
- DH, PFS, auth, IKE suite and AES key size are drawn per tunnel (one tunnel, one config);
  netem and noise per run.

### Tiers

Run in order. Each tier must pass its coverage check before the next starts.

**P0 (must have; `--dry-run` prints the current estimate per shard)**
- **traffic:** set A × {voip, video, web, email, icmp, bulk} × 1 rep, 90 s each (192 runs
  in 32 tunnel groups)
- **short:** 2 extra short tunnels per set-A config, ping + light web, 120 s, light lane
  (64 tunnels): more tunnels, each with its own IKE setup and its own drawn DH, PFS, auth
  and key size, for the config models
- **handshake:** set B × 3 reps (60 runs)
- **edge:** every P0 edge case × 3 reps

**P1 (strongly wanted; about 5 h serial, `--dry-run` prints it per slice)**

Every P1 traffic run (mixtures, anchor, chat, whatsapp, realism) is captured alone on its
machine (`--labs 1`, never next to another run) and records `timing_valid: true`. P1
edge cases are not timing-sensitive: `timing_valid: false`, and they may share lanes.
- **mixtures:** 10 combos × 8 set-A configs (`a8`: one per wire shape × mode; the two
  modes of a shape get opposite family and NAT-T, and each (family, NAT-T) is used
  twice), 90 s: 8 runs per combo.
  - Stagger app start and stop randomly so each run contains pure and mixed segments.
  - Combos: voip+video, voip+web, video+web, web+email, voip+bulk, video+bulk,
    icmp+web, chat+web, email+bulk, voip+video+web.
- **anchor:** the six single apps (voip, video, web, email, icmp, bulk) on the same 8
  configs, 60 s, validated like P0 traffic: timing-valid references, since the P0
  traffic runs were captured with 3 parallel labs.
- **chat:** live XMPP across set A in both modes (32 runs, 60 s), plus WhatsApp replay ×
  16 configs if pcaps exist (tunnel mode only: tcpreplay injects raw frames, which bypass
  XFRM, so replay can only enter the tunnel from `host_a` through `gw_a`; inner family v4).
- **realism:** tunnel mode to the real internet × 8 configs × 1 rep (8 runs): web on the
  live pages of `lab/sites.txt`, plus a Blender film on YouTube if reachable. YouTube
  often blocks datacenter IPs ("confirm you're not a bot"). A blocked attempt is retried
  like any failed one; the last attempt keeps the run (its web traffic) and records the
  block in `observed.blocked`, reported as a gap. Don't work around it. `host_a`
  resolves through the tunnel with the machine's own upstream resolver (codespaces drop
  queries to public resolvers), and `gw_a` keeps its own LAN out of the 0.0.0.0/0
  tunnel, as strongSwan's bypass-lan would (a main-table rule and a bypass policy), so
  replies and path-MTU ICMP reach `host_a`.
- **edge:** P1 edge cases × 3 reps. e22's big chain (an RSA 4096 certificate under an RSA
  4096 intermediate, from the lab PKI) is on the gateways only during e22 runs, e23 adds
  a second child SA for VoIP (UDP), and e26 replays from the host into the router's
  network namespace (the router image has no tcpreplay) from a fresh capture file (in
  the sticky `/tmp` tcpdump cannot overwrite an earlier run's file, and a stale one
  replays a dead SA's packets, which the responder drops as unknown SPIs instead of
  counting replays). No image changes.
- Only realism runs reach the internet: NAT, the internet DNS and gw_a's LAN bypass are
  set for internet runs and removed by the reset before every other run, which keeps
  P0's lab network (no DNS, lan_a to lan_b selectors) exactly.

**p0s: the P0 traffic runs recaptured serially (owner decision, 2026-09-28)**
- **Runs:** the 192 P0 traffic runs again. Each p0s run is the paired twin of one P0
  traffic run, and records its P0 run_id as `recapture_of` in meta.json.
- **Kept from the twin:**
  - the set-A tunnel config (drawn from P0's seed), app and 90 s duration;
  - the tunnel reuse and app order, so capture_start matches: 32 before_tunnel, 160
    mid_stream;
  - the netem profile and noise;
  - the split: P0's 8 test tunnels, one per wire shape × mode.
- **What differs:** only the run seed (tier seed 26004, recorded) and the capture
  concurrency. `plan.build("p0s")` copies the rest from `plan.build("p0")` (`like: p0`
  in `capture/matrix.yaml`).
- **Not recaptured:** short, handshake and edge runs.
- **Concurrency:** `--labs 1`, so every run is alone on its machine and records
  `timing_valid: true`. P0's traffic runs stay in the dataset, annotated
  `timing_valid: false`. The `p0-data` release is never modified.
- **Keys:** during each capture both gateways' `ip -s xfrm state` is dumped every 10 s
  into `xfrm_<gw>_periodic.txt`, besides the start and end dumps that validation reads,
  so an SA rekeyed away keeps its keys (the phase 5 lesson). Every run from p0s on has
  these files, and `tools/labels.py` reads them.
- **Lab:** exactly as in P1. No offload, network or image changes.
- **Slices:** `plan.deal` into 2 slices of 16 tunnels, in seeded order. Design
  fingerprint `ed9e524368e5e9a7`, plan `6954551793740594`; P1's lines keep their own
  design (merge per tier).

**P2 (only if quota remains)**
- A second rep of P0 traffic with a different seed.
- Replay of public non-VPN pcaps (ISCX, VNAT) from `dataset/external/public/` through set
  A. These are always `replayed: true` and are never used as the only test source.

The quota tip: every teammate's personal account has its own free quota. Split a tier
with `capture/run.py --slice i/n`. P0 dealt units (tunnel groups, single runs)
round-robin in hash order, stratum by stratum (`plan.slice_units`, kept for P0 and the
adversarial tiers). From P1 on, `plan.deal` deals each stratum (stage, edge case),
largest units first, to the least-loaded slice in estimated seconds, so the slices
finish together; among equally loaded slices a tunnel group goes where its config, wire
shape and mode are least represented, so no config is tied to one machine. Replay
strata are dealt last, round-robin, so whether their pcaps exist never moves another
unit. Inside a slice the units run in seeded random order (a group's runs together, in
group order), so run type is not tied to time of capture. All shards pull the same
image digests. Teammates follow
[SHARDS.md](../SHARDS.md): 4-core codespace, GHCR read access, maximum idle timeout,
`--slice i/n`, `--status` must say COMPLETE, then hand back the manifest on a branch and
the captures via `tools/export.py`. Merge with `tools/merge.py`: it rejects (writes
nothing) any shard whose plan, tier seed, design fingerprint or image digests differ,
or that ran on locally built images. run_ids are deterministic, so nothing collides.
The adversarial validation is never sharded.

### Parallel labs

Most of a run's wall time is real-time traffic, not CPU, so several labs run side by
side on one machine (`--labs 3` on 4 cores). One worker process drives each lab and the
workers share a placement state (`capture/placement.py`):

- **heavy** runs (video, web, bulk): at most one at a time on the machine
- **voip** never runs next to a heavy run
- no run starts while the machine's CPU is above ~70%
- a tunnel group stays on the lab holding its tunnel; everything else (email, icmp,
  handshake, edge) is light and fills the other labs
- a timed run (timing-sensitive stage) starts only on an idle machine, and nothing starts
  next to it; after P0 runs start in their slice's seeded order, a timed one holding back
  the runs after it

Every run records `lab_id`, `labs`, concurrency, load, machine and image digests.

**Adversarial validation before P0** (`tools/advval.py`). The same target runs (voip, web,
video on 3 set-A configs × 3 reps) are captured serially (tier `avs`, one lab) and at
full parallelism (tier `avp`, three labs, next to light filler runs), with identical
config, netem and app seed per pair. A LightGBM classifier on outer ESP window features
tries to tell serial from parallel windows, cross-validated with both twins of a pair in
the same fold. Pre-registered rule: proceed only if the out-of-fold AUC is below 0.60 and
not significantly above chance (paired permutation test, p ≥ 0.05). Otherwise lower
concurrency and retest. The result is recorded in `dataset/README.md`. These tiers are
not part of the dataset.

**Result (2026-09-27): failed.** AUC 0.724 (permutation p 0.005); video 0.787, voip
0.678, web 0.696, all driven by inter-arrival times. Capture with `--labs 1`. A retest
at 2 labs would need an interleaved design (serial and parallel batches alternating in
one session) to separate concurrency from drift; until one passes, do not raise it.

---

## 6. Edge cases (`capture/edge.yaml`)

Each case needs:
- a setup method
- an expected observation, checked automatically against the capture
- at least 3 successful reps

A run whose observation doesn't match the expectation is `status: mismatch`. Keep it for
debugging, but don't count it toward coverage.

**P0 edge cases**

| id | scenario | how | expected on the wire |
|---|---|---|---|
| e01 | IKE, no response | gw_b drops its own outgoing UDP 500/4500 (at its egress: the router's tcpdump sees ingress before any forward drop) | repeated IKE_SA_INIT requests, zero responder SPI, no ESP |
| e02 | half handshake (INIT only) | nftables drops IKE_AUTH (exchange type 35 at IKE header byte 18; +4 offset on port 4500) | INIT request+response, IKE_AUTH retransmits, no ESP |
| e03 | no proposal chosen | disjoint proposals | INIT response carries NO_PROPOSAL_CHOSEN, no ESP |
| e04 | wrong DH guess | initiator's first KE group not accepted by responder | INVALID_KE_PAYLOAD, then a second INIT that succeeds |
| e05 | auth failure | mismatched PSK | INIT + IKE_AUTH, no ESP |
| e06 | cookie challenge | `charon.cookie_threshold = 1` on gw_b; half-open IKE_SA_INITs from `noise_a` (curve25519, never completed) first | INIT → COOKIE notify → INIT with cookie |
| e07 | mid-stream only | capture starts after 60 s of traffic | ESP only, first seq far above 1, no IKE |
| e08 | rekey only | capture a window containing a CHILD rekey, no initial setup | CREATE_CHILD_SA + SPI change, no INIT |
| e09 | IKE SA rekey | IKE rekey_time 25 s, so two rekeys fall in the capture (after one rekey the new SPIs are only inside the encrypted payload; the second rekey runs on the new SA, so its SPI shows in a header) | CREATE_CHILD_SA rekeying the IKE SA (new IKE SPIs) |
| e10 | idle tunnel with DPD | no traffic, dpd_delay 10 s | INFORMATIONAL only, no ESP |
| e11 | teardown | `swanctl --terminate` mid-capture | INFORMATIONAL delete, then ESP stops |
| e12 | forced NAT-T | `encap = yes`, short keep-alive, plus a real source NAT on gw_a's egress (strongSwan sends keepalives only when it detects that the *local* host is behind NAT; forced encap alone never does); traffic stops at 25 s so keepalives are due | ESP-in-UDP 4500 with non-ESP marker on IKE, 0xFF keepalives |
| e13 | IKEv1 main mode | version 1 | 6-message main mode + quick mode |
| e14 | IKEv1 aggressive | version 1, `aggressive = yes`, PSK | 3-message aggressive mode, identity in cleartext |
| e15 | weak crypto | 3des-sha1-modp1024 (and md5 if supported) | negotiated weak suite visible in INIT |
| e16 | NULL encryption | esp null-sha256 | ESP with readable plaintext payload |
| e17 | lossy handshake | netem loss 20% during setup | IKE retransmissions, eventual success or failure recorded |
| e18 | multiple tunnels | 3 extra initiators to gw_b; 2 behind one NAT with encap | distinct IKE SPIs, NAT-T source ports, tunnel-grouping ground truth |

**P1 edge cases**

| id | scenario | how | expected |
|---|---|---|---|
| e19 | AH | `ah_proposals = sha256` | IP proto 51, plaintext payload |
| e20 | replay window off | `replay_window = 0` | label-only ground truth (not visible on the wire) |
| e21 | ESN | `-esn` in esp proposal | ESN negotiated (label; low 32-bit seq on wire) |
| e22 | IKE fragmentation | cert auth with a large chain, `fragmentation = force` | IKE fragments in IKE_AUTH |
| e23 | multiple child SAs | two children with different traffic selectors (VoIP ports vs rest) | two SPI pairs under one IKE SA |
| e24 | mixed families | v4 inner over v6 outer, and the reverse | outer and inner families differ |
| e25 | IP fragmentation | large pings exceeding path MTU | fragmented ESP packets |
| e26 | replay attempt | re-inject captured ESP toward gw_b with tcpreplay | duplicate seq numbers; replay counter rises in `ip -s xfrm state` |

Before building e15, e16, e19 and e22, run `swanctl --list-algs`. If an algorithm isn't
supported by this strongSwan build, record it as `unsupported` in coverage. **Do not fake
it.**

---

## 7. Sufficiency targets (`tools/coverage.py` must enforce)

Windows from the same run are correlated, so every target counts **runs**, not just
windows. A two-second window (aligned
to capture start) counts toward an app when the app is active in it; windows that also
carry ESP are recorded separately (`observed.windows_2s.esp_active`).

| what | minimum |
|---|---|
| each single app class (P0) | ≥ 32 ok runs, ≥ 1,400 two-second windows, covering ≥ 90% of set-A configs |
| each single app class (with P2) | ≥ 40 ok runs, ≥ 1,500 two-second windows |
| each set-A config | ≥ 5 ok runs |
| each mixture combo (P1) | ≥ 8 ok runs, ≥ 1 in test |
| each anchor app (P1) | ≥ 8 ok runs (all 8 `a8` configs), ≥ 230 two-second windows, ≥ 2 test runs |
| live chat (P1, 60 s runs) | ≥ 32 ok runs, ≥ 920 two-second windows, ≥ 90% of set-A configs, ≥ 8 test runs |
| realism (P1) | ≥ 8 ok runs (a YouTube block is retried, then recorded as a gap) |
| timing (P1) | every ok P1 traffic run `timing_valid` |
| each set-B combo | ≥ 3 ok runs, each with ≥ 1 observed CHILD rekey |
| each edge case | ≥ 3 ok runs with matching observation |
| mid-stream (ESP-only) captures | ≥ 15% of traffic runs |
| each netem profile | ≥ 15% of runs |
| test split | every app class and edge case present in test, with ≥ 8 test runs per app class |
| each set-A config (P0) | ≥ 3 ok tunnels (its traffic tunnel + 2 short tunnels) |

The P1 window minimums keep P0's share (1,400 of the 32 × 45 windows a set of 90 s runs
can give) for 60 s runs: 230 of 8 × 30, and 930 of 32 × 30 for chat, lowered to 920 (owner
decision, 2026-09-28): the 32 live chat runs gave 929, because each run brings up its own
tunnel and that IKE setup takes the start of its 60 s capture, by design. The chat class
(live chat and the WhatsApp chat replays) has 1,229.

`coverage.py`:
- prints a table of target vs actual
- lists the exact missing runs
- writes its tier's section of `coverage.md` (`--tier <t>`; the other sections are kept)
- exits non-zero if a target of the given tier is unmet (without `--tier`: any P0 target)

After each tier, run `capture/run.py --fill-gaps` to re-queue only what's missing.

---

## 8. Validation and labels

**Per-run validation (automatic, after every run).** A failing run is retried up to twice,
then marked `failed` with the reason. Checks:
- generator exited cleanly
- charon state matches `expected`
- ESP count above a threshold for traffic runs
- inner capture non-empty
- expected notifies present for edge cases
- checksums recorded

**Per-packet labels (`tools/labels.py`; method A, owner decision 2026-09-28).**
- Each ESP packet is labelled from its own decrypted header. The captured start of its
  payload (outer captures are cut at 128 bytes) is decrypted with the run's SA keys from
  `xfrm_*.txt`, and the inner header it starts with names the flow and app. Tunnel mode:
  the inner IP header and ports. Transport mode: the ports, the outer addresses, and the
  protocol from the ESP trailer when captured, else from the paired inner packet or the
  inner capture's flows.
- **The keys only build labels. They are never model inputs:** no key, plaintext or
  decrypted field is a feature.
- Each ESP packet is paired with the inner packet whose header bytes equal its decrypted
  ones (TTL / hop limit and the IPv4 checksum masked: the gateway rewrites them), first
  in a time window per direction. A segment of a segmentation-offload super-packet (the
  inner capture on the sending host sees the super-packet) is labelled but not paired.
- Fallbacks, flagged per packet in `label_source`:
  - `prefix`: the captured plaintext ends before the inner ports (IPv6 in IPv6 with a CBC
    cipher keeps 32 bytes). The flow is that of the inner packet paired by those bytes,
    or of the one inner flow with the same flow label and addresses.
  - `length`: nothing decrypts. The P0 method applies: exact expected length, order,
    time window.
- Fragmented ESP is not labelled: no fragment is a whole ESP packet. This covers IPv4
  fragments of an ESP packet and IPv6 fragment headers (e25 by design; replayed
  1500-byte packets).
- Report per run the labelled share (target ≥ 98% on `lan` runs; runs below 90% are
  flagged, not silently used), the shares by source and the paired share. Report per
  config how often the inner ports were in the captured plaintext.
- Output: `labels/<tier>/<run_id>/labels.parquet`, never inside run folders or
  archives, backed up as draft releases `<tier>-labels`. Columns: `ts`, `kind`, `dir`,
  `len`, `spi`, `seq`, `matched` (labelled), `label_source`, `ports_recovered`, `paired`,
  `inner_ts`, `inner_len`, `proto`, `flow`, `app`.

**Decryption spot-check (`tools/decrypt_check.py`).** Samples: 5 seeded runs per tier
covering both modes and both outer families, then GCM and CBC, plus 2 WhatsApp runs.
Per run, tshark decrypts an even sample of 300 labelled ESP packets with the keys from
`xfrm_*.txt`. tshark refuses truncated ESP, so it reads the sampled frames zero-padded
to their wire length, and only the captured plaintext is used. Checks per packet:
- the app named by tshark's plaintext equals the label's app (an app error otherwise;
  unverifiable when the plaintext ends before the ports);
- a paired inner packet equals the plaintext;
- tshark agrees with `labels.py`'s own decryption.

---

## 9. Phases for Claude Code

Do these in order. Don't start a phase until the previous one passes its acceptance
check. Report results to the user at each checkpoint.

**Phase 0: preflight** (`lab/preflight.py`). Check:
- Docker-in-Docker works and privileged sibling containers start
- `ip xfrm state` works inside a gateway container
- veth creation, IPv6 forwarding, netem, and NFLOG with the policy match all work
- a minimal strongSwan tunnel passes ping, and ESP is seen by tcpdump on the router

Write the results to `dataset/README.md` under "environment".
- **If kernel XFRM is unavailable**, switch strongSwan to the `kernel-libipsec` plugin
  (`/dev/net/tun`), set `ipsec_backend: libipsec`, and list any algorithms it can't do.
- **If netem is unavailable**, record it; all runs become `lan`; tell the user this is a
  dataset weakness.

**Phase 1: lab.** Build `compose.yaml`, the images, and the swanctl templates. Acceptance:
- one set-A config per mode and per family establishes and passes traffic
- `--dry-run` prints the full plan with a time estimate

**Phase 2: generators.** Build one module per class. Each has
`start(duration, seed)` → schedule entries. Acceptance: each class produces
recognisable traffic in a 30 s smoke run, verified by inner capture stats.

**Phase 3: orchestrator.** `capture/run.py --tier p0 [--scenario ...] [--resume]
[--fill-gaps] [--dry-run]`. Acceptance:
- 10 mixed runs complete end to end with valid meta
- killing the process mid-batch and resuming skips completed runs

**Phase 3b: parallel labs.** `--labs n`, `--slice i/n`, tunnel reuse, images pinned on
ghcr. Acceptance:
- several labs up side by side with identical addresses, and no traffic crossing labs
- a tunnel group and light runs complete across 3 labs under the placement rules,
  with lab_id, concurrency, load, machine and image digests in every meta.json
- `--dry-run` prints wall-clock, core-hours and storage per shard
- the adversarial validation passes (section 5); only then may P0 use `--labs 3`

**Phase 4: P0 capture.** Done 2026-09-27 (section 12). Only with the user's go-ahead on the time estimate. Run with
`--labs 1` (parallel labs failed the validation) on 4-core codespaces, split with `--slice i/n` across teammates if wanted,
merge with `tools/merge.py`. Then `coverage.py` must pass P0.

**Phase 5: labels + spot-check.**

**Phase 6: P1, then P2 if quota allows.** P1 done 2026-09-27 (section 12). Then `export.py` and the datasheet.

---

## 10. Conventions

- **Python style:** short lowercase names, no capitals in identifiers, no semicolon-stacked
  one-liners, minimal data structures (plain dicts and lists, no class hierarchies unless
  clearly needed). Compact and readable.
- **Determinism:** one global seed per tier, recorded. The same seed and config produce
  the same plan.
- **Integrity:** never invent, pad, or relabel data to hit a target. A visible gap in
  `coverage.md` is always better than a fake run. Never mark a run `ok` without validation
  passing.
- **Honesty in the datasheet.** `dataset/README.md` must state:
  - lab vs internet vs replayed proportions
  - backend (kernel or libipsec)
  - which algorithms were unsupported
  - netem availability
  - known limitations (virtual network, self-hosted services, replayed traffic isn't
    stateful)
- **Scope:** capture only lab traffic and the user's own test-device traffic. No third-party
  or personal data. WhatsApp replay uses the public ITC captures instead (owner decision
  2026-09-28, CC BY 4.0, attributed; section 5).
- **Lab keys** are throwaway test credentials stored only for ground truth. Never reuse them
  anywhere else.
- **Storage:** check `du -sh dataset/raw` after every batch. Warn the user when the
  codespace disk passes 10 GB, and suggest exporting and pruning exported tiers.
---

## 11. Capture runbook (how a tier is captured end to end)

This is the procedure P0 was captured with (P0 used 3 labs; since the adversarial
validation failed, use `--labs 1`), with the P1 changes. Use it for P1 and P2.

### 11.1 Once per account

- Collaborator on `sathwikshetty33/SIH`; the six ghcr packages grant Codespaces read
  access to this repository (README, "Lab images"). Access applies when a codespace
  starts.
- github.com/settings/codespaces: **default idle timeout 240 minutes** (the maximum).
  A shorter timeout stops the codespace mid-batch; P0 lost three resumes to it.
- A **classic** token with the `codespace` scope as the Codespaces secret `GHCR_TOKEN`
  (it also needs `write:packages` to publish images). Never paste tokens into chat or
  files; `lab/images.sh` logs in with a throwaway docker config. With package access
  granted to the account, the codespace's own credential pulls the images.
- One account runs at most **2 codespaces at a time**, all on the same quota.
- A codespace created from an older commit lacks `gh`: `sudo apt-get install -y gh`.
  If its creation-time bootstrap ran before package access existed, it may hold local
  images or media from the old fallback: `bash lab/images.sh pull && bash
  lab/images.sh pull-media`, then check every digest against `lab/images.lock`.

### 11.2 Plan

```bash
python3 capture/run.py --tier p1 --labs 1 --slice 1/2 --dry-run   # every shard of a 2-way split
```

Check: every shard within 15% of the others, both modes and all wire shapes in each,
total core-hours within quota, and the same `plan:` line (seed, design, plan, images) in
every slice. Ask the owner before anything over 2 hours.

### 11.3 Shard codespaces (from the maintainer codespace)

```bash
GH_TOKEN="$GHCR_TOKEN" gh codespace create -R sathwikshetty33/SIH -b main \
  -m standardLinux32gb --devcontainer-path .devcontainer/devcontainer.json \
  --idle-timeout 240m --display-name antar-shard-2
```

The code must be pushed first: a new codespace clones `main`. Bootstrap (postCreate)
installs the tools and pulls the pinned images and media (about 10 minutes). Then:

```bash
GH_TOKEN="$GHCR_TOKEN" gh codespace ssh -c <name> -- 'cd /workspaces/SIH/lab && python3 preflight.py'
GH_TOKEN="$GHCR_TOKEN" gh codespace stop -c <name>        # until the batch starts
```

Remote commands: avoid process patterns that match their own command line
(`pgrep -f "[c]apture/run[.]py"`, not `pkill -f "python3 capture/run.py"`: the ssh
shell's command contains the same text and kills itself). Copy files with
`gh codespace cp -e 'remote:<path>' .` from the maintainer. A shard created since the
P1 handoff has `gh` with its own repository token (release upload and download).
Pull code fixes into a running shard only between runs, and never over its
`dataset/manifest.jsonl`: check out the changed code files, not the manifest.

### 11.4 Launch

Each slice runs detached, so it survives a closed session:

```bash
setsid nohup python3 capture/run.py --tier p1 --labs 1 --slice i/n --yes \
  > dataset/raw/_logs/p1-slice-i.out 2>&1 < /dev/null & disown
```

The coordinator cleans docker (`lab/cleanup.sh`), refuses to start below 5 GB free or
while another batch's workers live, pulls the pinned images, generates the lab keys
once, then starts one worker per lab. Logs: `dataset/raw/_logs/<tier>-<stamp>.log`
(coordinator) and `...-lab<k>.log` (workers).

### 11.5 Monitor and handle interruptions

- Progress: `python3 capture/run.py --tier p1 --slice i/n --status`, or count `: ok`
  lines in the worker logs.
- **Codespace restarted** (idle timeout, host maintenance): run the same launch command
  again. Finished runs are skipped; an interrupted run is redone. Docker's unused image
  store and stale switch namespaces are cleaned up on the way.
- **Stopping a batch**: send SIGTERM to the coordinator; it stops its workers, and
  workers also stop by themselves when their coordinator dies. Check with
  `pgrep -fa "[c]apture/run[.]py"` that no `--worker` process is left before starting
  another batch (the coordinator refuses otherwise).
- **Failed runs** are retried twice at once. Afterwards: `--retry` retries exhausted
  runs, `--fill-gaps` also adds edge reps, `--redo --ids <ids>` recaptures specific ok
  runs (for example after an incident). Never an empty `--ids` (it is rejected).
  Attempts are append-only; the latest ok attempt is the run, and a new attempt
  replaces a run folder only once it is ok.

### 11.6 Finish, back up, merge

1. Every slice: `--status` prints COMPLETE.
2. Every slice: `python3 tools/export.py --tier <t> --slice i/n` (on its own codespace).
3. Draft release per slice, `<t>-slice<i>` (`gh release create <t>-slice<i> --draft`),
   with the archive and its `.sha256`; download again and `sha256sum -c` before
   anything is deleted. Then stop that shard codespace.
4. Merge only the tier's manifest lines of every slice:
   `python3 tools/merge.py --tier <t> dataset/manifest.jsonl <slice manifests>` (it
   rejects a different plan, seed, design or image set, and keeps the other tiers'
   lines as they are; without `--tier` the earlier tiers' older design fingerprint is
   rejected). Run `tools/coverage.py --tier <t>`, update `dataset/README.md`, commit,
   push.
5. The merged tier: unpack every slice archive into `dataset/raw`, `tools/export.py
   --tier <t>`, and upload it as the draft release `<t>-data`, verified the same way.
6. Stop the shard codespaces; delete them once the owner agrees (their data is in the
   releases).

---

## 12. Tier records

### P0 (2026-09-27)

**Result.** 370 of 370 runs ok, every P0 coverage target met, 1.34 GB, backed up in the
draft release `p0-data` (two slice archives, checksums verified after download).
Details in `dataset/README.md` (P0 collection) and `dataset/coverage.md`.

**How.** Two codespaces on the owner's account (the maintainer codespace and
`antar-shard-2`), `--slice 1/2` and `--slice 2/2`, 3 labs each, 13:33 to 16:12 UTC.
Pinned images from ghcr, kernel XFRM, netem available.

**Decisions.**
- Parallel labs: the adversarial validation, finished after P0, **failed** (AUC 0.724,
  p 0.005; video 0.787, voip 0.678, web 0.696; top features are inter-arrival times).
  P0 timing features are biased; sizes and IKE content are not. P1 onward: `--labs 1`.
  Open: recapture the 192 P0 traffic runs serially (about 6 h, 24 core-hours).
- The 192 P0 traffic runs carry a manifest annotation `timing_valid: false`
  (`tools/annotate.py`, appended at the P1 handoff; the attempts and the `p0-data`
  release are unchanged).
- Set A reduced to 32 configs (4 ESP wire shapes; AES key size drawn per tunnel), tunnel
  reuse per config, 2 extra short tunnels per config, 25% test split per tunnel
  stratified by shape x mode (8 test tunnels, 8 test runs per app).
- The adversarial validation ran after P0 (the owner chose not to wait for it); its
  runs are tiers `avs` and `avp` in the manifest, results in `dataset/advval.json`.

**Incidents during P0, and what was done** (every fix is in `main`):

| incident | effect | fix | runs |
|---|---|---|---|
| lab keys generated by 3 workers at once on a fresh codespace | certs not chaining to the ca: AUTHENTICATION_FAILED on shard-2 | keys once, under a lock, verified (34e13e3) | failed runs retried |
| stopping a coordinator left its workers running; a relaunch ran a second batch on the same labs | generators killed, tunnels torn down mid-run | orphaned workers stop, a second batch is refused (e156e38) | 10 ok runs in the overlap recaptured |
| an empty `--ids` selected every run; filters applied before slicing | a runaway redo batch (stopped within minutes); a filtered redo covered half its runs | slice first, reject empty ids (9c4dbec) | - |
| a killed attempt deleted the earlier ok folder | 4 ok runs lost their files | work folder, replaced only when ok (4b482c8) | 4 recaptured |
| email fetch of large messages on the congested profile ran past the run | generator killed (rc 124) | hard deadline per email action (09dae2c) | 3 email runs retried |
| stale switch namespace after a restart | resume failed at lab start | replace stale namespaces (13341f4) | - |
| maintainer codespace idled out 3 times | batch stopped | resumed with the same command; idle timeout raised | none lost |
| two labs claimed the same run (stale done list) | 4 runs captured twice | fresh done list at claim time (after P0) | latest ok kept |

Found before P0 started: the voip generator offered PCMU first while feeding a 48 kHz
source, so opus calls ended at once (384ad8c); DNS lookups hung in the isolated labs
(immediate failure since the veth refactor); Chrome needs ipv6 literals without
brackets in its resolver rules.

**Open items.** Labels and the decryption spot-check: done in phase 5 (2026-09-28, record
below). Serial recapture of the P0 traffic runs.
P1 with `--labs 1` (about 6h48m, 27 core-hours), then P2 if quota remains. Shard-2 ran
Docker 29.8.1, the maintainer codespace 29.8.0 (same kernel and images).

### P1 (2026-09-27)

**Result.** 192 of 192 runs ok (the 16 WhatsApp replay runs skipped: no pcaps), every P1
coverage target met except live chat's two-second windows (929 of 930), 1.32 GB. Backed
up in the draft releases `p1-slice1` and `p1-slice2` (one per slice) and `p1-data` (the
merged tier), each archive with its `.sha256`, verified after download. Details in
`dataset/README.md` (P1 collection) and `dataset/coverage.md` (P1 section).

**How.** A second account (`sathwik34`), which can run 2 codespaces at a time (a third was
refused: "too many codespaces running"): the maintainer codespace ran `--slice 1/2`,
`antar-p1-slice2` ran `--slice 2/2`, both with `--labs 1`, 19:43 to 22:29 UTC, at code
`e58bbf9` (plan `5f0407f286144a36`, design `99777e42f47d44c0`, seed 26002, the P0 image
pins plus the media digest). Every traffic run (168) is `timing_valid`: concurrency 1 on
its machine. The slice codespace was deleted once its release was verified and its
manifest lines were pushed.

**Decisions.**
- The approved plan changes (section 5): mixtures on the 8 `a8` configs at 90 s, the
  anchor set at 60 s, live chat at 60 s (window target 930), realism 8 runs, timing
  validity, the P0 traffic annotation, seeded balanced slices.
- Parts of P1 that had never run were implemented before the capture, without image
  changes: the realism tier (live web and YouTube generators, the machine's resolver,
  gw_a's LAN bypass), e22's big chain, e23's second child SA, e26's replay from the host.
- A YouTube block fails the attempt so the normal retries run; the last attempt keeps the
  run and records the block. All 8 realism runs ended blocked.
- The maintainer codespace had a 30-minute idle timeout, which a running codespace cannot
  change: with the owner's approval a `gh codespace ssh` session from the slice codespace
  kept it active (and would have restarted it and relaunched slice 1).

**Incidents during P1, and what was done** (every fix is in `main`):

| incident | effect | fix | runs |
|---|---|---|---|
| the account had no read access to the ghcr packages; the creation-time bootstrap built the images and crawled the media locally | capture stopped before it began | the owner granted Read; pinned images and media pulled again and checked line by line; a refused pull now fails instead of building (995c0a6) | - |
| realism, e22, e23 and e26 had never run: no youtube generator, no internet DNS or LAN bypass, no big chain, no second child, no tcpreplay in the router image and a stale replay capture | these runs would fail or mismatch on every attempt | implemented and retested before the capture (995c0a6, c438314, d045c68) | - |
| the slice codespace's batch crashed at start: the lab keys were made in a lab container, not yet up on a fresh codespace | no runs | the keys are made in a throwaway gw container (e58bbf9) | - |
| a relaunch guard matched its own ssh command line | nothing launched | check and launch in separate commands | - |
| large lan bulk captures (up to 560 MB raw) took 10 to 15 minutes to analyse | slower slices | none needed (P0: up to 784 s) | - |

**WhatsApp replay (2026-09-28).** The 16 planned `whatsapp` runs, captured on the
maintainer codespace with `--labs 1` from 01:21 to 01:48 UTC: 16/16 ok on the first
attempt (8 chat, 8 voip; 4 test), from the public ITC captures (section 5: sources,
labels, split by source, mapping). Every replay ran whole (`tcpreplay` rc 0) and every
chunk passed its sha256 check. Backed up in the draft release `p1-whatsapp` (the runs,
the chunk manifest and exclusion list, each with its `.sha256`, verified after download).
The runs record code `fcc19e1` (HEAD when they ran); the code that ran was the working
tree committed right after as `f169b05` (unchanged since the batch started). In one run
(sha384, IPv6 outer, NAT-T) gw_b IPv6-fragmented 534 large ESP packets: a replay cannot
adapt packet sizes to the tunnel, and fragmented ESP is counted as `other`. In
`p1-whatsapp-1397c6e5-r1` (IPv4 outer) 806 of the chunk's 1500-byte packets carry no DF
bit, so gw_b split each ESP packet into two IPv4 fragments. The run is valid: host_a
received all 1,145 packets of the chunk. The fragments stay unlabelled (phase 5).

**Open items.** YouTube from a non-datacenter address. The serial recapture of the P0
traffic runs. Resolved on 2026-09-28:
- chat window target 920 (section 7): live chat has 929 and the chat class 1,229;
- labels and the decryption spot-check (phase 5, record below).

### Phase 5: labels (2026-09-28)

**Result.**
- Every ok run of P0 (370), P1 (192) and the WhatsApp replay (16) has per-packet labels
  in `labels/<tier>/`, made with method A (section 8) by `tools/labels.py` at `a534182`.
- Backed up in the draft releases `p0-labels`, `p1-labels` and `p1-whatsapp-labels`,
  each archive with its `.sha256`, verified after download.
- Median labelled share: 100% in every tier. 5th percentile: 98.53% (P0), 99.90% (P1).
- Decryption spot-check with tshark: 12 runs, 0 app errors.
- Tables, validation and flagged runs: `dataset/labels.md`.

**How.**
- On the maintainer codespace (account `sathwik34`) with 4 workers.
- `p0-data` was downloaded and verified with `sha256sum -c` before extracting. The
  release was only read.
- The local P1 and WhatsApp runs matched `p1-data` and `p1-whatsapp` file by file, so
  they were used.
- Labelling took 7 minutes for P0 and 9 for P1.

**Decisions.**
- **First pass with the P0 method.** The labels.py from before 0478d94 (at 4cba50e) and
  the current one gave identical tables on 2 P0 runs, one tunnel and one transport. The
  failures were systematic:
  - Tunnel-mode up direction of TCP senders: host_a's inner capture holds
    segmentation-offload super-packets.
  - Drift between flows of one padded length: some packets had another flow's app.
  - The owner stopped the release and chose method A: each ESP packet is labelled from
    its own decrypted header and paired by content, with length matching only as a
    flagged fallback. The keys are never model inputs.
- **Validation of method A.**
  - (a) Where the old method matched at least 99.9%, old and new agree on the app for at
    least 99.9% of packets in 105 of 106 P0 runs, 62 of 64 P1 runs and 7 of 7 WhatsApp
    runs.
  - Where they differ, tshark confirms the new labels. `p0-video-0533b8ff-r1`: old 93
    of 300 sampled packets wrong, new 0.
  - (b) The spot-check passes.
  - (c) New tables in `dataset/labels.md`.
- **Flagged runs, all explained.**
  - `p0-handshake-fe59fc1f-r2`: rekeyed SAs whose keys the end-of-run xfrm dump no longer
    holds.
  - 3 realism runs and `p1-whatsapp-1397c6e5-r1`: IPv4-fragmented ESP. Its down
    direction was replayed through the tunnel, so the run is valid and needs no
    recapture.
  - By design: e25 (fragmentation) and e19 (AH).
- **Chat window target:** 920 (section 7).
- **Part 3 not started:** the serial P0 recapture, and no offload or other lab change
  (owner decision).

**Incidents during phase 5, and what was done:**

| incident | effect | fix | runs |
|---|---|---|---|
| tshark refuses to decrypt truncated ESP ("ESP truncated"; outer captures are cut at 128 bytes) | the spot-check could not run as specified | tshark reads the sampled frames zero-padded to their wire length, and only the captured plaintext is compared (a534182) | - |
| the P0 method paired offload segments and same-length flows wrongly | wrong or missing labels | method A (a534182) | all |
| the maintainer session stalled after the budget check (02:10 UTC); the keep-alive ended at its 06:18 cap and the codespace stopped for idleness | about 18 core-hours without work | the owner restarted the codespace at 07:51; the phase 5 pipeline ran detached | - |

**Open items.**
- Packets of SAs rekeyed away before the end-of-run xfrm dump have no key and get
  `length` labels: 8.5% of P0's ESP packets, 1,005,578 of 1,005,880 in handshake runs. A capture change
  could dump the xfrm state after each rekey.
- Fragmented ESP stays unlabelled.
- Serial recapture of the P0 traffic runs.

### p0s (2026-09-28)

**Result.**
- 192 of 192 runs ok. Every run is timing-valid (alone on its machine, concurrency 1)
  and the paired twin of its P0 traffic run (section 5).
- Every P0 traffic target is met (`coverage.md`); 1.84 GB.
- Backed up in the draft releases, each with its `.sha256`, verified after download:

| release | archive | sha256 |
|---|---|---|
| `p0s-slice1` | `p0s-slice-1-of-2-f2850ff.tar.zst` | `10200ec461f270b970eafc743d521bb5592cc803ad35c0ed131cb1ea997442d4` |
| `p0s-slice2` | `p0s-slice-2-of-2-f2850ff.tar.zst` | `c2d3cac9e493200a15942066c1a3e4e8d81362272c1ebb1af642e390d34a5b77` |
| `p0s-data` | `p0s-6d1e207.tar.zst` | `8ff1334d5a3237ca86cbffa1e44c2a5b85ea9dccd38d13a99fe8b41f19614efc` |
| `p0s-labels` | `p0s-labels-6d1e207.tar.zst` | `3cf5f41608ade494d1613f83d11346a304fd5fd67ecced74872ad7d8bcedcb1f` |

- **Labels (method A):** median 100% labelled, 5th percentile 99.62%, 0 flagged runs,
  no length fallback. The tshark spot-check found 0 app errors in 5 runs
  (`dataset/labels.md`).

**How.**
- Account `sathwik34`: the maintainer codespace ran `--slice 1/2` (13:45 to 16:34 UTC),
  and a second codespace, `antar-p0s-slice2` (4-core, 240-minute idle timeout), ran
  `--slice 2/2` (13:45 to 17:04 UTC). Both used code `f2850ff`, seed 26004, design
  `ed9e524368e5e9a7`, plan `6954551793740594` and the pinned images; digests and
  preflight were checked on both.
- Slice 2 was exported on its own codespace, copied here (`gh codespace cp -e`, checked
  against its own `.sha256`) and released from here.
- Both slices' lines were merged with `tools/merge.py --tier p0s`: 192 runs, 192 ok.
- The slice-2 codespace was deleted once its release was verified and its lines were
  pushed.
- A self keep-alive (owner-approved, capped) kept the maintainer codespace active.

**Decisions** (owner, 2026-09-28):
- **Twins:** each p0s run copies its P0 twin's tunnel config, app, app order, split,
  netem, noise and capture_start; only the run seed and the concurrency differ.
- **Keys:** dumped every 10 s during each capture.
- **Lab:** unchanged. No offload, network or image changes.
- **The 5 early runs:** captured before the pairing and the key dumps, then redone. Their
  start and end dumps covered every SPI, but 4 of them differed from their twins in
  netem or noise, and the design fingerprint changed. The superseded attempts stay in
  the manifest.

**Incidents during p0s, and what was done:**

| incident | effect | fix | runs |
|---|---|---|---|
| slice 1 was launched before the owner's gates (billing, twin pairing, key dumps, design record) | 5 runs under an earlier design | paused, fixed (`cf2e704`, `f2850ff`), relaunched with `--redo` | 5 redone |
| `images.sh pull-media` over `gh codespace ssh` said "unauthorized": the ssh session has no registry token | none | the creation-time bootstrap had pulled the pinned media. The media matched this codespace file for file, except the bulk payloads, which `media.sh` generates from `/dev/urandom` on every machine | - |
| slice 2's first launch did nothing: `dataset/raw/_logs/` doesn't exist on a fresh codespace | a minute lost | create it, then launch | - |
| lan bulk runs took up to 17 minutes (captures up to 266 MB) | slice 2, which had 6 of the 8 lan bulk runs, finished 30 minutes after slice 1 | none needed. `plan.deal` costs every bulk run the same, whatever its netem | - |
| `merge.py` would reject the tier over the 5 superseded attempts' old design fingerprint | merge blocked | check design and seed on each run's counting attempt; superseded ones are warnings (`ed2482e`) | - |
| `git push` from slice 2's ssh session had no credentials | shard branch not pushed | the manifest and archive were copied here and merged, pushed and released from here | - |
| the disk reached 94% (downloads, exports, verification copies) | labelling was at risk | removed the local copies of archives already in verified releases | - |
| labelling with 4 workers ran out of memory on the lan bulk runs | first labelling attempt aborted | relabelled with 2 workers | - |

**Open items.** The planner's cost model (`plan.deal`) should weigh bulk runs by
netem, so slices balance better.

