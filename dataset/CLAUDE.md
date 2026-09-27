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
- Run every capture batch on a **4-core** machine with **3 parallel labs**
  (`capture/run.py --labs 3`, see "Parallel labs" in section 5). There is no separate
  2-core plan; a 2-core machine is fine for development.
- Budget. The free personal quota is 120 core-hours and 15 GB-month storage.
  - A 4-core machine burns 4 core-hours per hour of runtime.
  - Always print a time estimate (`--dry-run`) before starting a batch. It simulates the
    parallel schedule and prints wall-clock, core-hours and storage per shard.
  - Ask the user before starting anything estimated at more than 2 hours.
- Lab images come from ghcr.io, pinned by digest in `lab/images.lock`
  (`lab/images.sh pull`, with a local build as fallback), so every shard runs identical
  images. The media snapshot (HLS ladders, mirrored pages) is pinned the same way
  (`lab/images.sh pull-media`). Every run records the image digests it used.
- Docker's image store survives a codespace restart only when the codespace runs this
  repo's devcontainer (docker-in-docker keeps `/var/lib/docker` on a volume). Otherwise
  every restart costs an image pull or rebuild.
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
  "lab_id": 0, "labs": 3,
  "concurrency": {"max": 3, "mean": 2.8, "overlapping": [{"lab": 1, "run_id": "...", "cls": "light"}]},
  "load": {"cpu_busy_mean": 41.0, "cpu_busy_max": 63.0, "loadavg_start": [], "loadavg_end": []},
  "machine": {"cores": 4, "mem_gb": 16.4, "cpu": "...", "codespace": "..."},
  "images": {"digest_gw": "ghcr.io/...@sha256:...", "...": "..."}
}
```

`config` of set-A runs also records `esp_shape` (the wire shape) and `esp_aes_bits`
(the key size drawn for the tunnel).

- `split` is assigned deterministically, never across a tunnel:
  - **Tunnels** (traffic, short and the other traffic-like stages): **25% test** per tier
    and stage, stratified by (mode, ESP wire shape). With the 32 set-A tunnels that is
    exactly one test tunnel per shape × mode pair (8 test tunnels, so 8 test runs per
    app). Inside a pair, family and NAT-T rotate: the two modes of a shape get opposite
    family and NAT-T, and every (family, NAT-T) combination is used equally. All runs of
    a tunnel share its split, so train and test never share a tunnel's SAs, SPIs or keys.
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

**P1 (strongly wanted, about 7 h)**
- **mixtures:** 10 combos × 12 set-A configs (both modes, GCM + CBC, v4 + v6), 120 s.
  - Stagger app start and stop randomly so each run contains pure and mixed segments.
  - Combos: voip+video, voip+web, video+web, web+email, voip+bulk, video+bulk,
    icmp+web, chat+web, email+bulk, voip+video+web.
- **chat:** live XMPP across set A in both modes (32 runs), plus WhatsApp replay × 16 configs if pcaps
  exist (tunnel mode only: tcpreplay injects raw frames, which bypass XFRM, so replay can
  only enter the tunnel from `host_a` through `gw_a`; inner family v4).
- **realism:** tunnel mode to the real internet (web, plus video via YouTube if reachable) ×
  8 configs × 2 reps. YouTube often blocks datacenter IPs. If it does, record that and move
  on; don't work around it.
- **edge:** P1 edge cases × 3 reps.

**P2 (only if quota remains)**
- A second rep of P0 traffic with a different seed.
- Replay of public non-VPN pcaps (ISCX, VNAT) from `dataset/external/public/` through set
  A. These are always `replayed: true` and are never used as the only test source.

The quota tip: every teammate's personal account has its own free quota. Split a tier
with `capture/run.py --slice i/n`: units (tunnel groups, single runs) are dealt
round-robin in hash order, stratum by stratum, so each shard gets a balanced mix of
apps, configs and scenarios. All shards pull the same image digests. Teammates follow
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
| each mixture combo | ≥ 8 ok runs |
| each set-B combo | ≥ 3 ok runs, each with ≥ 1 observed CHILD rekey |
| each edge case | ≥ 3 ok runs with matching observation |
| mid-stream (ESP-only) captures | ≥ 15% of traffic runs |
| each netem profile | ≥ 15% of runs |
| test split | every app class and edge case present in test, with ≥ 8 test runs per app class |
| each set-A config (P0) | ≥ 3 ok tunnels (its traffic tunnel + 2 short tunnels) |

`coverage.py`:
- prints a table of target vs actual
- lists the exact missing runs
- writes `coverage.md`
- exits non-zero if P0 targets are unmet

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

**Per-packet labels (`tools/labels.py`, after P0).**
- Match inner plaintext packets to outer ESP packets per direction and SPI, by order and
  time tolerance.
- Each ESP packet gets the app and flow of its inner packet.
- Report the match rate per run. The target is ≥ 98% on `lan` runs.
- Runs below 90% are flagged, not silently used.
- Output: `dataset/raw/<run_id>/labels.parquet`.

**Decryption spot-check.** For 5 random runs per tier, decrypt `outer` with keys from
`xfrm_*.txt` in tshark and confirm the plaintext agrees with `inner`. This proves the
ground truth is trustworthy.

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

**Phase 4: P0 capture.** Only with the user's go-ahead on the time estimate. Run with
`--labs 3` on 4-core codespaces, split with `--slice i/n` across teammates if wanted,
merge with `tools/merge.py`. Then `coverage.py` must pass P0.

**Phase 5: labels + spot-check.**

**Phase 6: P1, then P2 if quota allows.** Then `export.py` and the datasheet.

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
  or personal data. WhatsApp captures come from a dedicated test account.
- **Lab keys** are throwaway test credentials stored only for ground truth. Never reuse them
  anywhere else.
- **Storage:** check `du -sh dataset/raw` after every batch. Warn the user when the
  codespace disk passes 10 GB, and suggest exporting and pruning exported tiers.