# Antardrishti IPsec dataset

<!-- env:start -->
## Environment

Probed by `lab/preflight.py` on 2026-09-28.

- host kernel: `6.8.0-1064-azure`
- docker: `29.8.1-1`
- strongSwan: `strongSwan swanctl 5.9.13`
- ipsec backend: **kernel**
- netem available: **yes**
- kernel xfrm algorithms not available: none

| check | result | detail |
|---|---|---|
| docker | ok | 29.8.1-1 overlayfs |
| pinned images | ok | 6 digests of lab/images.lock: gw, router, host, services, noise, media |
| bridge netfilter off | ok | bridge-nf-call-ip(6)tables=0 |
| privileged sibling containers | ok | privileged siblings up, v4+v6 routed through router |
| kernel xfrm | ok | ip xfrm state add/flush works in gateway |
| veth | ok | veth create/delete |
| ipv6 forwarding | ok | router forwards ipv6 |
| netem | ok | delay/jitter/loss/rate |
| nflog policy match | ok | NFLOG + policy match, tcpdump -i nflog:5 |
| nft raw payload match | ok | raw payload match for ike exchange type |
| strongswan tunnel v4 (kernel) | ok | backend=kernel: 8 ike + 20 esp packets seen at router |
| strongswan tunnel v6 (kernel) | ok | backend=kernel: 8 ike + 20 esp packets seen at router |
| swanctl --list-algs | ok | encryption:15, integrity:15, aead:10, hasher:12, prf:10, xof:8, kdf:2, drbg:7, dh:27, rng:3, nonce-gen:1 |
| kernel xfrm algorithms | ok | unsupported: none |
<!-- env:end -->

<!-- notes:start -->
## Notes on collection

- **Replayed chat is tunnel mode only.** WhatsApp (and public pcap) replay injects
  captured frames with `tcpreplay`, and raw frames bypass the kernel's XFRM. Replay can
  therefore only enter IPsec by being forwarded through `gw_a`, i.e. in tunnel mode,
  with IPv4 inner traffic (the captures are IPv4). Replayed runs are marked
  `replayed: true`, are never the only test source, and are not stateful (no real
  endpoints answer them).
- **Live chat (XMPP) runs in both modes.** The live chat class covers tunnel and
  transport mode, both families, with and without NAT-T.
- **Tunnels are reused** within a set-A config: the first run of a tunnel captures its
  IKE setup (`before_tunnel`), later runs start on the established tunnel
  (`mid_stream`). Splits are per tunnel, so train and test never share a tunnel.
- **Timing validity.** A run records `timing_valid: true` only when it belongs to a
  timing-sensitive stage and was captured alone on its machine. Use only those runs for
  inter-arrival and burst-timing features.
- **Realism (internet) runs** leave the lab through the tunnel and `gw_b`'s NAT, and
  resolve names with the capturing machine's own upstream resolver (in codespaces the
  Azure resolver; public resolvers are blocked there). Web visits the live pages of the
  mirror list; YouTube is attempted and, when it answers the datacenter address with a
  bot check, the attempt is retried; the last attempt keeps the run and records the
  block (`observed.blocked`, a coverage gap) instead of working around it. Only realism
  runs reach the internet; all other runs keep the lab without DNS.
<!-- notes:end -->

<!-- p0:start -->
## P0 collection (2026-09-27)

| | |
|---|---|
| ok runs | **370** of 370 planned: 192 traffic (32 tunnels x 6 apps), 64 short tunnels, 60 handshake, 54 edge |
| split | 276 train / 94 test (per tunnel for traffic and short, per run for handshake and edge) |
| origin | 100% lab traffic: no internet, no replay in P0 |
| capture window | 13:33 to 16:12 UTC, 2 codespaces (4 cores each), 3 parallel labs per codespace |
| ipsec | kernel XFRM backend, strongSwan 5.9.13, no unsupported algorithms, netem available |
| images | pinned on ghcr.io (`lab/images.lock`): gw 6eff96ef, router 5e1ea702, host 3d8f1150, services 53d0c206, noise e7f822bb |
| netem | lan 122, broadband 85, mobile 87, congested 76 (all edge runs are lan) |
| capture start | 201 before_tunnel, 169 mid_stream (83% of traffic runs) |
| size | 1.34 GB compressed |
| storage | draft release `p0-data` on this repository: two slice archives + `.sha256` (download: `gh release download p0-data`) |
| coverage | every P0 target in `coverage.md` is met |

**Parallel labs failed the adversarial validation (see below).** Every P0 run was
captured with 3 labs on its machine (mean concurrency 2.93, mean machine CPU 19.7%).
The check, completed after P0, found serial and 3-lab windows distinguishable
(AUC 0.72, p = 0.005), almost entirely through packet inter-arrival times. For P0 this
means: **packet sizes, ESP shapes, IKE content and counts are unaffected; timing
features (inter-arrival statistics, burst timing) of P0 traffic runs are biased by
concurrency and should not be used to train or evaluate timing-based models** until the
traffic runs are recaptured serially (`--labs 1`, about 6 h / 24 core-hours). Every
run records `lab_id`, `labs`, concurrency and load. P1 and later use `--labs 1`. The
manifest annotates the 192 P0 traffic runs `timing_valid: false` (append-only annotation
lines; the attempts and the `p0-data` archives are unchanged).

**Code versions.** The experiment design (`plan.design_sha`) did not change during P0.
The orchestration and one generator were fixed while P0 ran (commits e03bb4b to
09dae2c, recorded per run in `plan.code`); every ok run passed the same validation.
18 runs have more than one ok attempt (recaptures after an incident, or a duplicate
claim); the latest ok attempt is the one in the archive, and all attempts stay in the
manifest.

**Known limitations.** Virtual network (veth, netem) inside one host; self-hosted
services; voip calls an echo service, so the server's audio mirrors the client's; web
uses a fixed mirror of 38 pages; video uses 2 films at 5 bitrates; the 160 mid_stream
traffic runs have their tunnel's IKE setup in another run of the same tunnel (tunnel
reuse), linked by `group`.
<!-- p0:end -->

<!-- p1:start -->
## P1 collection (2026-09-27)

| | |
|---|---|
| ok runs | **208** of 208 planned: 48 anchor (6 single apps x 8 configs), 80 mixtures (10 combos x 8 configs), 32 live chat, 16 WhatsApp replay (8 chat, 8 voip), 8 realism (internet), 24 edge (e19 to e26 x 3) |
| attempts | 224: the 16 extra are realism attempts retried after a YouTube bot check |
| split | 154 train / 54 test (per tunnel for the traffic stages, per run for edge; the WhatsApp chunks also per source file) |
| origin | 184 lab, 8 internet (realism), 16 replayed (WhatsApp) |
| capture window | 19:43 to 22:29 UTC, 2 codespaces of the account `sathwik34` (4 cores each), one lab per machine (`--labs 1`), `--slice 1/2` and `--slice 2/2`, code `e58bbf9`; the WhatsApp replay on 2026-09-28, 01:21 to 01:48 UTC, on the first codespace |
| timing | every traffic run (184: anchor, mixtures, chat, WhatsApp, realism) was captured alone on its machine: `timing_valid` true, concurrency 1 (mean machine CPU 10.7% over the 168 runs of 2026-09-27); the 24 edge runs are `timing_valid` false. The WhatsApp runs' inner timing is that of the original phone networks (see below) |
| ipsec | kernel XFRM backend, strongSwan 5.9.13, no unsupported algorithms, netem available |
| images | the P0 pins from ghcr.io (`lab/images.lock`) and the media snapshot `1d265727`, recorded in every run |
| netem | lan 44, broadband 47, mobile 32, congested 45 (non-edge runs; edge runs are lan) |
| capture start | 56 before_tunnel, 112 mid_stream traffic runs (67%) |
| size | 1.32 GB compressed, plus 0.10 GB of WhatsApp replay |
| storage | draft releases `p1-slice1` and `p1-slice2` (one per slice), `p1-data` (the merged tier of 192 runs) and `p1-whatsapp` (the 16 replay runs, the chunk manifest and exclusion list), each file with its `.sha256`, verified after download |
| coverage | every P1 target in `coverage.md` is met; live chat alone has 929 two-second windows, the chat class (live chat and the WhatsApp chat replays) 1,229 |

**Design.** P1 follows the approved plan changes (`dataset/CLAUDE.md`, section 5): the
mixtures on 8 configs (one per ESP wire shape x mode) at 90 s, an anchor set of the six
single apps on the same 8 configs at 60 s (timing-valid references, since the P0 traffic
runs were captured with 3 parallel labs), live chat at 60 s, 8 realism runs and the P1
edge cases. Each slice ran its share in a seeded random order, so run type is not tied to
time of capture.

**WhatsApp replay (2026-09-28).** The 16 planned runs replay public WhatsApp captures
(ITC-Net-Blend-60 and ITC-Net-Audio-5, CC BY 4.0; attribution below) through the tunnel:
8 replay chat chunks (messaging and media) and 8 voip chunks (calls), 80 s each, every
chunk of a source file in one split (Blend-60 scenario B and one Audio-5 device are
test). Each run records `replayed: true`, `label`, `source` and `replay` (DOI, scenario,
device, split, source file, offsets, chunk sha256, checked before the replay). The
replay keeps the capture's inter-packet timing, so **the WhatsApp runs' timing reflects
the original phone networks** (the ISPs, places and phones of the ITC captures:
Blend-60 in 2021-11 and 2021-12, Audio-5 in 2023-03) under the lab's netem profile, not
a live WhatsApp session. The replay is not stateful (no endpoint answers it) and cannot
adapt packet sizes to the tunnel. In `p1-whatsapp-da7d0955-r1` (sha384, IPv6 outer,
NAT-T, the largest overhead) gw_b IPv6-fragmented 534 large ESP packets, which the ESP
count and the labels miss (fragments count as `other`). In `p1-whatsapp-1397c6e5-r1`
(IPv4 outer, sha384) the chunk's 806 downloaded 1500-byte packets carry no DF bit, so
gw_b split each ESP packet into two IPv4 fragments. They crossed the tunnel (host_a
received every packet of the chunk), but no fragment is a whole ESP packet, so they stay
unlabelled and the run's labelled share is 17%. In the other runs, packets over 1400
bytes fit the tunnel and are labelled.

**Gaps.** *YouTube:* every realism attempt from the codespaces'
datacenter addresses got YouTube's bot check; after the normal retries each realism run
keeps its web traffic and records the block (`observed.blocked`), so the realism runs
hold no YouTube video. *Chat windows:* live chat gave 929 (target 920 since 2026-09-28,
was 930); each chat run is its own tunnel, so its capture starts with the IKE setup and
the chat begins a second or two in.

**Known limitations.** As in P0: virtual network (veth, netem) inside one host,
self-hosted services, a fixed mirror of 38 pages. Anchors are 60 s runs (P0 traffic: 90 s).
Realism runs resolve names with the capturing machine's resolver (the Azure one) through
the tunnel and gw_b's NAT. In mixtures, web and video both use HTTPS to the same lab
server, so per-packet app labels there would be ambiguous (the run-level labels are exact).
<!-- p1:end -->

<!-- labels:start -->
## Per-packet labels (2026-09-28)

Every ok run of P0, P1 and the WhatsApp replay has per-packet labels in
`labels/<tier>/<run_id>/labels.parquet`, backed up in the draft releases `p0-labels`,
`p1-labels` and `p1-whatsapp-labels`. Tables, validation and flagged runs:
`dataset/labels.md`.

| | |
|---|---|
| method | each ESP packet is labelled from its own decrypted header. The captured start of its payload is decrypted with the run's SA keys (outer captures are cut at 128 bytes) and paired with the inner packet by header content. Fallbacks are flagged in `label_source`: `prefix` for IPv6 in IPv6 with CBC, whose 32 captured plaintext bytes end before the ports; `length` when there is no key |
| keys | **the SA keys only build labels; they are never model inputs.** No key, plaintext or decrypted field is a feature |
| labelled share | median 100% in P0, P1 and WhatsApp; 5th percentile 98.53% (P0), 99.90% (P1) |
| label sources | P0: 76.4% decrypt, 14.5% prefix, 8.6% length, 0.6% unlabelled. P1: 82.3%, 17.6%, 0.0%, 0.05%. WhatsApp: 97.8% decrypt, 2.2% unlabelled |
| spot-check | tshark decrypted 300 labelled packets in each of 12 runs (5 per tier and 2 WhatsApp; both modes, both outer families, GCM and CBC): 0 app errors |
| not labelled | fragmented ESP (IPv4 fragments of an ESP packet, IPv6 fragment headers): e25 by design, 3 realism runs, `p1-whatsapp-1397c6e5-r1` |
| limitations | in handshake runs, packets of rekeyed-away SAs have no key (8.5% of P0's ESP packets, `length` labels). Offload segments are labelled but unpaired (no `inner_ts`). HTTPS apps that share the lab server in one run stay `ambiguous:<apps>` |
<!-- labels:end -->

<!-- advval:start -->
## Parallel labs: adversarial validation

Can a model tell traffic captured with one lab on the machine from traffic captured with three labs side by side? The same 27 target runs (voip, web, video on 3 set-A configs x 3 reps) were captured serially (tier `avs`) and at full parallelism (tier `avp`, next to light filler runs), with identical config, netem and app seed per pair. A LightGBM classifier on outer ESP window features (2 s windows, per-direction size and inter-arrival statistics) was cross-validated with both twins of a pair in the same fold.

- pairs: 27, windows: 1674
- out-of-fold AUC: **0.724**

| class | windows | AUC | permutation p | null 95th pct | verdict |
|---|---|---|---|---|---|
| video | 707 | 0.787 | 0.05 | 0.774 | **fail** |
| voip | 732 | 0.678 | 0.045 | 0.649 | **fail** |
| web | 235 | 0.696 | 0.005 | 0.601 | **fail** |

- most informative features (share of gain): up_iat_p50 0.096, down_iat_p10 0.087, up_iat_p90 0.086, down_iat_min 0.081, up_iat_max 0.059, up_iat_p10 0.05
- paired permutation test (200 permutations): p = 0.005, null mean 0.499, null 95th percentile 0.641
- mean concurrency during the parallel target runs: 2.95
- pre-registered rule: pass if auc < 0.6 and permutation p >= 0.05 (overall and per class) -> **failed**: concurrency must be lowered and retested
- caveat: the serial half ran before the parallel half (not interleaved), so slow drift of the host's own load over those hours is confounded with the condition
<!-- advval:end -->

<!-- attribution:start -->
## Third-party data and attribution

The WhatsApp replay runs (P1 stage `whatsapp`) are derived from two public datasets,
used under the Creative Commons Attribution 4.0 International licence (CC BY 4.0,
https://creativecommons.org/licenses/by/4.0/):

- **ITC-Net-Blend-60.** M. Bayat, J. Garshasbi, M. Mehdizadeh, N. Nozari, A. Rezaei Khesal,
  M. Dokhaei and M. Teimouri (ITC Laboratory, University of Tehran), "ITC-Net-Blend-60: A
  Comprehensive Dataset for Robust Network Traffic Classification in Diverse
  Environments", Mendeley Data, 2024. Scenarios A to E: doi:10.17632/ssv23kfcgs.3,
  doi:10.17632/3zggb53m4x.3, doi:10.17632/gp8r347j38.3, doi:10.17632/mcmf627yh5.3,
  doi:10.17632/gdtnnfyr7s.3 (supplementary materials doi:10.17632/4sgt9tjs4w.7);
  described in BMC Research Notes (2024), doi:10.1186/s13104-024-06817-5. Used: the
  WhatsApp Messenger archive of each scenario.
- **ITC-Net-Audio-5.** M. Nikbakht and M. Teimouri (ITC Laboratory, University of
  Tehran), "ITC-Net-Audio-5: An Audio Streaming Dataset for Application Identification in
  Network Traffic Classification", figshare, 2024, doi:10.6084/m9.figshare.24721035.v2;
  described in BMC Research Notes (2024), doi:10.1186/s13104-024-06718-7. Used: the
  WhatsApp voice-call files.

**Changes made.** Only the WhatsApp files were used. Their traffic was labelled (sustained
UDP media flows as voip calls, the rest of a Blend-60 file as chat) and cut into 80 s
chunks, short or sparse pieces excluded; every chunk, its source file and offsets are
listed in `dataset/external/whatsapp/manifest.jsonl` (`tools/whatsapp_prep.py`). Each
replayed chunk had its IP and MAC addresses rewritten to the lab's and was replayed
through the lab's IPsec tunnels, under the lab's netem profiles, and captured again: the
dataset holds those new captures (outer ESP, inner headers), not the original files. The
original authors do not endorse this dataset or its use.

The media served by the lab itself (films, mirrored web pages) carry their own licences,
listed in `lab/ATTRIBUTION.md`.
<!-- attribution:end -->
