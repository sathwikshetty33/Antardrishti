# Per-packet labels (phase 5, 2026-09-28)

Every ok run of P0, P1 and the P1 WhatsApp replay has per-packet labels, made by
`tools/labels.py` at `a534182` (method A, owner decision 2026-09-28) on the maintainer
codespace. Inputs:
- P0 from the draft release `p0-data`, verified with `sha256sum -c` before extracting.
- P1 and WhatsApp from local runs, identical file by file to the releases `p1-data` and
  `p1-whatsapp` (both verified).

The labels live in `labels/<tier>/<run_id>/labels.parquet`, never inside run folders or
archives. They are backed up in three draft releases, each with its `.sha256`, verified
after download:

| release | archive | sha256 | runs |
|---|---|---|---|
| `p0-labels` | `p0-labels-a534182.tar.zst` (85.4 MB) | `e33af070de3813b2d199e30c7f8b11bc7d42c61b524aa7ab3ae104baf37d04d4` | 370 |
| `p1-labels` | `p1-labels-a534182.tar.zst` (71.9 MB) | `f4958fa6b8f137a369bdd7b214508200fae20bf88dd538eeb6698150f8a13e91` | 192 |
| `p1-whatsapp-labels` | `p1-whatsapp-labels-a534182.tar.zst` (1.0 MB) | `7ba16b407a67f4bda82c828c4993ce77358c979ef9b34b315a991d256f33eebb` | 16 |

Each archive holds `labels.parquet` per run, `labels.json` (per run stats), `labels.md`
(per run table) and `decrypt_check.json` (the spot-check).

## Method

- **Own header.** Outer captures are cut at 128 bytes. The captured start of each ESP
  packet is decrypted with the run's SA keys (`xfrm_*.txt`: AES-CBC, AES-GCM, 3DES,
  NULL), and the inner header it starts with names the flow and app.
  - Tunnel mode: the inner IP header and ports.
  - Transport mode: the ports and the outer addresses. The protocol comes from the ESP
    trailer when it was captured, else from the paired inner packet or the inner
    capture's flows.
- **The SA keys only build labels. They are never model inputs:** no key, plaintext or
  decrypted field is a feature.
- **Pairing.** Each ESP packet is paired with the inner packet whose header bytes equal
  its decrypted ones (TTL / hop limit and IPv4 checksum masked), first in the time
  window of its direction.
- **Fallbacks,** flagged per packet in `label_source`:
  - `prefix`: the plaintext ends before the ports (IPv6 in IPv6 with CBC keeps 32
    bytes). The flow is that of the inner packet paired by those bytes, or of the one
    inner flow with the same flow label and addresses.
  - `length`: no key. The P0 method applies: exact expected length, order, time window.
- **Fragments.** Fragmented ESP (an IPv4 fragment of an ESP packet, an IPv6 fragment
  header) is not labelled: no fragment is a whole ESP packet.
- **Columns:** `ts`, `kind`, `dir`, `len`, `spi`, `seq`, `matched` (labelled),
  `label_source`, `ports_recovered`, `paired`, `inner_ts`, `inner_len`, `proto`, `flow`,
  `app`.

**Why the method changed.** The first pass used the P0 method (pairing by expected
length, order and time) and hit two systematic faults:
- host_a's inner capture holds segmentation-offload super-packets (up to 41 KB), so most
  uploaded segments in tunnel mode had no same-length inner packet. Up-direction rates
  were 2% to 77%, with 24 P0 runs below 90%.
- Pairing by length drifts between flows of one padded length, so packets inherited
  another flow's app: 31% of the sampled packets in `p0-video-0533b8ff-r1` (validation
  below).

The outer ESP packets are unaffected by either fault.

## Labelled share per tier

"Labelled" = decrypt + prefix + length. "Paired" = with an inner packet (by content or
by length). Unpaired labels (32% of P0's and 34% of P1's ESP packets) are mostly
offload segments, labelled from their own header with no `inner_ts`.

| tier | runs | with ESP | median | 25th pct | 5th pct | min | ESP packets | decrypt | prefix | length | unlabelled | paired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p0 | 370 | 355 | 100.00% | 99.99% | 98.53% | 63.91% | 11,765,072 | 76.35% | 14.48% | 8.55% | 0.61% | 68.41% |
| p1 | 192 | 189 | 100.00% | 100.00% | 99.90% | 20.93% | 11,738,923 | 82.31% | 17.64% | 0.00% | 0.05% | 66.01% |
| p1-whatsapp | 16 | 16 | 100.00% | 100.00% | 17.38% | 17.38% | 73,435 | 97.80% | 0.00% | 0.00% | 2.20% | 97.46% |

P0 by lab concurrency. P0 ran with 3 labs almost throughout, so 1 lab has only 3 runs;
the 5 runs below 98% are the flagged handshake run and 4 runs below 98% on other
profiles:

| labs on the machine | runs with ESP | median labelled | min | below 98% |
|---|---|---|---|---|
| 1 | 3 | 99.38% | 98.53% | 0 |
| 2 | 4 | 100.00% | 100.00% | 0 |
| 3 | 348 | 100.00% | 63.91% | 5 |

## Ports in the captured plaintext and label sources, per config

"Ports in plaintext" is the share of TCP/UDP ESP packets whose own decrypted header held
the inner ports.
- **IPv6 in IPv6 tunnels with CBC:** the ports never fit in the captured plaintext (32
  bytes), so these packets are all `prefix`.
- **Every other config fits the ports.** Lower shares in P0's tunnel configs come from
  the 60 handshake runs. Their SAs are rekeyed during the run and the end-of-run xfrm
  dump keeps only the last keys, so 1.08 M packets of rekeyed-away SAs have no key (the
  `length` share).
- **3DES and NULL** are ICMP-only edge runs.

**p0**

| config (mode, outer/inner, NAT-T, cipher) | runs | ESP packets | ports in plaintext | decrypt | prefix | length | unlabelled | paired |
|---|---|---|---|---|---|---|---|---|
| transport v4/v4 natt=n cbc | 24 | 1,674,313 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 44.03% |
| transport v4/v4 natt=n gcm | 8 | 267,630 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 55.13% |
| transport v4/v4 natt=y cbc | 24 | 507,109 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 66.48% |
| transport v4/v4 natt=y gcm | 8 | 194,680 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 65.75% |
| transport v6/v6 natt=n cbc | 24 | 1,736,741 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 65.38% |
| transport v6/v6 natt=n gcm | 8 | 280,505 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 44.70% |
| transport v6/v6 natt=y cbc | 24 | 653,739 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.70% |
| transport v6/v6 natt=y gcm | 8 | 294,663 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 63.43% |
| tunnel v4/v4 natt=n 3des | 3 | 292 | - | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| tunnel v4/v4 natt=n cbc | 38 | 827,461 | 76.09% | 75.45% | 0.02% | 24.19% | 0.35% | 70.44% |
| tunnel v4/v4 natt=n gcm | 68 | 780,207 | 49.35% | 45.32% | 0.00% | 46.48% | 8.20% | 72.58% |
| tunnel v4/v4 natt=n null | 3 | 348 | - | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| tunnel v4/v4 natt=y cbc | 24 | 644,571 | 100.00% | 99.98% | 0.02% | 0.00% | 0.00% | 62.05% |
| tunnel v4/v4 natt=y gcm | 11 | 192,250 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.60% |
| tunnel v6/v6 natt=n cbc | 40 | 1,147,708 | 0.00% | 0.00% | 78.12% | 21.64% | 0.24% | 84.66% |
| tunnel v6/v6 natt=n gcm | 23 | 1,535,080 | 87.60% | 87.12% | 0.03% | 12.68% | 0.16% | 81.21% |
| tunnel v6/v6 natt=y cbc | 24 | 806,396 | 0.00% | 0.00% | 100.00% | 0.00% | 0.00% | 99.48% |
| tunnel v6/v6 natt=y gcm | 8 | 221,379 | 100.00% | 99.89% | 0.11% | 0.00% | 0.00% | 98.62% |

**p1**

| config (mode, outer/inner, NAT-T, cipher) | runs | ESP packets | ports in plaintext | decrypt | prefix | length | unlabelled | paired |
|---|---|---|---|---|---|---|---|---|
| transport v4/v4 natt=n cbc | 19 | 1,838,514 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.95% |
| transport v4/v4 natt=n gcm | 1 | 153 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 52.94% |
| transport v4/v4 natt=y cbc | 19 | 1,498,702 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 70.11% |
| transport v4/v4 natt=y gcm | 1 | 189 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 51.85% |
| transport v6/v6 natt=n cbc | 19 | 927,556 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 58.10% |
| transport v6/v6 natt=n gcm | 1 | 151 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 47.02% |
| transport v6/v6 natt=y cbc | 3 | 557 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 48.29% |
| transport v6/v6 natt=y gcm | 17 | 3,938,265 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 57.96% |
| tunnel v4/v4 natt=n cbc | 6 | 43,687 | 100.00% | 94.06% | 0.00% | 0.00% | 5.94% | 63.26% |
| tunnel v4/v4 natt=n gcm | 39 | 696,626 | 100.00% | 99.54% | 0.04% | 0.03% | 0.39% | 58.97% |
| tunnel v4/v4 natt=y cbc | 19 | 658,643 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 58.45% |
| tunnel v4/v4 natt=y gcm | 1 | 180 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 50.00% |
| tunnel v4/v6 natt=n gcm | 1 | 106 | - | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| tunnel v6/v4 natt=n cbc | 3 | 49,488 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 81.43% |
| tunnel v6/v4 natt=n gcm | 3 | 14,956 | 100.00% | 99.98% | 0.02% | 0.00% | 0.00% | 69.25% |
| tunnel v6/v6 natt=n cbc | 19 | 618,554 | 0.00% | 0.00% | 100.00% | 0.00% | 0.00% | 97.88% |
| tunnel v6/v6 natt=n gcm | 1 | 173 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| tunnel v6/v6 natt=y cbc | 19 | 1,452,277 | 0.00% | 0.00% | 100.00% | 0.00% | 0.00% | 95.39% |
| tunnel v6/v6 natt=y gcm | 1 | 146 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |

**p1-whatsapp**

| config (mode, outer/inner, NAT-T, cipher) | runs | ESP packets | ports in plaintext | decrypt | prefix | length | unlabelled | paired |
|---|---|---|---|---|---|---|---|---|
| tunnel v4/v4 natt=n cbc | 3 | 4,876 | 100.00% | 66.94% | 0.00% | 0.00% | 33.06% | 66.37% |
| tunnel v4/v4 natt=n gcm | 1 | 7,253 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 99.94% |
| tunnel v4/v4 natt=y cbc | 3 | 5,596 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 99.20% |
| tunnel v4/v4 natt=y gcm | 1 | 3,024 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 98.68% |
| tunnel v6/v4 natt=n cbc | 3 | 41,435 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 99.68% |
| tunnel v6/v4 natt=n gcm | 1 | 2,428 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| tunnel v6/v4 natt=y cbc | 3 | 6,340 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 99.97% |
| tunnel v6/v4 natt=y gcm | 1 | 2,483 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 100.00% |

`prefix` labels: 89.6% of P0's and 96.1% of P1's were paired by the decrypted bytes; the
rest came from the flow label alone.

## Validation

**(a) Old and new labels where the old method matched about 100%** (old labelled share
at least 99.9%):

| tier | runs (old match >= 99.9%) | ESP packets compared | same app | same flow | lowest run (same app) |
|---|---|---|---|---|---|
| p0 | 106 | 3,557,142 | 98.40% | 95.37% | p0-video-0533b8ff-r1 70.36% |
| p1 | 64 | 813,241 | 99.49% | 99.47% | p1-email_bulk-fc1e46cd-r1 97.36% |
| p1-whatsapp | 7 | 46,352 | 100.00% | 95.48% | p1-whatsapp-7a7540a0-r1 100.00% |

- **Agreement:** 105 of 106 P0 runs, 62 of 64 P1 runs and all 7 WhatsApp runs agree on
  the app for at least 99.9% of packets.
- **Where they differ,** tshark decrypts the packets and confirms the new labels (300
  sampled packets per run):

| run | same app, old vs new | app errors, new labels | app errors, old labels |
|---|---|---|---|
| `p0-video-0533b8ff-r1` (transport) | 70.36% (bulk and video swapped) | 0 of 300 | 93 of 300 |
| `p1-email_bulk-fc1e46cd-r1` (transport) | 97.36% (email and bulk swapped) | 0 of 300 | 9 of 300 |
| `p1-icmp_web-fc1e46cd-r1` (transport) | 99.67% (5 of 1,505 packets) | 0 of 300 | 0 of 300 (none of the 5 sampled) |

- **Flows:** "same flow" is lower than "same app" (95.4% in P0) because the old pairing
  also drifted inside one app's flows.

**(b) Decryption spot-check** (`tools/decrypt_check.py`, seed 26005):
- **Sample:** 5 traffic runs per tier covering both modes and both outer families (GCM
  and CBC), plus 2 WhatsApp runs, 300 labelled ESP packets each.
- **Method:** tshark decrypts a zero-padded copy of the sampled frames, since it refuses
  truncated ESP; only captured plaintext is compared.
- **Result:** all 12 runs pass.
  - 0 app errors.
  - tshark agrees with `labels.py`'s own decryption on every packet.
  - Every paired inner packet equals its plaintext.
- **Unverifiable:** the IPv6-in-IPv6 CBC runs, whose plaintext stops before the ports.
  Their pairs still agree with tshark.

| tier | run | mode | outer/inner | NAT-T | ESP | checked | app errors | unverifiable | paired equal | tshark = labels.py |
|---|---|---|---|---|---|---|---|---|---|---|
| p0 | `p0-bulk-df1a0b23-r1` | tunnel | v4/v4 | no | aes128gcm16 | 300 | 0 | 0 | 165/165 | 300/300 |
| p0 | `p0-bulk-e42f44e6-r1` | tunnel | v6/v6 | yes | aes256-sha1 | 300 | 0 | 300 | 300/300 | 300/300 |
| p0 | `p0-web-e25294bb-r1` | transport | v4/v4 | no | aes256-sha384 | 300 | 0 | 0 | 116/116 | 300/300 |
| p0 | `p0-video-2857e318-r1` | transport | v6/v6 | no | aes256-sha256 | 300 | 0 | 0 | 232/232 | 300/300 |
| p0 | `p0-web-df1a0b23-r1` | tunnel | v4/v4 | no | aes128gcm16 | 300 | 0 | 0 | 165/165 | 300/300 |
| p1 | `p1-voip-ca3d545d-r1` | tunnel | v4/v4 | no | aes128gcm16 | 300 | 0 | 0 | 142/142 | 300/300 |
| p1 | `p1-icmp_web-08d7b3c9-r1` | tunnel | v6/v6 | yes | aes128-sha256 | 300 | 0 | 300 | 298/298 | 300/300 |
| p1 | `p1-voip_web-21e3e3f0-r1` | transport | v4/v4 | no | aes256-sha256-modp3072 | 300 | 0 | 0 | 283/283 | 300/300 |
| p1 | `p1-chat-c3e64ef9-r1` | transport | v6/v6 | no | aes128gcm16-ecp256 | 151 | 0 | 0 | 71/71 | 151/151 |
| p1 | `p1-video_bulk-58d561c1-r1` | tunnel | v4/v4 | no | aes128gcm16-modp3072 | 300 | 0 | 0 | 155/155 | 300/300 |
| p1-whatsapp | `p1-whatsapp-1397c6e5-r1` | tunnel | v4/v4 | no | aes256-sha384-modp2048 | 300 | 0 | 0 | 300/300 | 300/300 |
| p1-whatsapp | `p1-whatsapp-9af2ee7b-r1` | tunnel | v6/v4 | yes | aes256-sha256-modp3072 | 300 | 0 | 0 | 300/300 | 300/300 |

**(c) New labelled shares:** the tables above.
- P0: every lan run meets 98%. Every run is at 90% or more except
  `p0-handshake-fe59fc1f-r2`; 4 other runs are between 90% and 98% on non-lan profiles.
- P1 and WhatsApp: every run meets the target except the fragmented runs below.

## Flagged runs, with reasons

Each flagged run is below 98% on `lan` or below 90% on any profile.

- **P0 `p0-handshake-fe59fc1f-r2`** (handshake, broadband): 63.91% labelled (up 32.25%,
  down 99.23%).
  - Its SAs were rekeyed during the run, and 166,279 of its 167,128 ESP packets belong to
    SAs whose keys the end-of-run xfrm dump no longer holds.
  - The length fallback labels the down direction. It fails on the up direction's
    offload segments.
- **P1 realism** `p1-inet-57cad5b1-r1` (91.28%), `p1-inet-cd2fa796-r1` (94.09%) and
  `p1-inet-eee460b0-r1` (96.98%), all lan, up 100%.
  - Every unlabelled packet is an IPv4 fragment of an ESP packet: 1,244, 977 and 374
    fragments.
  - Full-size internet packets without DF were fragmented by gw_b after encryption.
- **WhatsApp `p1-whatsapp-1397c6e5-r1`** (lan): 17.38% labelled (up 100%, down 1.10%).
  - 806 packets of the chunk's download are 1500 bytes without DF, so gw_b split each
    ESP packet into two IPv4 fragments (1,612 unlabelled fragments).
  - The down direction was replayed through the tunnel: host_a received all 1,145
    packets of the chunk. The run is valid and needs no recapture or replay fix.
  - A replay cannot adapt packet sizes to the tunnel. In the other 15 runs every packet
    fits, except `p1-whatsapp-da7d0955-r1`'s 534 IPv6 fragments (counted as `other`, not
    ESP).
- **By-design exceptions:**
  - e25 (P1, 3 runs, 20.9% to 23.3%): IP fragmentation, fragmented ESP by design.
  - e19 (P1, 3 runs): AH, no ESP.
- **No ESP by design** (not flagged): P0 e01, e02, e03, e05 and e10 (no tunnel, or an
  idle one; 3 runs each), and P1 e19 (3 runs).

## Limitations

- **No keys after rekeys.** P0 handshake runs lose the keys of rekeyed-away SAs, so 8.5%
  of P0's ESP packets are `length` labels with the P0 method's weaknesses. A later
  capture could dump the xfrm state after each rekey (a capture change, not made).
- **IPv6 in IPv6 with CBC:** `prefix` labels, 14.5% of P0's and 17.6% of P1's ESP
  packets.
- **Unlabelled packets:**
  - P0 0.61%: almost all handshake packets with no key and no length match.
  - P1 0.05%: fragmented ESP (e25, realism).
  - WhatsApp 2.2%: the fragments of `p1-whatsapp-1397c6e5-r1`.
- **Unpaired segments:** offload segments have no identical inner packet, so their
  `inner_ts` is empty; they are still labelled.
- **Ambiguous HTTPS:** HTTPS apps sharing the lab server in one run stay
  `ambiguous:<apps>` (the app is named by port).

## First pass (P0 method), for the record

The first pass was replaced by method A.

| tier | median | 5th pct | min | below 90% | lan below 98% |
|---|---|---|---|---|---|
| P0 | 99.19% | 81.74% | 13.30% | 24 | 12 |
| P1 | 99.65% | 85.19% | 20.93% | 13 | 12 |
| WhatsApp | 99.83% | 17.38% | 17.38% | 1 | 1 |

Before the method change, the pre-0478d94 `labels.py` (at 4cba50e) and the current one
gave identical tables on 2 P0 runs (one tunnel, one transport).

## p0s (2026-09-28)

The 192 p0s runs (the serial recapture of P0's traffic) are labelled the same way,
into `labels/p0s/`.
- **Code:** `tools/labels.py` as of `cf2e704` (it also reads the periodic key dumps),
  HEAD `6d1e207`.
- **Workers:** 2, not 4. The lan bulk runs, with up to 1.8 M ESP packets each, ran out
  of memory with 4.
- **Backup:** the draft release `p0s-labels`: `p0s-labels-6d1e207.tar.zst` (90.0 MB),
  sha256 `3cf5f41608ade494d1613f83d11346a304fd5fd67ecced74872ad7d8bcedcb1f`, verified
  after download.

| tier | runs | with ESP | median | 25th pct | 5th pct | min | ESP packets | decrypt | prefix | length | unlabelled | paired | no key |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p0s | 192 | 192 | 100.00% | 100.00% | 99.62% | 90.65% | 16,014,595 | 91.45% | 8.55% | 0.00% | 0.00% | 69.85% | 29 |

"No key": 29 packets, all in `p0s-icmp-843c14d8-r1`. They are the tails of 29
IPv4-fragmented ESP packets (large pings on the congested profile), so the "SPI" they
show is payload. Every real SPI of every p0s run has its key, from the periodic dumps.
The first fragments are labelled; the 29 tails are that run's only unlabelled packets
(labelled share 90.65%). The run is not flagged: it is at least 90%, and not lan.

Per config:

| config (mode, outer/inner, NAT-T, cipher) | runs | ESP packets | ports in plaintext | decrypt | prefix | length | unlabelled | paired |
|---|---|---|---|---|---|---|---|---|
| transport v4/v4 natt=n cbc | 18 | 2,228,204 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 74.45% |
| transport v4/v4 natt=n gcm | 6 | 293,744 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.77% |
| transport v4/v4 natt=y cbc | 18 | 1,907,750 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 66.89% |
| transport v4/v4 natt=y gcm | 6 | 135,425 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 73.94% |
| transport v6/v6 natt=n cbc | 18 | 3,382,161 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 63.86% |
| transport v6/v6 natt=n gcm | 6 | 1,676,119 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 61.99% |
| transport v6/v6 natt=y cbc | 18 | 420,930 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.03% |
| transport v6/v6 natt=y gcm | 6 | 277,571 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 61.97% |
| tunnel v4/v4 natt=n cbc | 18 | 678,453 | 100.00% | 99.99% | 0.00% | 0.00% | 0.00% | 59.25% |
| tunnel v4/v4 natt=n gcm | 6 | 210,388 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.06% |
| tunnel v4/v4 natt=y cbc | 18 | 1,806,214 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 67.02% |
| tunnel v4/v4 natt=y gcm | 6 | 171,600 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 54.57% |
| tunnel v6/v6 natt=n cbc | 18 | 613,758 | 0.00% | 0.00% | 100.00% | 0.00% | 0.00% | 97.91% |
| tunnel v6/v6 natt=n gcm | 6 | 1,405,843 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 83.97% |
| tunnel v6/v6 natt=y cbc | 18 | 754,662 | 0.00% | 0.00% | 100.00% | 0.00% | 0.00% | 98.17% |
| tunnel v6/v6 natt=y gcm | 6 | 51,773 | 100.00% | 100.00% | 0.00% | 0.00% | 0.00% | 97.47% |

Against the P0 twins (same config and app):

| app | runs | p0s ESP packets | P0 twins' ESP packets | ratio | p0s median labelled | P0 twins' median labelled |
|---|---|---|---|---|---|---|
| voip | 32 | 455,694 | 254,894 | 1.79 | 100.00% | 100.00% |
| video | 32 | 2,725,599 | 2,949,747 | 0.92 | 100.00% | 100.00% |
| web | 32 | 138,557 | 254,839 | 0.54 | 100.00% | 100.00% |
| email | 32 | 588,642 | 607,270 | 0.97 | 100.00% | 100.00% |
| icmp | 32 | 31,114 | 19,947 | 1.56 | 100.00% | 100.00% |
| bulk | 32 | 12,074,989 | 5,449,148 | 2.22 | 100.00% | 100.00% |

**Flagged runs:** none. Every lan run is at least 98% and every run at least 90%.

**Decryption spot-check:** `tools/decrypt_check.py --tier p0s`, seed 26005. It picked
the twins of the P0 sample: both modes, both outer families, GCM and CBC.

| run | mode | outer/inner | NAT-T | ESP | checked | app errors | unverifiable | paired equal | tshark = labels.py |
|---|---|---|---|---|---|---|---|---|---|
| `p0s-bulk-df1a0b23-r1` | tunnel | v4/v4 | no | aes128gcm16 | 300 | 0 | 0 | 153/153 | 300/300 |
| `p0s-bulk-e42f44e6-r1` | tunnel | v6/v6 | yes | aes256-sha1 | 300 | 0 | 300 | 299/299 | 300/300 |
| `p0s-web-e25294bb-r1` | transport | v4/v4 | no | aes256-sha384 | 300 | 0 | 0 | 159/159 | 300/300 |
| `p0s-video-2857e318-r1` | transport | v6/v6 | no | aes256-sha256 | 300 | 0 | 0 | 226/226 | 300/300 |
| `p0s-web-df1a0b23-r1` | tunnel | v4/v4 | no | aes128gcm16 | 300 | 0 | 0 | 160/160 | 300/300 |
