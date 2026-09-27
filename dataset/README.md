# Antardrishti IPsec dataset

<!-- env:start -->
## Environment

Probed by `lab/preflight.py` on 2026-09-27.

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
| strongswan tunnel v4 (kernel) | ok | backend=kernel: 8 ike + 12 esp packets seen at router |
| strongswan tunnel v6 (kernel) | ok | backend=kernel: 8 ike + 16 esp packets seen at router |
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
