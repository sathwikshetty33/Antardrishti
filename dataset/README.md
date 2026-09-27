# Antardrishti IPsec dataset

<!-- env:start -->
## Environment

Probed by `lab/preflight.py` on 2026-09-27.

- host kernel: `6.8.0-1064-azure`
- docker: `29.8.0-1`
- strongSwan: `strongSwan swanctl 5.9.13`
- ipsec backend: **kernel**
- netem available: **yes**
- kernel xfrm algorithms not available: none

| check | result | detail |
|---|---|---|
| docker | ok | 29.8.0-1 overlayfs |
| build images | ok |  |
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

**Parallel labs are not yet validated.** Every P0 run was captured with 3 labs on its
machine (mean concurrency 2.93, mean machine CPU 19.7%, highest per-run mean 50%). The
pre-registered adversarial validation (section "Parallel labs" in CLAUDE.md) was paused
at 27/27 serial and 3/91 parallel runs: the owner chose to start P0 without waiting
for it. Until it is completed, treat any effect of parallel labs on timing features as
unmeasured. Every run records `lab_id`, `labs`, concurrency and load, so it can be
controlled for.

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
