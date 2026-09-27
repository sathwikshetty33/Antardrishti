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
