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
