## Findings

**What works.**
- **ESP suite** is read from sizes alone: 100% on the test tunnels with all packets, 98.5%
  from the first 50 ESP packets. The residues of the ESP length mod 16 carry it (each wire
  shape leaves its own residue: 8 + IV + ICV).
- **voip, icmp and chat** presence is near perfect on the lab test windows (F1 0.996, 0.928,
  0.951), with small session-share errors (0.0 to 2.6 pp where the app dominates).
- **Calibration** is good: presence ECE 0.001 to 0.040, suite 0.003, mode 0.038.

**What underperformed, and why.**
- **Video, bulk, email and web** (presence F1 0.75 to 0.80; session share MAE 22 to 28 pp
  when the app dominates) are mostly confused with each other. Inside ESP they are all TCP
  downloads from the same lab server: HLS segments, curl or scp files, IMAP attachments up
  to 5 MB, and mirrored pages. In a 2 s window their size histograms and inter-arrival
  times overlap; what separates them is structure over tens of seconds (segment cadence,
  think time, one long transfer), which the spec's window features only see through the
  neighbouring-window deltas.
  - The netem profile makes this worse: bulk F1 is 0.21 on `mobile` (60 ms, 1% loss) and
    video 0.47 on `congested`, where loss and rate limits flatten the transfers.
  - The ablation shows timing features matter (web 0.60 to 0.81, bulk 0.17 to 0.28 on the
    anchor set), so the P0 traffic runs' biased timing would have hurt.
- **Mixtures** are harder than single apps. Mixed-window F1: video 0.46, web 0.35, icmp
  0.04. A window's features pool every flow of the tunnel, so a small flow (pings, a page
  load) disappears next to a large one. The icmp+web test mixtures include
  `p1-icmp_web-21e3e3f0-r1`, 98% leaked bulk. There the pings sit under a bulk transfer,
  which the model does name (bulk predicted in 55% of those windows).
- **Mode** is 95.4% on the test tunnels, 100% on every stage except icmp-only tunnels. The
  mode shows in sizes only through the inner IP header (20 or 40 bytes), which needs a
  fixed-size reference packet such as a TCP ACK. The ping generator varies its payload
  size, so an icmp-only tunnel has no anchor. Leave one config out drops to 42 to 53% on
  two combinations (transport cbc-sha256 v4, tunnel gcm16 v4, no NAT-T). An unseen
  combination shifts every size, so its offsets are never seen together in training.
- **PFS** is 92.9% on 14 test tunnels. It depends on seeing a child rekey (set B handshake
  runs and a few edge cases); every other tunnel is "not determinable".
- **Out of distribution**:
  - *Realism* (the live internet): web is read mostly as bulk (session web share 7 to
    30% instead of 77 to 100%). Real sites send far more and larger objects than the 38
    mirrored lab pages, and QUIC flows (UDP 443) exist nowhere in the lab training data.
    Presence precision for web stays 1.0; recall is 0.39.
  - *WhatsApp*: voip calls transfer well (F1 0.94; 86% predicted share on both test
    calls). WhatsApp chat does not (F1 0.07): the Blend-60 scenario B test files are read
    as email. Only 92 training windows of WhatsApp chat exist, from other scenarios (A, C,
    D, E), against 317 of live XMPP chat, so the chat model mostly learned XMPP.

**Label decisions in numbers** (details below):
- Leaked bulk kept as bulk: 396 MB in 25 p0s runs over 1%, 95 MB in 3 anchor runs, 4.5 MB in
  one realism run. Leaked HTTPS in single-app runs, left unknown: 120 MB in p0s.
- Ambiguous HTTPS: the schedule resolves 13 to 19% of the ambiguous bytes. 645 video, 421 web
  and 224 bulk windows are unknown for those apps and left out.
- **The leak explains most of the P0 vs p0s volume gap.** With leaked bytes excluded, voip
  goes from 1.79x to 1.01x and icmp from 1.56x to 0.99x. Bulk's 2.22x is genuine (lan bulk at
  full speed alone on the machine), and web's 0.54x becomes 0.73x.
