# Antardrishti analyzer (phase 2)

The analyzer learns from the finished dataset (`dataset/CLAUDE.md`). It has a feature
pipeline, 17 LightGBM models (3 config, 7 presence, 7 share), an evaluation report and a
command-line tool. There is no capture, no lab and no Docker in this phase. This file is
the analyzer's spec (owner brief, 2026-09-28).

---

## 1. Rules

- **Passive observer.** Features come only from the outer capture. A feature never uses:
  - IP addresses, ports or SPIs;
  - absolute timestamps;
  - inner captures, keys or decrypted fields.

  Addresses, ports and SPIs only group packets into tunnels and SAs and set the direction.
- **Labels** come from `labels/<tier>/<run_id>/labels.parquet` (per packet) and from the
  run's latest ok manifest line (config, apps, split).
- **No ground-truth config as input.** Ground-truth config is only a target for the
  config models. Wherever config enters the traffic models (overhead, context), it is an
  out-of-fold config prediction.
- **Never tune on the test split.** That covers thresholds, calibration, early stopping
  and hyperparameters.
- **Releases are read-only.** Never modify a release.
- **Git holds** code, this file, `REPORT.md` and the report plots. Never commit data,
  features or model files over 50 MB. The model bundle goes to a draft release.
- **Code style:** `dataset/CLAUDE.md` section 10: short lowercase names, no
  semicolon-stacked one-liners, plain dicts and lists.
- **Budget.** On the owner's local machine (2026-09-28) no Codespaces budget applies.
  Ask the owner before any step not covered here that would take over an hour.
- **Commits:** one subject line per phase (`analyzer: ...`), no body.

## 2. Data

| release | archive holds | used for |
|---|---|---|
| `p0-data`, `p0-labels` | P0: 370 runs | config models; the P0 traffic runs only for sizes |
| `p0s-data`, `p0s-labels` | p0s: 192 serial twins of the P0 traffic runs | config and traffic models |
| `p1-data`, `p1-labels` | P1: 192 runs (anchor, mixtures, chat, realism, edge) | config and traffic models |
| `p1-whatsapp`, `p1-whatsapp-labels` | 16 WhatsApp replay runs | config and traffic models |

- **Machine (owner, 2026-09-28):** the owner's WSL2 Ubuntu machine, not a codespace.
  Data lives in `~/antar-data` in the Linux home folder (never under `/mnt/c`), outside
  the repo. No Codespaces budget gates apply. Memory stays under about 75% of what WSL
  has; heavy steps run with `nice -n 10`.
- **Download:** `gh release download` into `~/antar-data/dl`. Check every archive with
  `sha256sum -c` before extracting.
- **Extract** into `~/antar-data/raw/<tier>` and `~/antar-data/labels/<tier>`. The
  local `dataset/raw` is not used.
- **Work run by run:**
  - Decompress a run's captures to a temporary file, parse it, then delete the file.
  - Cache the run's packet table and tunnel rows under `features/` (gitignored).
  - Delete the run's extracted folder once its features are cached.
- **Workers:** 1 for parsing, 2 only when monitoring shows clear headroom. In phase 5,
  4 workers ran out of memory on the lan bulk runs. Runs are processed one at a time.
- **Metadata:** the release names and checksums go into the model bundle.

## 3. Tier usage (strict)

| models | trained and tested on | excluded |
|---|---|---|
| config (suite, mode, PFS) | P0 short tunnels, handshake, edge, and P0 traffic (sizes); p0s; P1 anchor, mixtures, chat, realism, edge; WhatsApp | e15, e16 (3DES, NULL) and e19 (AH): outside the four wire shapes |
| traffic (presence, share) | p0s; P1 anchor, mixtures, chat, realism; WhatsApp | **P0's 192 traffic runs** (parallel capture distorted their timing and volume); P0 short, handshake, edge; P1 edge |

- Sizes are valid in every tier. That is why the P0 traffic runs feed the config models.
  Nothing timing-based comes from P0.
- **Splits.** Each run's recorded split is used: per tunnel for the traffic-like stages,
  per run for handshake and edge.
  - WhatsApp is split by source file. Blend-60 scenario B and the Audio-5 device
    192.168.137.218 are test.
  - p0s uses its P0 twin's split. The manifest matches it: 0 mismatches in split and
    config.
  - All 8 realism runs are test-only, whatever their recorded split. They are reported
    as an out-of-distribution row.
- **CV groups:** a group is the run's config hash, the third field of the run_id.
  - The runs of a reused tunnel share a group.
  - So do a P0 traffic run and its p0s twin, and the reps of a handshake or edge config.
  - A group is never split across folds.
- **"Config" in leave-one-config-out** is (mode, ESP wire shape, outer family, NAT-T).
  - Config models: one fold per combination, 32 set-A combinations.
  - Traffic models: one fold per (mode, wire shape), 8 folds.

## 4. Parser (`analyzer/parse.py`)

- **Input:** one or more pcap or pcapng files, `.zst` allowed.
  - Several files are merged by time.
  - A truncated IKE packet is replaced by its full copy from another file.
    `outer.pcap.zst` is cut at 128 bytes; `ike.pcap.zst` holds full IKE packets.
  - Link types: sll2, sll, ethernet, raw IP, null/loop.
  - Outgoing copies (sll2 packet type 4) are dropped. The router saw every packet twice.
- **Reassembly first:** outer IP fragments are reassembled before anything else.
  - IPv4 uses MF and the offset; IPv6 uses the fragment header.
  - The key is (source, destination, id, protocol).
  - A reassembled packet has the first fragment's time and bytes and the summed length.
- **Classes:**
  - ESP (protocol 50) and AH (51);
  - IKE: UDP 500, or UDP 4500 with the 4-byte non-ESP marker;
  - NAT-T ESP: UDP 4500 without the marker;
  - NAT-T keepalive: UDP 4500 carrying one 0xFF byte;
  - other.
- **Tunnels.** Packets are joined into tunnels by:
  - the outer address pair;
  - the NAT-T ports;
  - the IKE SPIs, which link port 500 to port 4500;
  - the ESP SPIs.

  ESP SAs are grouped into SPI pairs: the two directions of one child SA, paired by first
  appearance.
- **Direction.** Direction is initiator to responder.
  - With IKEv2, the initiator is the sender of messages with the I flag; with IKEv1, the
    sender of the first main or aggressive mode message.
  - With no IKE and NAT-T, the side not on port 4500 is the initiator.
  - Otherwise the lower outer address is the initiator. In the lab this always equals
    gw_a, so the tests cannot measure a wrong fixed-rule direction. The symmetric
    features exist for that case.
- **Handshake status**, per tunnel:
  - `full`: initial exchange (IKE_SA_INIT and IKE_AUTH, or IKEv1 main or aggressive and
    quick mode) with ESP or AH;
  - `rekey-only`: CREATE_CHILD_SA without an initial exchange;
  - `esp-only`: ESP without IKE setup;
  - `failed`: an initial exchange that never produced ESP;
  - `ike-only`: other IKE (for example DPD) with no ESP.
- **IKE_SA_INIT fields:**
  - version;
  - the responder's chosen proposal: encryption and key length, PRF, integrity, DH group;
  - the KE group;
  - cleartext notifies;
  - message sizes and retransmissions.
- **Also recorded:** IKEv1 SA attributes, CREATE_CHILD_SA request and response sizes, and
  the rekey count.

## 5. Features (`analyzer/features.py`)

**Config evidence**, one row per tunnel at the first 50, 200 and 1000 ESP packets and at
all packets. IKE packets up to the last ESP packet used also count. Row features:
- the ESP length is the IP payload after any UDP header;
- number of distinct `len % 16` and `len % 4` residues, the dominant residue and its
  share;
- low percentiles (p1, p5, p10) and the minimum size, per direction;
- outer family and NAT-T;
- the IKE SA proposal and DH group, when seen;
- CREATE_CHILD_SA sizes, split by whether new ESP SPIs follow (child rekey) or not
  (IKE SA rekey);
- the rekey count and the evidence size.

**Window features**, per tunnel and SPI pair, in 2 s windows aligned to the capture start:
- sizes are the ESP length minus the estimated ESP overhead. The overhead comes from
  (suite, mode, family, NAT-T), with the suite and mode from out-of-fold config
  predictions (section 6);
- per direction: packets, bytes, size statistics, a 7-bin size histogram, inter-arrival
  statistics, and bursts (split at gaps over 50 ms);
- balance ratios and symmetric max/min of the per-direction features;
- FFT of packet counts in 5 ms bins: peak frequency, peak ratio, 45-55 Hz energy;
- deltas to the previous and next window;
- inferred config context.

A run's packet table (time relative to the capture start, direction, lengths, SPI pair,
label) is cached. Windows are computed from it once the config predictions exist.

**Window labels** (from `labels.parquet`):
- an app is present if it has at least 5 packets or at least 2% of the window's ESP
  bytes;
- byte share per app over the window's ESP bytes;
- a window with no present app is idle/unknown.
- Single-app runs (anchor, p0s, chat, realism, WhatsApp) give the run's app to every
  window with traffic. Realism's app is web (YouTube was blocked on every run). WhatsApp's
  app is the run's `label`.
- **Decided (section 11):** leaked bulk transfers keep their app, ambiguous HTTPS in
  mixtures is resolved by the schedule or left unknown, realism windows take the run's app.

Features and labels are cached to parquet under `features/`. Row counts are reported per
tier and class.

## 6. Config models (`analyzer/config_models.py`)

The models train on tunnel rows at all four evidence sizes.

| model | target | rows |
|---|---|---|
| suite | multiclass: gcm16, cbc_icv12 (sha1), cbc_icv16 (sha256), cbc_icv24 (sha384) | every tunnel with ESP of the four shapes |
| mode | binary: tunnel vs transport | same |
| PFS | binary | tunnels with at least one observed rekey; otherwise "not determinable" |

- **Out-of-fold predictions:** 5 grouped folds give a prediction for every training
  tunnel. They feed the traffic models, so no traffic row sees a config model trained
  on its own tunnel. Test tunnels get the model trained on all training tunnels.
- **Calibration:** isotonic, fitted on the out-of-fold predictions.
- **Report:**
  - accuracy and macro-F1 by evidence size (50, 200, 1000, all);
  - the confusion matrix;
  - leave-one-config-out;
  - calibration (reliability, ECE).

## 7. Traffic models (`analyzer/traffic_models.py`) and aggregation (`analyzer/aggregate.py`)

- **Apps:** voip, video, web, email, icmp, bulk, chat. Each app has two models.
  - **Presence:** binary, class_weight balanced, early stopping on grouped validation
    (5 grouped folds), isotonic calibration on the out-of-fold predictions, and a
    per-app threshold that maximises F1 on them.
  - **Share:** objective `cross_entropy` on the byte share.
- **Inputs:** window features with out-of-fold config features. Never ground-truth
  config.
- **Aggregation:**
  - zero absent apps' shares and renormalise per window;
  - session byte share, byte-weighted, with "unknown" explicit;
  - active-time share per app;
  - largest-remainder rounding to 100;
  - error bars from the out-of-fold (validation) session share error per app and share
    bucket (0-10, 10-50, 50-100).

## 8. Evaluation (`analyzer/evaluate.py` -> `analyzer/REPORT.md`, plots in `analyzer/report/`)

Everything below uses the held-out test split, reported honestly.
- **Presence:** per-app F1, precision and recall, separately for pure and mixed windows.
  Also by netem profile, mid_stream vs before_tunnel, and leave-one-config-out.
- **Share:** MAE in percentage points per app, bucketed by true share (0-10, 10-50,
  50-100).
- **Calibration:** reliability plots and ECE for the presence and config models.
- **Out of distribution:** realism runs, and WhatsApp by source file, as separate rows.
- **Ablation:** size-only vs full features, with leave-one-tunnel-out CV on the anchor
  set (8 tunnels).
- **Feature importance** for every model.
- **Optional:** a paired P0 vs p0s comparison of volume and timing features, as evidence
  of the capture-contention effect.

## 9. Bundle and CLI (`analyzer/bundle.py`, `analyzer/cli.py`)

- **`models/v1/` holds** (gitignored):
  - LightGBM boosters (`.txt`);
  - calibrators and thresholds as JSON;
  - the feature schema (column order, dtypes);
  - the overhead table;
  - training metadata (data releases and checksums, commit, seeds, library versions);
  - a SHA-256 manifest.
- **Versions** are pinned in `analyzer/requirements.txt`.
- **Command:** `python -m analyzer.cli analyze <pcap> [<pcap> ...] --out result.json`
  runs parse, config inference, windows, presence and share, then aggregation.
- **Output, per tunnel:**
  - handshake status;
  - config facts, each with a confidence and a source: "read from IKE", "observed"
    (outer family, NAT-T) or "inferred";
  - session byte share and active-time share, with error bars;
  - the window timeline and per-window probabilities.
- **Tests** (pytest, `analyzer/tests/`):
  - parser known-answer cases, checked against tshark on dataset runs;
  - bundle loading and schema checks;
  - CLI end to end on 3 test-split runs (one mixture, one WhatsApp, one edge case), with
    output equal to the evaluation's predictions.

  The CLI speed is reported in seconds per minute of traffic.
- **Release:** `models/v1` as the draft release `models-v1`, with its `.sha256`,
  verified by re-download.

## 10. Seeds

Analyzer seed **26006**. It sets the folds, LightGBM and any sampling. The dataset's
seeds are 26001 to 26005.

## 11. Findings and label decisions

Found while reading the labels (2026-09-28). Decided by the owner on 2026-09-28; the
decisions follow each finding.

**Leaked bulk transfers.** An scp or rsync transfer started in one run can continue
through the next runs on the same lab. The ssh connection survives the tunnel being
torn down and set up again. The per-packet labels see it: the decrypted headers show
port 22, so the app is bulk. Runs where such traffic is over 1% of the ESP bytes:

| tier, stage | runs | runs over 1% | worst |
|---|---|---|---|
| p0s | 192 | 15 | `p0s-icmp-27b1109f-r1`: 98.8% bulk |
| P1 anchor | 48 | 3 | `p1-icmp-ca3d545d-r1`: 99.7% bulk |
| P1 mixtures | 80 | 6 | `p1-icmp_web-21e3e3f0-r1`: 98.4% bulk |
| P1 realism | 8 | 1 | `p1-inet-d3d41cac-r1`: 4.7 MB bulk |
| P1 chat, WhatsApp | 48 | 0 | - |

Giving the run's app to every window would label these ssh transfers as icmp, voip,
web and so on.

- **Decision:** single-app runs take the run's app, except packets whose decrypted
  header names another lab app (here always bulk over ssh). Those keep that app, so
  their windows become mixed windows.
- **Report:** per tier and stage, the runs and ESP bytes relabelled this way.
- **P0 vs p0s comparison (optional, section 8):** leaked bytes are excluded from both
  twins. The report notes that the earlier "bulk 2.22x" finding (`dataset/README.md`)
  may be partly due to the leak, not only to concurrency.
- **Root cause:** the scp and rsync generators are not killed at run end, so the ssh
  transfer outlives its run and crosses the next runs' re-established tunnels. The
  capture fix is recorded in `dataset/CLAUDE.md` (section 12, open items), not yet
  implemented.

**QUIC in realism.** The per-packet labels call Google's QUIC flows (UDP 443 with
ephemeral client ports) "voip". The port rule misfires on internet traffic.

- **Decision:** realism windows take the run's app (web); the QUIC-as-voip port rule
  is ignored there. The leaked-bulk exception above still applies.

**Ambiguous HTTPS in mixtures.** In video+web, voip+video+web and video+bulk (curl),
the HTTPS packets are `ambiguous:<apps>`. The schedule's app intervals resolve only
12-17% of those bytes.

- **Decision:** where only one candidate app is active (schedule intervals), the packet
  gets that app. Otherwise the window's presence and share are unknown for the
  candidate apps only; the other apps' labels stay exact.
- Windows unknown for an app are left out of that app's presence and share training and
  evaluation, and out of session-share scoring for that app.
- **Report:** excluded windows per app and per app pair, and `REPORT.md` states the rule.
- **Future fix** (capture, not yet implemented): separate server addresses for video
  and web, recorded in `dataset/CLAUDE.md` (section 12, open items). The rejected
  alternative was flow attribution by the generators' logged events (about 0.5 h).

## 12. Status (checkpoints)

- **Phase A done (2026-09-28).** Parser, features, prep. Every ok run of P0 (370), p0s (192),
  P1 (192) and WhatsApp (16) is cached under `features/<tier>/` (esp packet table and
  tunnel rows). Label rows align with the parsed captures in every run; direction agrees
  with the labels on every packet; all p0s splits and configs equal their P0 twins'. Peak
  prep memory 1.2 GB (one worker). Resume: `python -m analyzer.prep --tier <t>` skips
  cached runs.
- **Phase B done (2026-09-28).** Config models (`python -m analyzer.config_models`, 23 s):
  2,746 evidence rows. Test accuracy with all packets: suite 100%, mode 95.4% (every error
  is an icmp-only tunnel: ping sizes vary, so no fixed-size packet shows the inner header),
  PFS 92.9% (14 test tunnels with a rekey). Out-of-fold config context in
  `features/config_pred.parquet`.
- **Phase C done (2026-09-28).** Traffic models (`python -m analyzer.traffic_models`, 2 min,
  1.0 GB peak): 12,185 windows (p0s, P1 anchor, mixtures, chat, realism, WhatsApp; no P0
  traffic runs). Out-of-fold F1: voip 0.985, icmp 0.926, chat 0.884, email 0.745, web
  0.741, bulk 0.686, video 0.662. Most errors are video, bulk and email confused with each
  other (all TCP downloads from the lab server). Predictions in
  `features/window_pred.parquet`.
- **Phase D done (2026-09-28).** Aggregation and evaluation (`python -m analyzer.evaluate`,
  82 s): `analyzer/REPORT.md` and `analyzer/report/*.png`. Lab test windows: presence macro
  F1 0.851 (voip 0.996, chat 0.951, icmp 0.928, video 0.797, web 0.786, email 0.751, bulk
  0.747); session share MAE 4.4 pp. Out of distribution: realism web read mostly as bulk,
  WhatsApp chat read as email, WhatsApp voip fine.
