# Handoff: P1 on a new account

State on 2026-09-27, when P1 moved to a codespace on a second GitHub account. Details
live in `dataset/CLAUDE.md` (spec; §11 runbook, §12 P0 record), `SHARDS.md` and
`dataset/README.md` (datasheet). This file only holds what those do not make obvious.

## P0: done, do not touch

- 370/370 runs ok, every P0 coverage target met (`dataset/coverage.md`).
- Captures: draft release **`p0-data`** on `sathwikshetty33/SIH`:
  `p0-slice-1-of-2-09dae2c.tar.zst` (sha256 `e90a3592c5124d6e…`) and
  `p0-slice-2-of-2-09dae2c.tar.zst` (sha256 `4a0b5c4327d826c7…`), each with its `.sha256`.
  Verified by re-download.
- `dataset/manifest.jsonl` holds every P0 attempt (both slices merged) plus the
  adversarial-check attempts (tiers `avs`, `avp`). Append only; never edit by hand.
- P0 was captured with 3 parallel labs. That is now known to bias timing (below).
  **Never recapture, modify or re-upload P0 data or the `p0-data` release from the P1
  account.** A serial recapture of P0 traffic is an open item for the owner's account.

## Adversarial check: failed, capture with `--labs 1`

`dataset/advval.json`, datasheet section "Parallel labs: adversarial validation".
Overall AUC 0.724 (permutation p 0.005); video 0.787, voip 0.678, web 0.696. The top
features are all inter-arrival times: parallel labs change packet timing, not sizes.
**P1 runs with `--labs 1`** (the default). Do not raise it without a new, interleaved
validation that passes.

## P1 plan changes (approved by the owner, 2026-09-27)

- Mixtures: 10 combos on 8 configs (`a8`, one per wire shape x mode), 90 s: 8 runs per combo.
- Anchor set: the 6 single apps on the same 8 configs, 60 s, validated like P0 traffic.
- Live chat 60 s (targets lowered to match: 32 runs, 930 windows, then 920: each run's own IKE setup); realism 8 runs.
- Every P1 traffic run is captured alone on its machine and records `timing_valid: true`;
  P1 edge cases record `timing_valid: false`. The 192 P0 traffic runs are annotated
  `timing_valid: false` in the manifest (append-only).
- `--slice i/n` for P1: `plan.deal` balances time, stages and configs; each slice runs in
  seeded random order (a tunnel group's runs stay together).
- P1 at `--labs 1`: 208 runs (16 WhatsApp skipped without pcaps), about 5h serial:
  **2 slices 2h31m each, 21.5 core-hours with setup, 0.66 GB** (`--dry-run`).

## Pinned images (P1 must use exactly these)

```
gw       sha256:6eff96efce030172e400ecddea821a76a181035b059d06b3e4c7649ffa42952a
router   sha256:5e1ea7024cad6c98acbe06047cd762f1cacd498a986e13ae85ecb0c324e97f03
host     sha256:3d8f115020bb0789cd69104626f1d018315c8a490603cf39f3af30da7092928b
services sha256:53d0c2069b4c8112d9eb9c5faddf6c169ab441cf17963801621b90b694dde60b
noise    sha256:e7f822bb5a3524dd48651baf7dce8710911b199cebc96f5f8ce945016ee09e83
media    sha256:1d265727457bdecc1f0c2c4a77e7190096c9153ea3b5b1ff191dc39002322a39
```

All under `ghcr.io/sathwikshetty33/antardrishti-<name>`, as in `lab/images.lock`; every P1
run records all six (`digest_media` from `lab/media/.digest`). Each
package also lists two untagged versions next to the tagged one: its `linux/amd64`
platform manifest and a build-provenance record. They belong to the pinned image; never
delete them.

## Plan identity

- Tier seeds: p0 26001, **p1 26002**, p2 26003. Design fingerprint (`plan.design_sha`):
  P0 `289a5fa670fce4d6`; since the P1 plan changes **`99777e42f47d44c0`**, P1 plan
  fingerprint (`plan.plan_sha`) **`5f0407f286144a36`**. Every P1 run records them;
  `tools/merge.py --tier p1` rejects runs with a different seed, design, plan or images
  (merge per tier: the P0 lines keep their older design).
- Do not edit `capture/matrix.yaml`, `capture/edge.yaml` or `capture/netem.yaml` beyond
  the approved plan changes.
- WhatsApp replay uses the chunks in `dataset/external/whatsapp/`, made by
  `tools/whatsapp_prep.py` from the public ITC captures (never synthesized). Realism
  (internet) runs may find YouTube blocked: record it, move on.

## Open items

1. Phase 5 (labels + decryption spot-check): **done** 2026-09-28 for P0, P1 and the
   WhatsApp replay (method A: labels from each ESP packet's decrypted header). Labels
   are written to `labels/<tier>/`, never into run folders; the P0 runs were only read
   from the verified `p0-data` release. Draft releases `p0-labels`, `p1-labels` and
   `p1-whatsapp-labels`; tables and flagged runs in `dataset/labels.md`, record in §12.
2. Serial recapture of the 192 P0 traffic runs: **done** 2026-09-28 as tier `p0s`
   (account `sathwik34`, 2 slices, `--labs 1`). All 192 ok and timing-valid, each run the
   paired twin of its P0 run (`recapture_of`). Draft releases `p0s-slice1`,
   `p0s-slice2`, `p0s-data` and `p0s-labels`; record in §12.
3. P1: **done** on 2026-09-27 (account `sathwik34`, 2 slices, `--labs 1`): 192/192 runs ok,
   draft releases `p1-slice1`, `p1-slice2`, `p1-data` (verified). Record in `dataset/CLAUDE.md`
   §12. WhatsApp replay done 2026-09-28 from the public ITC captures: 16/16 ok, draft
   release `p1-whatsapp`. Open: YouTube from a non-datacenter address.
4. For P1 mixtures, web and video both use HTTPS to the same server: the label tool marks
   such flows `ambiguous:web+video`. Fine for P1's run-level labels; per-packet app labels
   in mixtures need a per-app client address (not implemented).

## Things a fresh session gets wrong (learned in P0)

- **Idle timeout.** The default 30 minutes stops the codespace mid-batch. Set 240 minutes
  (github.com/settings/codespaces) *before* creating the codespace, or stop and start it
  once after changing it. Resuming works (same command) but costs minutes each time.
- **Detached batches.** Launch with `setsid nohup … &` (runbook §11.4) so a closed session
  does not kill the batch.
- **One batch per machine.** Stop a batch with SIGTERM to its coordinator, then check
  `pgrep -fa "[c]apture/run[.]py"` shows no `--worker`. Process patterns in ssh or
  `sh -c` commands must be bracketed (`[c]apture`) or they match their own shell.
- **Restarts** leave an unused docker image store and stale namespaces behind; the batch
  cleans them itself. Codespaces secrets added after a codespace started only appear
  after a restart.
- **`--ids` with `--redo`**: always pass explicit ids (an empty list is rejected); a new
  attempt only replaces a run folder once it is ok.
- **Billing numbers** come from github.com/settings/billing/usage (the API needs a token
  with the `user` scope; the P1 token has `read:packages` only, so ask the owner to read
  the page). Storage is reported in GB-months and lags by hours.
- **Draft releases** are visible only to accounts with write access to the repository.
- **Labels.** Pairing inner and outer packets by length fails:
  - host_a's inner capture holds segmentation-offload super-packets;
  - same-length flows get swapped.

  Use `tools/labels.py` (it labels from the decrypted headers). tshark refuses truncated
  ESP, so `tools/decrypt_check.py` pads the sampled frames. xfrm dumps keep only the last
  keys, so packets of rekeyed-away SAs fall back to length labels.
- `gh` (needed for release download and upload) is in the devcontainer since this
  handoff; a codespace created earlier gets it with `bash lab/bootstrap.sh`, or
  `sudo apt-get install -y gh`.
- **P1 account (`sathwik34`).** Its Codespaces secret is named `GHCP_TOKEN` (used as
  `GH_TOKEN` for `gh codespace`); ghcr pulls use the codespace's own credential once
  the account has Read access to the six packages. A codespace created before that
  access got local images and a local media crawl from the old fallback: re-pull with
  `bash lab/images.sh pull && bash lab/images.sh pull-media` and compare RepoDigests
  with `lab/images.lock` line by line. The fallback is gone (a refused pull now fails).
- **Realism** needs the tunnel's DNS through the machine's own resolver (codespaces drop
  queries to 1.1.1.1 / 8.8.8.8) and gw_a's LAN kept out of the 0.0.0.0/0 tunnel (route
  rule + bypass policy in `topo.nat`); without them no page loads. YouTube answers
  datacenter addresses with a bot check: retried like a failure, then recorded on the
  last attempt as `observed.blocked` (a coverage gap), never worked around. Only
  realism runs get internet access; every reset restores P0's lab network.
- **e22** (IKE fragmentation) uses the lab PKI's big chain (RSA 4096 cert under an RSA
  4096 intermediate), installed on the gateways only for e22 runs; **e23** gets its
  second child SA from the `voip_child` setup action. Neither changes an image.
- **e26** (replay attempt) replays from the host into the router's namespace
  (`sudo nsenter`): the pinned router image has no tcpreplay. Its capture file is
  removed first: with `fs.protected_regular` tcpdump cannot overwrite an earlier run's
  file in `/tmp`, and replaying the stale one sends a dead SA's packets
  (`XfrmInNoStates` on gw_b, no replay counted).
