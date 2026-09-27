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

P1 at `--labs 1`: about **6h48m wall, 27.2 core-hours, 0.8 GB** (`--dry-run`).

## Pinned images (P1 must use exactly these)

```
gw       sha256:6eff96efce030172e400ecddea821a76a181035b059d06b3e4c7649ffa42952a
router   sha256:5e1ea7024cad6c98acbe06047cd762f1cacd498a986e13ae85ecb0c324e97f03
host     sha256:3d8f115020bb0789cd69104626f1d018315c8a490603cf39f3af30da7092928b
services sha256:53d0c2069b4c8112d9eb9c5faddf6c169ab441cf17963801621b90b694dde60b
noise    sha256:e7f822bb5a3524dd48651baf7dce8710911b199cebc96f5f8ce945016ee09e83
media    sha256:1d265727457bdecc1f0c2c4a77e7190096c9153ea3b5b1ff191dc39002322a39
```

All under `ghcr.io/sathwikshetty33/antardrishti-<name>`, as in `lab/images.lock`. Each
package also lists two untagged versions next to the tagged one: its `linux/amd64`
platform manifest and a build-provenance record. They belong to the pinned image; never
delete them.

## Plan identity

- Tier seeds: p0 26001, **p1 26002**, p2 26003. Design fingerprint (`plan.design_sha`):
  **`289a5fa670fce4d6`**. Every P1 run must record both; `tools/merge.py` rejects runs
  with a different seed, design or images.
- Do not edit `capture/matrix.yaml`, `capture/edge.yaml` or `capture/netem.yaml`.
- WhatsApp replay is skipped unless pcaps are in `dataset/external/whatsapp/` (never
  synthesized). Realism (internet) runs may find YouTube blocked: record it, move on.

## Open items

1. P0 phase 5 (labels + decryption spot-check): tools ready (`tools/labels.py`,
   `tools/decrypt_check.py`), to be run on the owner's account because it writes into
   P0 run folders.
2. Serial recapture of the 192 P0 traffic runs (owner's account, about 24 core-hours).
3. P1 on the new account, `--labs 1`, after the owner approves the dry-run.
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
- `gh` (needed for release download and upload) is in the devcontainer since this
  handoff; a codespace created earlier gets it with `bash lab/bootstrap.sh`, or
  `sudo apt-get install -y gh`.
