# Antardrishti

Phase 1 of an AI-driven IPsec analysis platform (SIH 2026): a lab that builds a
labelled IPsec traffic dataset.

Read before doing anything:
- `dataset/CLAUDE.md`: the specification. §11 is the capture runbook, §12 the P0 and P1 records.
- `HANDOFF.md`: current state and what a fresh session gets wrong.
- `SHARDS.md`: running a slice of a tier; `dataset/README.md`: the datasheet.

Rules that matter most:
- Captures run on a 4-core codespace with `--labs 1` (parallel labs failed validation).
  Timing-sensitive runs (traffic, anchor, mixtures, chat, realism) are captured alone on
  their machine and record `timing_valid`; the P0 traffic runs are annotated
  `timing_valid: false` (append-only manifest annotations, `tools/annotate.py`).
- Images and media come only from the pins in `lab/images.lock`: a refused pull is an
  error, never a local build (check RepoDigests line by line before a batch).
- P1 plan (approved 2026-09-27): mixtures 10 combos x 8 configs (`a8`) at 90 s, an anchor
  set of the 6 single apps on the same configs at 60 s, live chat 60 s, realism 8 runs,
  P1 edges; `--slice i/n` deals balanced slices (`plan.deal`) that run in seeded order.
  Merge a tier with `tools/merge.py --tier <t>` (the design fingerprint changed in P1).
- Never commit raw captures; back them up to a draft release `<tier>-data` (§2).
- Never touch P0 data or the `p0-data` release outside the owner's account.
- Never ask for or paste tokens in chat: Codespaces secrets only.
- Commits: one subject line `area/sub: Capitalized sentence.` (for example
  `capture: Add ...`, `docs: ...`), no body, no co-author trailer. Commit each phase.
- Ask the owner before any batch estimated over 2 hours.
