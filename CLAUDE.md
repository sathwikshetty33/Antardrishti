# Antardrishti

Phase 1 of an AI-driven IPsec analysis platform (SIH 2026): a lab that builds a
labelled IPsec traffic dataset.

Read before doing anything:
- `dataset/CLAUDE.md`: the specification. §11 is the capture runbook, §12 the P0 record.
- `HANDOFF.md`: current state and what a fresh session gets wrong.
- `SHARDS.md`: running a slice of a tier; `dataset/README.md`: the datasheet.

Rules that matter most:
- Captures run on a 4-core codespace with `--labs 1` (parallel labs failed validation).
- Never commit raw captures; back them up to a draft release `<tier>-data` (§2).
- Never touch P0 data or the `p0-data` release outside the owner's account.
- Never ask for or paste tokens in chat: Codespaces secrets only.
- Commits: one subject line `area/sub: Capitalized sentence.` (for example
  `capture: Add ...`, `docs: ...`), no body, no co-author trailer. Commit each phase.
- Ask the owner before any batch estimated over 2 hours.
