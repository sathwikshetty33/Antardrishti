# Antardrishti

*Antardrishti* (Sanskrit: "inner vision"): an AI-driven IPsec VPN analysis platform
for SIH 2026. It infers the IPsec configuration of captured or live traffic, predicts
the traffic type inside ESP and produces a security assessment, without ever
decrypting anything.

This repository is phase 1: the lab that builds the labelled training and testing
dataset. The full specification is [dataset/CLAUDE.md](dataset/CLAUDE.md); the
datasheet is [dataset/README.md](dataset/README.md).

## Layout

- `lab/`: dev lab (strongSwan gateways, router tap, services, noise), preflight, images
- `gen/`: traffic generators, one per app class
- `capture/`: the experiment design and the orchestrator (`run.py`)
- `tools/`: coverage, checks, merge, export, adversarial validation
- `dataset/`: manifest, coverage report, datasheet (raw captures are never committed)

## Quick start (maintainer)

```bash
bash lab/bootstrap.sh                      # tools, pinned images, media
python3 lab/preflight.py                   # what this kernel supports
python3 capture/run.py --tier p1 --labs 1 --dry-run
```

Several teammates can each capture a slice of a tier: see [SHARDS.md](SHARDS.md).

## Lab images on ghcr.io

The lab images and the media snapshot are private packages owned by
`sathwikshetty33` and linked to this repository:
`ghcr.io/sathwikshetty33/antardrishti-{gw,router,host,services,noise,media}`.
Every shard pulls them by the digests pinned in [lab/images.lock](lab/images.lock),
so all shards run identical images (`tools/merge.py` rejects runs that did not).

**Publishing** (maintainer): needs a **classic** personal access token with
`write:packages` in `GHCR_TOKEN` (github.com/settings/tokens, "Tokens (classic)").
Fine-grained tokens are refused by ghcr.io with "does not match expected scopes".
`lab/images.sh` logs in with a throwaway docker config, so the token is never stored.

```bash
bash lab/images.sh push && bash lab/images.sh push-media
git add lab/images.lock && git commit -m "lab: Pin lab images."
```

**Giving a teammate read access** (maintainer, once per package, for each of the six
packages on github.com/sathwikshetty33?tab=packages):

1. Package settings, *Manage Codespaces access*: add `sathwikshetty33/SIH` with read
   access. Codespaces created from this repository can then pull with their own
   built-in token, nothing else needed.
2. Package settings, *Manage access*: invite the teammate with the *Read* role. This
   is needed to pull from anywhere else, and is the fallback if step 1 is not enough.

**Pulling** (teammate): `lab/bootstrap.sh` does it. If a pull is refused, create a
classic personal access token with only `read:packages`, add it as the Codespaces
secret `GHCR_TOKEN` (github.com/settings/codespaces), restart the codespace and run
`bash lab/images.sh pull && bash lab/images.sh pull-media`.
