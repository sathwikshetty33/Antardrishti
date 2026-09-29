# Antardrishti

*Antardrishti* (Sanskrit: "inner vision"): an AI-driven IPsec VPN analysis platform
for SIH 2026. It infers the IPsec configuration of captured or live traffic, predicts
the traffic type inside ESP and produces a security assessment, without ever
decrypting anything.

The repository holds all three phases:
1. **Dataset** (`lab/`, `gen/`, `capture/`, `tools/`, `dataset/`): the lab that built the labelled
   IPsec dataset. Spec: [dataset/CLAUDE.md](dataset/CLAUDE.md); datasheet:
   [dataset/README.md](dataset/README.md).
2. **Analyzer** (`analyzer/`): parser, features and 17 LightGBM models (bundle `models-v1`).
   Spec: [analyzer/CLAUDE.md](analyzer/CLAUDE.md); results: [analyzer/REPORT.md](analyzer/REPORT.md).
3. **Platform** (`app/`): rule engine, FastAPI backend with PostgreSQL, React dashboard,
   deployable on Vercel's free tier. Spec: [app/CLAUDE.md](app/CLAUDE.md).

## Run the platform

- **On Vercel (Hobby):** one project with a Python function (FastAPI), the dashboard on the CDN,
  Neon Postgres and Vercel Blob from the Marketplace. The manual steps are in
  [DEPLOY.md](DEPLOY.md).
- **Locally, self-hosted:** Postgres in Docker (`docker compose up -d`), the API under uvicorn
  and the Vite dev server, with captures stored in a local folder. See [DEMO.md](DEMO.md).

There are no workers, queues or Redis in either setup. An analysis runs inside the request
that starts it; the dashboard polls its status from Postgres, and a demo replay feeds a stored
capture to the API in 5-second chunks.

## Tech stack

| layer | technology |
|---|---|
| analysis | Python 3.12, numpy: a pure-Python inference path (a numpy evaluator of the LightGBM models, zstandard); no tshark or other binaries at runtime |
| models | LightGBM 4.7, trained offline (`analyzer/`), shipped as the checksummed bundle `app/api/models/v1` |
| rules | table-driven checks against RFC 8221, RFC 8247, NIST SP 800-77r1, RFC 7296 and RFC 4303 (`app/api/rules`) |
| api | FastAPI, pydantic (result contract `app/schema`, JSON Schema), SQLAlchemy 2 with NullPool, Alembic, psycopg 3 |
| data | PostgreSQL: Neon on Vercel, Docker locally. Captures in Vercel Blob (browser client uploads) or a local folder |
| dashboard | React 19, TypeScript, Vite, Tailwind CSS 4, shadcn/ui components on Radix, Apache ECharts, Framer Motion, lucide; reports printed to PDF in the browser |
| hosting | Vercel Hobby: FastAPI preset, the dashboard served by `app.frontend()` from the CDN, 300 s functions |

## Layout

- `lab/`: dev lab (strongSwan gateways, router tap, services, noise), preflight, images
- `gen/`: traffic generators, one per app class
- `capture/`: the experiment design and the orchestrator (`run.py`)
- `tools/`: coverage, checks, merge, export, adversarial validation
- `dataset/`: manifest, coverage report, datasheet (raw captures are never committed)
- `analyzer/`: parser, features, models, evaluation, CLI (`python -m analyzer.cli analyze <pcap>`)
- `app/`: `schema/` (contract), `api/` (FastAPI, rules, demos, model bundle), `web/` (dashboard),
  `tests/`, `docs/screenshots/`

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
