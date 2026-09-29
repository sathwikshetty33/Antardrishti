# Deploying Antardrishti on Vercel (Hobby)

The whole platform is one Vercel project built from this repository:
- a **Python function**: the FastAPI app `app/api/index.py`, named in `pyproject.toml`;
- a **static React dashboard**: `app/web`, built into `app/web/dist`, served by the FastAPI app's
  `app.frontend()` and promoted by Vercel to its CDN;
- **Neon Postgres** and **Vercel Blob**, both from the Vercel Marketplace.

There are no workers, queues or Redis. An analysis runs inside the request that starts it,
and the UI polls its status. `app/CLAUDE.md` section 2 lists the Hobby limits this design
works within.

Do these steps by hand, once. Secrets go into the Vercel dashboard only: never into the
repository, an issue or a chat.

## 1. Create the project

1. On vercel.com, open **Add New… → Project** and import `sathwikshetty33/SIH`.
2. **Root Directory:** leave it at the repository root (`./`).
3. **Framework Preset:** Vercel should detect **FastAPI** from `pyproject.toml`. If it doesn't,
   pick FastAPI. Leave the Build, Output and Install settings on their defaults. `vercel.json`
   sets the build command, which verifies the model bundle, runs the migrations when a database
   is connected, and builds the dashboard into `app/web/dist`.
4. Don't deploy yet if the dashboard offers to. The environment comes first.

## 2. Add Neon Postgres

1. In the project, open **Storage → Create Database → Neon** (Marketplace) on the free plan.
   Connect it to Production, Preview and Development.
2. Neon adds `DATABASE_URL` (pooled, PgBouncer: the app uses this) and `DATABASE_URL_UNPOOLED`
   (direct: migrations use this), plus `PG*` variables. Keep them.

## 3. Add a Blob store

1. **Storage → Create → Blob**, access **Private**. Connect it to Production and Preview (and
   Development if you run `vercel dev`).
2. This adds `BLOB_READ_WRITE_TOKEN`, which the API needs to sign browser upload tokens and to
   read private captures, plus `BLOB_STORE_ID`.

## 4. Set the other environment variables

In **Settings → Environment Variables**, for Production and Preview:

| name | value | why |
|---|---|---|
| `STORAGE` | `blob` | captures go to Vercel Blob |
| `BLOB_ACCESS` | `private` | must match the store's access |
| `APP_ACCESS_KEY` | a long random string you choose | only holders of the key can upload and start analyses (the UI asks for it once). Without it anyone could fill your Blob store |
| `UPLOAD_LIMIT_MB` | `100` | per-file limit (default 100) |
| `MAX_PCAP_MB` | `300` | largest capture per analysis, uncompressed (measured, below) |
| `MODEL_BUNDLE` | `app/api/models/v1` | the model bundle directory; a v2 bundle replaces it with no code change |

`.env.example` documents every setting.

## 5. Create the tables (migrations)

Migrations never run at function start. Every Vercel build runs them (`app/migrate.sh`, from the
build command) with `DATABASE_URL_UNPOOLED` once Neon is connected, and skips them when no
database is configured, so a redeploy after connecting Neon creates the tables. To run them
by hand from your machine instead:

```bash
cd SIH
uv venv --python 3.12 .venv && . .venv/bin/activate
uv pip install -r pyproject.toml -r app/requirements-dev.txt
# paste the direct connection string at the prompt instead of into a file:
read -rs DATABASE_URL_UNPOOLED && export DATABASE_URL_UNPOOLED
alembic -c app/alembic.ini upgrade head
unset DATABASE_URL_UNPOOLED
```

To get the string, run `vercel env pull .env` (the file is gitignored) or copy it from the
Neon dashboard.

## 6. Deploy and check

1. Deploy: push to `main`, or use **Deployments → Redeploy**.
2. Open `https://<project>.vercel.app/api/health`. It should report `"ok": true`, `db: ok` and
   `bundle: v1`.
3. Open the site, set the access key (key icon in the top bar), and run a demo from **Analyze
   capture** or **Demo replay**.
4. Check `/api/model`. It should show bundle `v1`, commit `a88b2a4` and 17 models.

## Limits (measured)

| | value |
|---|---|
| function bundle | about 143 MB uncompressed (127 MB of dependencies: numpy, zstandard, fastapi, pydantic, sqlalchemy, psycopg; 16 MB of sources, including the 6 MB model bundle and 10.5 MB of demo captures). The Python limit is 500 MB |
| largest capture | **300 MB uncompressed pcap** (`MAX_PCAP_MB`). Its worst case, 2.2 M records of LAN bulk traffic, took 13.4 s on one core with 686 MB peak memory under a 2 GB address-space cap (`app/tests/test_timing.py`). At an assumed 3x slower Vercel vCPU, about 40 s of the 300 s limit |
| upload | 100 MB per file (`UPLOAD_LIMIT_MB`), straight from the browser to Blob. Vercel's 4.5 MB body limit only applies to API requests, which never carry the capture |
| `/tmp` | a compressed upload and its decompressed pcap briefly coexist: up to 100 + 300 MB. Vercel doesn't document the `/tmp` size; Lambda's 512 MB default is assumed |

A larger capture is rejected with a clear message before parsing. Split it (`editcap -c`)
or analyse it locally with `python -m analyzer.cli analyze <pcap> --out result.json`.

## Things to know

- **Cold starts:** the first request after a pause loads numpy and the models, a few seconds.
- **Neon free plan** suspends idle compute; the first query after a pause takes a moment.
- **Blob usage** counts against the Hobby quota. Delete old captures from the store's
  browser if you need space. The analyses keep their results in Postgres.
- **Preview deployments** share the same database unless you create a Neon branch for them.
