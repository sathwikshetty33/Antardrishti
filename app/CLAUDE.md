# Antardrishti platform (phase 3)

The product around the trained models (`analyzer/`, bundle `models-v1`): a rule engine,
a FastAPI backend with PostgreSQL and a React dashboard, deployable on Vercel's free
(Hobby) tier and runnable locally. Owner brief, 2026-09-28. The models are not retrained or
changed; the dataset is not touched.

---

## 1. Rules

- **No background work.** No workers, Redis, queues or long-lived processes. An analysis
  runs synchronously inside the request that starts it; the UI polls its status.
- **Passive analysis only.** Everything shown comes from the outer capture, through
  `analyzer` (section 4 of `analyzer/CLAUDE.md`). No decryption, no keys.
- **The model bundle is read-only** and selected by `MODEL_BUNDLE`; a v2 bundle replaces
  v1 with no code change.
- **Code style:** short lowercase names, no semicolon-stacked one-liners, plain dicts and
  lists (`dataset/CLAUDE.md` section 10). Heavy local steps run with `nice -n 10`.
- **Secrets** live only in the Vercel dashboard or a local, gitignored `.env`. Never in
  chat or the repo.
- **Commits:** one subject line (`app: ...`), no body, no trailer. Commit and push after each
  of steps 2 to 7 with a status line in section 12.

## 2. Vercel Hobby constraints (checked against vercel.com/docs on 2026-09-28)

| constraint | value (docs) | design |
|---|---|---|
| request and response body | 4.5 MB max (`/docs/functions/limitations`, "Request body size"; 413 `FUNCTION_PAYLOAD_TOO_LARGE`) | pcaps go from the browser straight to Vercel Blob (client upload, `/docs/vercel-blob/client-upload`); the API only receives the blob URL. Upload limit `UPLOAD_LIMIT_MB`, default 100 |
| duration | Hobby: 300 s default and maximum (fluid compute) | the analysis runs inside one request; the largest supported capture is measured (section 9) and larger ones are rejected before parsing with a clear message |
| memory / CPU | Hobby: 2 GB / 1 vCPU, not configurable | peak memory measured per packet; the packet limit keeps the peak under 1.5 GB |
| bundle | Python: 500 MB uncompressed (`/docs/functions/runtimes/python`) | runtime dependencies only (numpy, zstandard, fastapi, pydantic, sqlalchemy, psycopg); no lightgbm, scikit-learn, pandas or pyarrow at runtime (section 4); `excludeFiles` drops the dataset, lab and web sources. Measured size in section 12 |
| WebSockets, background | WebSockets are only a public beta; nothing may run after the response | no WebSockets: progress is stored in Postgres and polled with backoff |
| disk | no persistent disk; `/tmp` is writable scratch: 525 MB on the live function (measured through `/api/health`; not stated in the Vercel docs) | Postgres on Neon (Vercel Marketplace): `DATABASE_URL` is the pooled PgBouncer string, `DATABASE_URL_UNPOOLED` the direct one (neon.com Vercel-managed integration docs). SQLAlchemy uses `NullPool` (one connection per request, no long-lived pool). Migrations (Alembic) run from the owner's machine or CI against `DATABASE_URL_UNPOOLED`, never at function start. Captures live in Blob and are downloaded to `/tmp` for the request |
| Python runtime | 3.12 default; FastAPI zero-config preset; `tool.vercel.entrypoint` in `pyproject.toml`; a Build Command in `vercel.json` takes precedence; files in `public/` are served from the CDN | one project rooted at the repository root. `pyproject.toml` sets `entrypoint = "app.api.index:app"`, so the function imports `analyzer/` directly (no copy). The build command verifies the model bundle, runs the migrations when a database is connected, and builds `app/web` into `app/web/dist`, which `app.frontend()` serves (index.html fallback for client routes) and Vercel promotes to the CDN (`tool.vercel.fastapi.static`). Rewrites are not used: in backend-framework projects they route to the app |
| Blob | client uploads need `BLOB_READ_WRITE_TOKEN` to sign client tokens; private stores are read with `Authorization: Bearer <token>` | the API signs client-upload tokens itself (the `handleUpload` protocol of `@vercel/blob`, reimplemented in Python) and reads private blobs with the token |
| runtime binaries | no system packages | the inference path is pure Python plus wheels: no tshark, zstd binary or libgomp (section 4) |

## 3. Architecture

```
browser (React, Vercel CDN: public/)
   | 1. POST /api/uploads      -> client token          (Blob mode)
   | 2. PUT file -> Vercel Blob (direct, up to UPLOAD_LIMIT_MB)
   | 3. POST /api/analyses {urls} -> runs the analysis in this request (<= 300 s)
   | 4. GET /api/analyses/{id} (polled with backoff by other views)
   v
FastAPI (app/api, one Vercel Function)
   storage adapter: blob | local        db adapter: Postgres (Neon | local Docker)
   analyzer (repo analyzer/, pure inference) -> contract (app/schema, v1)
   rules engine (app/api/rules) -> findings, risk scores, threat matrix
```

- **Adapters.** `STORAGE=blob|local`: blob uses Vercel Blob; local stores files under
  `LOCAL_STORAGE_DIR` and accepts uploads at `PUT /api/uploads/local/{name}` (local mode
  only). The database is always PostgreSQL through `DATABASE_URL` (Neon on Vercel, Docker
  locally). The same code runs in both places.
- **Model bundle.** `models/v1` is vendored at `app/api/models/v1` with its `SHA256SUMS`;
  the build command and the API's first load check every checksum. `MODEL_BUNDLE`
  (default `app/api/models/v1`) selects it. `/api/model` and the UI show its version and
  commit.
- **Access key.** Uploading and starting analyses need `APP_ACCESS_KEY` (header
  `x-access-key`) when it is set, so a public deployment cannot be used by anyone to fill
  the Blob store (the Blob docs require authenticating client-token requests). Unset
  locally.

## 4. Analyzer inference path (pure Python)

`analyzer.cli` today imports lightgbm and scikit-learn (through `bundle.py` and `ml.py`) and
decompresses `.zst` with the `zstd` binary. On Vercel, lightgbm's wheel needs the system
OpenMP library and the binary is absent. Fix, without changing model behaviour:
- `analyzer/lgbm.py`: a numpy evaluator of LightGBM text models (numerical splits, missing
  value handling, binary, multiclass and cross-entropy outputs). A test checks it against
  lightgbm on every cached window and config row (max difference below 1e-9).
- `analyzer/calib.py`: the isotonic helpers (`ml.py` imports them from there).
- `analyzer/parse.py` decompresses `.zst` with the `zstandard` wheel.
- `bundle.load` and `cli` use only these. The parser, bundle and CLI tests must still pass.

Extra observed facts for the rules (additive, the output shape is unchanged: `config` is a
map from fact name to fact): IKE exchanges, IKEv1 aggressive mode, IKEv1 authentication
method, IKE payload types (for example CERTREQ), IKE retransmissions, AH packets, ESP
plaintext share (NULL encryption), duplicate ESP sequence numbers (replay), rekey times.

## 5. Contract (app/schema)

- `app/schema/v1.py`: pydantic models of the analyzer result, `schema_version =
  "antardrishti.result/1"`. `app/schema/result.v1.json` is the exported JSON Schema.
- It matches `analyzer.cli` output: inputs, bundle, counts, timing, and per tunnel:
  handshake status, endpoints, config facts (value, confidence, source: `read from IKE`,
  `observed`, `inferred`), byte share with error bars, rounded byte share (sums to 100),
  active-time share, window timeline with per-window presence probabilities and shares.
- Tests validate real CLI output of the kept test captures in `~/antar-data/keep`.

## 6. Rule engine (app/api/rules)

- `table.py`: one readable row per check (id, title, standard, fact(s), thresholds, verdict
  and severity per value, threat ids, recommendation). Thresholds are data, not code.
- `engine.py`: evaluates the table on the result; every finding carries check id,
  verdict (`pass`, `fail`, `warn`, `info`, `not determinable`), severity (critical, high,
  medium, low, info), cited standard, evidence (fact, value, source), and confidence = the
  lowest confidence of the facts it rests on. Below 0.8 the wording says "likely".
- Not yet observable facts (PFS without a rekey, ESP AES key size, ESN, replay window)
  give "not determinable" findings, never guesses.
- Risk score 0-100 per tunnel and overall (`risk.py`). Severity weights: critical 40,
  high 20, medium 8, low 3, info 0, each times the finding's confidence; the sum is capped
  at 100; a confident critical (confidence at least 0.8) sets the floor to 90. Overall =
  the worst tunnel.
- Threat matrix (`threats.py`): threat, likelihood (1-5), impact (1-5), affected tunnels,
  linked findings.
- Standards: RFC 8221 (ESP/AH algorithms), RFC 8247 (IKEv2 algorithms), NIST SP 800-77r1
  (IPsec guide), RFC 4303 section 2.7 (TFC padding, for metadata exposure).

## 7. Backend (app/api)

- FastAPI app in `app/api/index.py` (`app`), SQLAlchemy 2, Alembic (`app/api/migrations`).
- **Tables:** analyses (status, progress, stage, error, source, name, urls, sizes, bundle
  version, timings, schema version, risk), tunnels, config_facts, windows, session_shares,
  findings, risk_scores, threats, replay_chunks.
- **Endpoints:** `POST /api/uploads` (Blob client token; the `handleUpload` protocol),
  `PUT /api/uploads/local/{name}` (local mode), `POST /api/analyses` (from blob URLs or a
  demo; runs the analysis in the request), `GET /api/analyses`, `GET /api/analyses/{id}`,
  `.../tunnels`, `.../tunnels/{tid}`, `.../findings`, `.../threats`, `.../report`,
  `GET /api/demos`, `POST /api/replays`, `POST /api/replays/{id}/next`, `GET /api/health`,
  `GET /api/model`, `GET /api/config`.
- **Demo replay:** live capture can't run on Vercel. A replay feeds a stored demo capture
  to the API in successive 5 s chunks: each `next` call appends the next chunk to
  `replay_chunks` (Postgres), re-analyses all chunks so far and replaces the analysis'
  tunnels, facts, findings and scores, so confidence rises as evidence accumulates. The
  UI labels it a replay.
- **Demos:** 3 small test-split captures in `app/api/demo/` (a mixture, a WhatsApp replay
  run, an edge case), each a single pcap with the full IKE packets merged in, under the
  upload limit, analysable with one click. The WhatsApp one is derived from ITC-Net
  (CC BY 4.0), attributed in `app/api/demo/README.md`.

## 8. Frontend (app/web)

React + TypeScript (Vite), Tailwind, shadcn/ui, Apache ECharts, Framer Motion, lucide icons.
Built into `public/` and served from the CDN.

### Design brief

- **Character:** a calm, dense security-analytics console. Dark first, light theme toggle.
  Data is the hero; chrome is quiet.
- **Palette** (CSS tokens on `:root`, dark default, light under `[data-theme=light]`):

| token | dark | light | use |
|---|---|---|---|
| bg | `#0b0e14` | `#f7f8fa` | page |
| surface | `#11151d` | `#ffffff` | cards |
| surface-2 | `#171c26` | `#f1f3f6` | insets, table headers |
| border | `#252c39` | `#e2e5eb` | hairlines |
| text | `#e7eaf0` | `#0f1320` | primary text |
| text-2 | `#a4acbb` | `#4a5263` | secondary text |
| muted | `#737c8e` | `#6b7385` | captions (large text only in light) |
| accent | `#12a38f` (the logo teal) | `#0d6b64` | brand, focus ring, primary buttons |
| critical | `#ff6b6b` | `#b42323` | severity |
| high | `#ff9f43` | `#9a4a07` | severity |
| medium | `#f5c542` | `#735b00` | severity |
| low | `#60a5fa` | `#1a57c2` | severity |
| info / pass | `#94a3b8` / `#34d399` | `#5b6474` / `#0e6e44` | severity, verdicts |

  Severity chips are the severity colour on a 14% tint of itself, so the text keeps AA
  contrast in both themes; severity never relies on colour alone (icon and label).
- **Brand** (the owner's logos, 2026-09-29): originals in `app/web/brand` (`logo.png` light
  lockup, `logo-dark.png` / `logo-dark.svg` dark lockup, `mark.png`, `favicon-512.png`);
  `app/web/scripts/brand.py` derives the web assets in `app/web/public` (favicons, touch and PWA
  icons, the UI mark, the light lockup, the dark lockup with a transparent background, a
  1200 x 630 link preview). Brand colours: navy `#1B2A6B`, teal `#12A38F`, gold `#F4B400` (the
  lock, kept out of the UI palette so it never reads as a severity), navy-black `#0F172A`,
  light teal `#5EEAD4`; tagline "See inside the tunnel". The mark sits in the shell, the lockup
  on the first-run screen and on both reports.
- **App colours** (charts, fixed order, never cycled; the validated reference palette):
  voip `#3987e5`, video `#d95926`, web `#199e70`, email `#c98500`, icmp `#d55181`, bulk
  `#008300`, chat `#9085e9` in dark (light: `#2a78d6`, `#eb6834`, `#1baf7a`, `#eda100`,
  `#e87ba4`, `#008300`, `#4a3aa7`); unknown is neutral grey `#6b7385`.
- **Type:** Inter for UI, JetBrains Mono for numbers, IDs and hashes (tabular figures).
  Scale 12 / 13 / 14 (body) / 16 / 20 / 24 / 32 / 44 (gauge value); weights 400, 500, 600.
- **Layout:** fixed left sidebar 232 px that collapses to 72 px of icons with a toggle (kept per
  browser; icons by default below 1280 px), a drawer from the top bar's menu button below 768 px, top bar 56 px,
  content max 1600 px, 12-column grid with 24 px gutters (16 px below 1280), 8 px spacing
  unit, card radius 12 px, 1 px borders instead of shadows in dark.
- **Components:** AppShell, Sidebar, TopBar (bundle version, theme toggle), Card,
  StatTile, RiskGauge, SeverityBadge, VerdictBadge, ConfidenceBadge, SourceBadge,
  DataTable, Tabs, Skeleton, EmptyState, ErrorState, Dropzone, UploadProgress,
  StatusSteps, ShareBar (stacked bar to 100% with error whiskers and unknown), ActiveBars,
  WindowTimeline, ThreatHeatmap, FindingCard, FindingDrawer, ReplayBanner, Toaster.
- **Motion:** 150-250 ms fades and height transitions, reduced when
  `prefers-reduced-motion`.
- **Accessibility:** every control reachable by keyboard with a visible focus ring, charts
  have text equivalents (tables or labels), WCAG AA contrast for text in both themes.
- **Numbers:** shares shown with largest-remainder rounding to 100; error bars clipped to
  0-100; confidence as a percentage with "likely" below 80%.

### Pages

Overview (inventory, overall risk gauge, critical alerts, recent analyses); Upload
(drag-and-drop to Blob with progress, then polled status); Tunnel detail (handshake,
config facts with confidence and source, byte share bar to 100% with error bars and
unknown, active-time bars with an overlap note, window timeline, findings); Threat matrix
(likelihood x impact heatmap, drill-down); Replay (demo replay, labelled); Reports
(executive and technical, print stylesheet to PDF in the browser, every number from the
API).

## 9. Limits measured locally

The largest capture that fits: measured by `app/tests/test_timing.py` on the largest kept
capture, with the time scaled for Vercel's single vCPU and peak memory measured. Recorded
in section 12 and in `DEPLOY.md`.

**Live sessions** (`app/api/live.py`) reanalyse the whole capture so far on every chunk, the
same way demo replay does, so a chunk's processing time grows with the session, not with the
chunk. Measured on 2026-09-29 (local machine, in-process `TestClient` against Docker Postgres,
so analyzer, rules and database time without the network): one session fed the mixture
demo's ESP records looped, in chunks of 5,000 packets (0.69 MB, about 2 s of that traffic),
back to back as fast as each was processed, with the size cap lifted so that the 20-minute
cap ended it:

| into the session | ESP capture so far | processing per chunk (median, range) |
|---|---|---|
| 1 minute | 16-31 MB | 2.6 s (1.8-3.3 s) |
| 10 minutes | 94-99 MB | 7.7 s (7.3-8.6 s) |
| 20 minutes | 139-141 MB | 10.9 s (10.7-11.0 s) |

204 chunks in all; the session then completed on its own ("reached the 20-minute cap on a live
session"). The cost is about 0.08 s per accumulated MB, linear, as expected for a full reparse
and rerun of every model on each chunk. With the default size cap this feed completes at
chunk 145 (100 MB, 10.9 minutes in, 8.1 s per chunk). So a live session completes at 20
minutes or 100 MB of accumulated ESP pcap, whichever comes first (`LIVE_MAX_DURATION_S`,
`LIVE_MAX_ESP_MB`; status `completed` with the reason, which the agent prints before it
exits). The binding limit is not Vercel's 300 s: past about 60 MB a chunk takes longer to
analyse than the 5 s the agent spends capturing it, so the sensor falls further behind with
every chunk. Scaled by the 3x slower vCPU assumed in step 6, a chunk at the size cap takes
about 25 s on Vercel, still well inside the function limit.

**Future work: incremental analysis.** Instead of reprocessing the whole capture on every
chunk, persist each tunnel's parser state (reassembly buffers, SPI pairing, the running
config-evidence accumulators) and its finished 2 s windows, and process only the new chunk
plus the carried-over trailing partial window. A chunk's processing time would then stay
roughly constant instead of growing with the session, which removes the reason for the
current caps (a size cap would still bound `/tmp` and the stored capture). Not done here: it
needs `analyzer.parse` and `analyzer.features` to expose and accept that state, a larger
change to their contract than the live-mode brief allows.

**Future work: incremental analysis.** Instead of reprocessing the whole capture on every
chunk, persist each tunnel's parser state (reassembly buffers, SPI pairing, the running
config-evidence accumulators) and its finished 2 s windows, and process only the new chunk
plus the carried-over trailing partial window. That would make a chunk's processing time
roughly constant instead of growing with the session, removing the reason for the current
caps (though a size cap would likely still make sense, to bound `/tmp` and the stored
capture). Not done here: it needs `analyzer.parse` and `analyzer.features` to expose and
accept that state, which changes their contract more than this brief allows.

## 10. Deployment

`vercel.json` (build, function config, rewrites), `pyproject.toml` (runtime dependencies,
entrypoint), `.env.example` (every setting), `DEPLOY.md` (the owner's manual steps:
project, Neon, Blob, env vars in the dashboard, migrations), `DEMO.md` (local run: docker
compose Postgres, uvicorn, Vite).

## 11. Plan

1. Spec (this file). 2. Contract and pure inference. 3. Rule engine. 4. Backend.
5. Frontend. 6. Deployment files. 7. Tests, timing, screenshots.

## 12. Status (checkpoints)

- **Step 0-1 (2026-09-28).** Spec written; repository at `12fb01f`; Vercel constraints
  checked against the docs (section 2).
- **Step 2 done (2026-09-28).** Contract `app/schema/v1.py` + `result.v1.json`
  (`antardrishti.result/1`), validated on real CLI output of 8 kept test captures. Pure
  inference: `analyzer/lgbm.py` equals lightgbm on all 17 models (max difference 0.0 on
  12,185 windows and 2,746 config rows), `analyzer/calib.py`, zstandard in the parser; the
  inference path imports no lightgbm, scikit-learn, pandas or pyarrow and runs no binary.
  New observed facts for the rules (section 4). Tests: analyzer 46, schema 19, all pass.
- **Step 3 done (2026-09-28).** Rule engine `app/api/rules`: 23 checks in `table.py` (RFC 8221,
  RFC 8247, NIST SP 800-77r1, RFC 7296, RFC 4303), findings with verdict, severity, standard,
  evidence and confidence ("Likely (x% confidence)" below 0.8), "not determinable" for PFS
  without a rekey, ESP key size, replay window and ESN, lifetimes without two rekeys. Risk:
  weights critical 40, high 20, medium 8, low 3, times confidence, cap 100, floor 90 for a
  confident critical; overall = worst tunnel. Threat matrix of 8 threats. 60 unit tests pass.
  On the kept edge captures: NULL ESP 90 (critical), IKEv1 aggressive PSK high, 3DES +
  modp1024 fail.
- **Step 4 done (2026-09-28).** Backend `app/api`: FastAPI (`index.py`), SQLAlchemy 2 with
  NullPool (`db.py`), 9 tables (`models.py`), Alembic migration `0001` (`app/alembic.ini`),
  storage adapters (local files, Vercel Blob client tokens signed in Python and private
  downloads), in-request pipeline with polled progress, demo replay in 5 s chunks stored in
  `replay_chunks`, 3 demo captures (`app/api/demo`), vendored bundle `app/api/models/v1`
  (checked by `python -m app.api.verify_bundle`). Local timings: demos 1.0-4.6 s, replay step
  0.4-1.5 s. 10 API tests pass against Docker Postgres.
- **Step 5 done (2026-09-29).** Frontend `app/web`: React 19 + TypeScript (Vite 8), Tailwind 4,
  shadcn/ui-style components written in `src/components/ui` (Radix primitives; the shadcn CLI's
  interactive init was not used), ECharts (SVG renderer, tree-shaken), Framer Motion, lucide,
  TanStack Query (polling with backoff), `@vercel/blob` client uploads. Pages: overview,
  upload, analyses, analysis, tunnel detail, threat matrix, demo replay, reports (executive,
  technical; print stylesheet to PDF). Follows the design brief (section 8): tokens in
  `src/index.css`, dark first with a light toggle, fonts self-hosted. `tsc -b` and oxlint
  clean; build 0.8 s into `public/`. Screenshots in `app/docs/screenshots`
  (`python app/docs/screenshots.py`), no console errors.
- **Step 6 done (2026-09-29).** `pyproject.toml` (runtime dependencies, `tool.vercel.entrypoint =
  "app.api.index:app"`), `vercel.json` (build: verify the bundle, build the dashboard into
  `public/`; function `app/api/index.py` with `maxDuration` 300 and `excludeFiles`; SPA rewrite;
  headers), `.vercelignore`, `.env.example`, `DEPLOY.md` (the owner's manual steps), `DEMO.md`
  (local run), README "Run the platform" and "Tech stack". Function bundle about 143 MB
  (127 MB of dependencies). Largest capture: `MAX_PCAP_MB` = 300 (13.4 s, 686 MB under a 2 GB
  address-space cap; about 40 s at an assumed 3x slower vCPU).
- **Step 7 done (2026-09-29).** Tests: 144 Python tests pass (analyzer 46 incl. the numpy
  evaluator against lightgbm; contract 19; rules 60, one case per check plus wording, "not
  determinable", scores and threats; API 10 on the 3 demo captures, upload -> analysis ->
  findings, replay, access key, limits, blob token; platform 8: no heavy imports or binaries at
  runtime, bundle selection and tamper check, WCAG AA contrast of every text and severity
  token in both themes, which moved 6 light-theme tokens; timing 1: 300 MB in 13.4 s, 686 MB
  under a 2 GB address-space cap). Frontend: 3 unit tests (rounding, error bars, "likely"),
  `tsc -b`, oxlint and the build clean. Screenshots retaken.
- **Deployment (2026-09-29).** Vercel project `antardrishti` (Hobby, FastAPI preset) linked to
  the repository, private Blob store `antardrishti-captures` connected. The first build stopped
  at the bundle check: `.vercelignore` had matched `app/api/models/` (fixed: anchored paths).
  The dashboard moved from a rewrite to `app.frontend()`, since rewrites in backend-framework
  projects route to the app.
  Neon project `antardrishti` (`sparkling-hill-44536745`, `aws-us-east-1`, Postgres 17) created
  with the Neon MCP server; `DATABASE_URL` (pooled) and `DATABASE_URL_UNPOOLED` (direct) stored as
  sensitive Vercel variables. Replay chunks are zstd-compressed in Postgres (Neon free plan: 512 MB
  per branch). Production URL: https://antardrishti-sathwik-shettys-projects.vercel.app.
- **Live verification (2026-09-29).** Build: bundle check passes, migrations run in the build
  ("database at head", 10 tables in Neon). On the live site: health ok (db, bundle v1, `/tmp`
  525 MB), SPA deep links served from the CDN, one-click mixture demo analysed in 2.7 s, a 10 MB
  browser upload through the Blob client-token handshake (Python-signed) fetched back in 0.3 s and
  analysed in 3.1 s, a full 18-step replay. Captures are fetched and decompressed one at a time
  so `/tmp` stays at or below 400 MB.
- **Public (2026-09-29, owner's decision).** Vercel Authentication switched off: the site is
  public at https://antardrishti-zeta.vercel.app (and the project URL above); a logged-out visitor
  loads the dashboard and runs a demo. `APP_ACCESS_KEY` is not set, so anyone can also upload
  captures (up to 100 MB each) to the Blob store and start analyses.
