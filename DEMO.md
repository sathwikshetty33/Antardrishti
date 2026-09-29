# Running Antardrishti locally

The same code as on Vercel, self-hosted: Postgres in Docker, the API under uvicorn, the
dashboard on the Vite dev server, and captures stored in a local folder. No Vercel account,
Redis or workers are needed.

## Once

```bash
git clone https://github.com/sathwikshetty33/Antardrishti.git && cd Antardrishti
uv venv --python 3.12 .venv && . .venv/bin/activate   # uv: https://docs.astral.sh/uv/
uv pip install -r pyproject.toml -r app/requirements-dev.txt
cp .env.example .env                                 # local defaults: STORAGE=local, docker postgres
docker compose up -d --wait                          # postgres 17 on 127.0.0.1:5434
alembic -c app/alembic.ini upgrade head              # create the tables
(cd app/web && npm ci)
```

## Every time

```bash
docker compose up -d --wait
nice -n 10 uvicorn app.api.index:app --port 8000 --reload   # terminal 1: the api
cd app/web && npx vite                                        # terminal 2: http://localhost:5173
```

Then open http://localhost:5173:
- **Analyze capture:** drop a `.pcap`, `.pcapng` or `.cap` (optionally `.zst`), or click one of
  the three demo captures.
- **Demo replay:** replays a demo in 5 s chunks and shows the confidence rising.
- **Reports:** executive and technical reports; print them to PDF from the browser.

The API documentation is at http://localhost:8000/api/docs. After `cd app/web && npm run build`,
uvicorn also serves the built dashboard at http://localhost:8000, the way Vercel does.

## Tests

```bash
pytest -q analyzer/tests app/tests          # analyzer, contract, rules, api (needs docker postgres), timing
cd app/web && npx tsc -b && npx oxlint src && npm run build
python app/docs/screenshots.py              # ui screenshots (api and vite running, demos analysed)
```

The parser tests compare against `tshark`. They, the schema tests and the timing test use
the kept test captures in `~/antar-data/keep`, and skip when those are missing.

## Command line

The analyzer also runs without the platform:

```bash
python -m analyzer.cli analyze capture.pcap --out result.json    # contract: app/schema/result.v1.json
```
