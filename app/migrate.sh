#!/bin/sh
# run the alembic migrations during the vercel build (ci), never at function start.
# uses DATABASE_URL_UNPOOLED (neon's direct string) or DATABASE_URL; skips when neither is set.
set -e
if [ -z "$DATABASE_URL_UNPOOLED" ] && [ -z "$DATABASE_URL" ]; then
  echo "migrate: no database configured, skipping"
  exit 0
fi
dir=/tmp/antar-migrate
if command -v uv >/dev/null 2>&1; then
  uv pip install -q --target "$dir" -r app/requirements-migrate.txt
else
  python3 -m pip install -q --target "$dir" -r app/requirements-migrate.txt
fi
PYTHONPATH="$dir:." python3 -m alembic -c app/alembic.ini upgrade head
echo "migrate: database at head"
