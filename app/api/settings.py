"""settings from the environment (documented in .env.example). nothing here holds a secret
value: tokens come only from the environment (vercel dashboard or a local .env)."""
import os
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
api_dir = Path(__file__).resolve().parent


def load_dotenv():
    """a local .env for development (never on vercel, where the dashboard sets variables)"""
    f = root / ".env"
    if f.exists() and not os.environ.get("VERCEL"):
        for line in f.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv()


def env(k, default=None):
    v = os.environ.get(k)
    return v if v not in (None, "") else default


def db_url():
    u = env("DATABASE_URL", "postgresql://antar:antar@localhost:5434/antar")
    for pre in ("postgres://", "postgresql://"):
        if u.startswith(pre):
            return "postgresql+psycopg://" + u[len(pre):]
    return u


storage = env("STORAGE", "blob" if env("BLOB_READ_WRITE_TOKEN") else "local")
blob_token = env("BLOB_READ_WRITE_TOKEN")
blob_access = env("BLOB_ACCESS", "private")
local_dir = Path(env("LOCAL_STORAGE_DIR", str(root / ".local-storage")))
bundle_dir = Path(env("MODEL_BUNDLE", str(api_dir / "models" / "v1")))
if not bundle_dir.is_absolute():
    bundle_dir = root / bundle_dir
upload_limit_mb = float(env("UPLOAD_LIMIT_MB", "100"))
# the largest capture (uncompressed pcap bytes) an analysis accepts: measured to finish well
# under the 300 s function limit on one vcpu within 2 gb (app/CLAUDE.md section 9)
max_pcap_mb = float(env("MAX_PCAP_MB", "300"))
access_key = env("APP_ACCESS_KEY")
tmp_dir = Path(env("TMP_DIR", "/tmp"))
on_vercel = bool(env("VERCEL"))
demo_dir = api_dir / "demo"
replay_chunk_s = 5.0

# live capture sessions (protects the free tier: app/CLAUDE.md live-mode brief item 2)
live_max_chunk_mb = float(env("LIVE_MAX_CHUNK_MB", "3"))               # well under vercel's 4.5 mb body limit
live_min_chunk_interval_s = float(env("LIVE_MIN_CHUNK_INTERVAL_S", "1"))
live_idle_timeout_s = float(env("LIVE_IDLE_TIMEOUT_S", str(20 * 60)))   # auto-stop without chunks
live_max_duration_s = float(env("LIVE_MAX_DURATION_S", str(2 * 60 * 60)))  # auto-stop overall
live_max_sessions_per_ip = int(env("LIVE_MAX_SESSIONS_PER_IP", "3"))
