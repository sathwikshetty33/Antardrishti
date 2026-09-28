"""storage adapters: where uploaded captures live.

blob:  vercel blob. the browser uploads straight to blob with a client token signed here (the
       handleUpload protocol of @vercel/blob 2.x: "vercel_blob_client_<store>_" + base64 of
       "<hmac-sha256 hex>.<base64 json payload>", keyed with BLOB_READ_WRITE_TOKEN); the api
       only receives the blob url and downloads it to /tmp for the analysis.
local: files under LOCAL_STORAGE_DIR, uploaded with PUT /api/uploads/local/{name}; urls are
       "local:<name>".
"""
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.request
import uuid
from pathlib import Path

from app.api import settings

chunk = 1 << 20


class too_large(Exception):
    pass


def safe_name(name):
    n = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)[:120]
    return n or "capture.pcap"


def client_token(pathname, max_bytes, valid_s=3600):
    """a blob client-upload token for one pathname (what @vercel/blob's handleUpload returns)"""
    tok = settings.blob_token
    if not tok:
        raise RuntimeError("BLOB_READ_WRITE_TOKEN is not set")
    parts = tok.split("_")
    store = parts[3] if len(parts) > 3 else ""
    if not store:
        raise RuntimeError("BLOB_READ_WRITE_TOKEN has an unexpected format")
    body = {"pathname": pathname, "maximumSizeInBytes": int(max_bytes), "addRandomSuffix": True,
            "validUntil": int((time.time() + valid_s) * 1000)}
    payload = base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode()
    sig = hmac.new(tok.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"vercel_blob_client_{store}_" + base64.b64encode(f"{sig}.{payload}".encode()).decode()


def is_blob_url(url):
    """a vercel blob url, of this deployment's store when the token is known"""
    m = re.match(r"^https://([a-z0-9]+)\.(public|private)\.blob\.vercel-storage\.com/", url)
    if not m:
        return False
    parts = (settings.blob_token or "").split("_")
    return len(parts) < 4 or m.group(1) == parts[3].lower()


def local_path(name):
    return settings.local_dir / safe_name(name)


def save_local(name, stream, limit):
    """write an uploaded body to local storage, refusing more than limit bytes"""
    settings.local_dir.mkdir(parents=True, exist_ok=True)
    n = f"{uuid.uuid4().hex[:8]}-{safe_name(name)}"
    p = local_path(n)
    size = 0
    with open(p, "wb") as f:
        for b in stream:
            size += len(b)
            if size > limit:
                f.close()
                p.unlink()
                raise too_large(f"upload over the {limit / 2 ** 20:.0f} MB limit")
            f.write(b)
    return f"local:{n}", size


def fetch(url, dest, limit):
    """copy a stored capture to dest (a local path), refusing more than limit bytes"""
    if url.startswith("local:"):
        src = local_path(url[6:])
        if not src.exists():
            raise FileNotFoundError(url)
        if src.stat().st_size > limit:
            raise too_large(f"{src.stat().st_size / 2 ** 20:.1f} MB is over the {limit / 2 ** 20:.0f} MB upload limit")
        with open(src, "rb") as a, open(dest, "wb") as b:
            while True:
                x = a.read(chunk)
                if not x:
                    break
                b.write(x)
        return src.stat().st_size
    if not is_blob_url(url):
        raise ValueError("only vercel blob urls of this store are accepted")
    req = urllib.request.Request(url)
    if ".private." in url:
        if not settings.blob_token:
            raise RuntimeError("BLOB_READ_WRITE_TOKEN is needed to read a private blob")
        req.add_header("Authorization", f"Bearer {settings.blob_token}")
    size = 0
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
        n = r.headers.get("content-length")
        if n and int(n) > limit:
            raise too_large(f"{int(n) / 2 ** 20:.1f} MB is over the {limit / 2 ** 20:.0f} MB upload limit")
        while True:
            x = r.read(chunk)
            if not x:
                break
            size += len(x)
            if size > limit:
                raise too_large(f"over the {limit / 2 ** 20:.0f} MB upload limit")
            f.write(x)
    return size
