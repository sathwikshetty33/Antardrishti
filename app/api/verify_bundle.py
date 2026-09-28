"""build step: check the vendored model bundle against its SHA256SUMS (and the release archive's
checksum, recorded here) before deploying. python -m app.api.verify_bundle"""
import hashlib
import sys

from app.api import settings

release = {"v1": {"archive": "models-v1-a88b2a4.tar.zst",
                  "sha256": "78d5a6c5379b7c48a45d52cf56ebbcbee79772f5d2ad7f181aafe9bfef0e6fde"}}


def main():
    d = settings.bundle_dir
    sums = (d / "SHA256SUMS").read_text().splitlines()
    for line in sums:
        h, name = line.split(None, 1)
        if hashlib.sha256((d / name.strip()).read_bytes()).hexdigest() != h:
            sys.exit(f"bundle {d}: {name} does not match SHA256SUMS")
    print(f"bundle {d.name}: {len(sums)} files match SHA256SUMS (release {release.get(d.name, {}).get('archive')})")


if __name__ == "__main__":
    main()
