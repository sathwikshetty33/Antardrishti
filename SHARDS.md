# Capturing a shard

A tier (`p0`, `p1`, `p2`) is split into n shards, one per teammate's personal account,
so each shard spends that account's own free Codespaces quota. `--slice i/n` deals the
plan deterministically: every shard gets a balanced mix of apps, configs and edge
cases, and run ids never collide. The maintainer tells you your `i` and `n`.

The adversarial validation (`tools/advval.py`) is never sharded: the maintainer runs
it once, on one codespace, before any shard starts.

## 1. Access

- Be a collaborator on `sathwikshetty33/SIH`.
- Read access to the lab image packages: the maintainer grants it (README, "Lab images").

## 2. Create the codespace

On github.com/sathwikshetty33/SIH: **Code, Codespaces, "...", New with options**:

- branch `main`, dev container `antardrishti`
- machine type **4-core** (not 2-core: each shard runs 3 labs side by side)
- the codespace bills your own account's free quota (check github.com/settings/billing)

The container runs `lab/bootstrap.sh` on creation: tools, the pinned lab images and the
media snapshot. Check it:

```bash
bash lab/images.sh pull          # every line must say "pulled ghcr.io/...@sha256:..."
python3 lab/preflight.py         # every check ok; netem available
```

If an image line says "building locally", stop and ask the maintainer for package
access: runs on local builds are rejected at merge.

## 3. Raise the idle timeout

github.com/settings/codespaces:

- **Default idle timeout**: the maximum (240 minutes). A stopped codespace pauses the
  batch; resuming works, but costs an image pull.
- **Default retention period**: keep it well above the time until you hand back
  (a codespace inactive for longer is deleted, with its captures).

## 4. Run your slice

```bash
python3 capture/run.py --tier p0 --labs 3 --slice i/n --dry-run   # estimate first
python3 capture/run.py --tier p0 --labs 3 --slice i/n --yes       # the batch
```

- Keep the browser tab open or the terminal busy; the batch logs to
  `dataset/raw/_logs/`.
- After an idle stop or a restart, run the same command again: finished runs are
  skipped, an interrupted run is redone from scratch.
- Do not edit `capture/matrix.yaml`, `capture/edge.yaml` or `capture/netem.yaml`, do
  not use more than 3 labs, and do not rebuild images: any of these makes the merge
  reject your shard.

## 5. Verify before handing back

```bash
python3 capture/run.py --tier p0 --slice i/n --status   # must print COMPLETE
```

If runs are listed as exhausted (failed or mismatched three times), run the batch once
more with `--fill-gaps` and check `--status` again. Tell the maintainer about runs that
still fail; never edit the manifest by hand.

## 6. Hand back

The manifest, on a branch:

```bash
git checkout -b shard/p0-i-of-n
git add dataset/manifest.jsonl
git commit -m "data: Add p0 slice i/n manifest."
git push -u origin shard/p0-i-of-n
```

The captures (never commit them):

```bash
python3 tools/export.py --tier p0 --slice i/n
```

Upload `dataset/export/p0-slice-i-of-n-*.tar.zst` and its `.sha256` where the
maintainer says (for example as assets of a GitHub release on this repository). Keep
the codespace until the maintainer confirms the merge.

The maintainer merges all shards with

```bash
python3 tools/merge.py git:origin/shard/p0-1-of-n git:origin/shard/p0-2-of-n ...
```

which rejects any shard built from a different plan, seed or image set.
