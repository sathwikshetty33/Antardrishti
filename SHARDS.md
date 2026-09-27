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
- machine type **4-core**
- the codespace bills your own account's free quota (check github.com/settings/billing)

The container runs `lab/bootstrap.sh` on creation: tools, the pinned lab images and the
media snapshot. Check it:

```bash
bash lab/images.sh pull          # every line must say "pulled" or "present ghcr.io/...@sha256:..."
bash lab/images.sh pull-media    # "media from ghcr.io/...": the pinned snapshot
python3 lab/preflight.py         # every check ok ("pinned images" included); netem available
```

If a line says "pull refused", stop and ask the maintainer for package access: images
are never built locally (runs on local builds are rejected at merge).

## 3. Raise the idle timeout

github.com/settings/codespaces:

- **Default idle timeout**: the maximum (240 minutes). A stopped codespace pauses the
  batch; resuming works, but costs an image pull.
- **Default retention period**: keep it well above the time until you hand back
  (a codespace inactive for longer is deleted, with its captures).

## 4. Run your slice

```bash
python3 capture/run.py --tier p1 --labs 1 --slice i/n --dry-run   # estimate first
python3 capture/run.py --tier p1 --labs 1 --slice i/n --yes       # the batch
```

The `plan:` line of the dry run (seed, design, plan, images) must be the same on every
slice. A P1 slice runs its share in a seeded order; its traffic runs are captured alone
on the machine (`timing_valid`).

- Keep the browser tab open or the terminal busy; the batch logs to
  `dataset/raw/_logs/`.
- After an idle stop or a restart, run the same command again: finished runs are
  skipped, an interrupted run is redone from scratch.
- Do not edit `capture/matrix.yaml`, `capture/edge.yaml` or `capture/netem.yaml`, do
  not use more than 1 lab (parallel labs bias timing), and do not rebuild images: any of these makes the merge
  reject your shard.

## 5. Verify before handing back

```bash
python3 capture/run.py --tier p1 --slice i/n --status   # must print COMPLETE
```

If runs are listed as exhausted (failed or mismatched three times), run the batch once
more with `--fill-gaps` and check `--status` again. Tell the maintainer about runs that
still fail; never edit the manifest by hand.

## 6. Hand back

The manifest, on a branch:

```bash
git checkout -b shard/p1-i-of-n
git add dataset/manifest.jsonl
git commit -m "data: Add p1 slice i/n manifest."
git push -u origin shard/p1-i-of-n
```

The captures (never commit them):

```bash
python3 tools/export.py --tier p1 --slice i/n
```

Upload `dataset/export/p1-slice-i-of-n-*.tar.zst` and its `.sha256` where the
maintainer says (for P1: the draft release `p1-slice<i>` on this repository), then
download them again and check with `sha256sum -c`. Keep the codespace until the
maintainer confirms the merge.

The maintainer merges the tier's lines of all shards with

```bash
python3 tools/merge.py --tier p1 dataset/manifest.jsonl git:origin/shard/p1-1-of-n git:origin/shard/p1-2-of-n ...
```

which rejects any shard built from a different plan, seed, design or image set.
