# Maintenance releases

DockVault supports more than one release line at a time: each minor line from 0.33 on receives
security fixes until six months after the next minor release ships ([SECURITY.md](../../.github/SECURITY.md)).
This guide says what that means for an install, and how the maintainers release a fix on a line that
is no longer the newest.

## Release lines

A release line is every release that shares a major and minor version: 0.33.0, 0.33.1 and 0.33.2 are
the 0.33 line.

- The newest line is released from `main`.
- Once a newer minor release exists (0.34.0, say), fixes for the older line come from a branch named
  `release/0.33`. It is cut from the newest 0.33 release tag and holds only that line's fixes. Before
  0.34.0 exists, a 0.33 patch release comes from `main` like any other release.
- A release candidate is pushed as `candidate/X.Y.Z`. Candidates get the full test run on demand;
  pushes to `main` and to `release/X.Y` branches run the merge checks automatically.

## Image tags

| Tag | Names | Moves |
|---|---|---|
| `ghcr.io/dockvault/vault:vX.Y.Z` | one release | never |
| `ghcr.io/dockvault/vault:vX.Y` | the newest release of line X.Y | to each new patch release of that line |
| `ghcr.io/dockvault/vault:latest` | the highest version released | to each release that is higher than every other |

A patch release of an older line moves its `:vX.Y` tag only. It never moves `:latest`, and GitHub's
"latest release" stays on the highest version too. Before any tag moves, the release workflow checks
the version the tag holds now and refuses to move it backwards.

## For an install on an older line

- `dockvault.py update` lists the published releases and what each move involves, from the upgrade
  matrix (`docs/upgrade-matrix.json`). A patch release on your own line is normally the smallest
  move that fixes a vulnerability; moving to the newer line works too, and the matrix says whether
  that move needs a backup or cannot be undone.
- To have `docker compose pull` follow your line, set `DOCKVAULT_IMAGE=ghcr.io/dockvault/vault:vX.Y`
  in `.env`. To choose each release yourself, set the exact `:vX.Y.Z`.
- Going back to an older release is protected from 0.33.1 on: an image refuses to start on data a
  newer release has changed in a way it cannot read, and its log says how to undo the change with
  the newer release. 0.33.0 and earlier do not check, so going back to them is not protected
  (see "Database migrations" in the README).

## For maintainers: releasing

### What the release gate accepts

The release workflow runs `.github/scripts/release_gate.py` on the tagged commit, again just before
it logs in to the registry, and refuses to publish unless:

- the tag is an **annotated** tag (`git tag -a vX.Y.Z -m "vX.Y.Z"`), whose own time decides which
  releases this one's matrix must already know about. Check with `git cat-file -t vX.Y.Z`, which
  must print `tag`, before pushing it: a lightweight tag cannot be released and, once version tags
  are protected, cannot be replaced either;
- the tagged commit is on `main` and the version is above every other release, except a release
  already tagged on top of this commit (two releases cut the same day); **or**
- the tagged commit is on `release/X.Y` for its own line, a newer minor release has already been
  released from `main`, the version is above every other release of its line, and the branch starts
  at a released X.Y tag on `main`;
- the upgrade matrix declares this release and every release tagged before it;
- no GitHub Release exists yet for the tag. To publish a failed release again, fix the cause, delete
  the GitHub Release if one was created, and re-run the workflow; never move the tag.

A release on a line past its support date is published with a warning, not refused: a serious fix
may still be worth shipping late.

The gate also decides what the release moves: `:vX.Y` when it is the newest release of its line,
`:latest` and GitHub's "latest release" when it is the highest release of all, and which earlier
release its notes compare against. A release from a `release/X.Y` branch says so in the first line
of its notes.

### Two releases the same day, before the older line has a branch

Tag the older release first and wait until its release run has finished publishing: its GitHub
Release exists, and `:vX.Y` and `:latest` resolve to its digest. Only then tag the newer release.
If the older release's run fails, fix it and re-run it before tagging the newer one. Tagged the
other way round, or before the older run finishes, the older release leaves `:latest` on the
release before it until the newer one publishes.

### A fix on several lines

1. Prepare a candidate for each supported line the fix affects: the newest line from `main`, each
   older line as `candidate/X.Y.N` from its `release/X.Y` branch. Run the full test run on every
   candidate.
2. Tag the older lines first. Their matrix is `main`'s plus their own new entry, the edge into it
   and an edge from it up to the newest release, without the advisory, and their notes say that a
   security fix is included and that its details are published with the newest line's release the
   same day. The validator requires that way up: every release that is not end-of-life must reach
   the newest one.
3. Tag the newest line last, within hours. Its release commit adds the advisory once, complete, with
   the fix on every line and the older releases' entries. Each older release's edge into a release
   the fix leaves affected becomes an edge to the newest line's fix: the validator refuses an edge
   that brings a fixed vulnerability back. Such an edge skips releases, so it must be at least as
   cautious as the route it replaces (the edge into the newest line from the older one, then that
   line up to the fix): a backup if any step needs one, irreversible if any step is, every step's
   conditions, and no release an upgrade must land on in between. `main` moves forward with it.
4. Bring each older branch's matrix back in line with `main`'s:

   ```bash
   git show origin/main:docs/upgrade-matrix.json > /tmp/main.json
   python3 .github/scripts/matrix_sync.py sync --main /tmp/main.json --branch docs/upgrade-matrix.json
   python3 .github/scripts/matrix_sync.py check /tmp/main.json docs/upgrade-matrix.json
   ```

A fix that only an older line needs is followed, within the hour, by a commit to `main` that
changes nothing but the matrix: the documentation site, the in-app check and `dockvault.py` read
`main`'s matrix, so the release is not described anywhere until it lands there.

```bash
git show origin/release/X.Y:docs/upgrade-matrix.json > /tmp/line.json
python3 .github/scripts/matrix_sync.py sync --main docs/upgrade-matrix.json \
    --branch /tmp/line.json --output docs/upgrade-matrix.json
```

A release commit that adds references also shortens the old ones, after every other matrix edit:
`python3 .github/scripts/matrix_sync.py compact docs/upgrade-matrix.json`.

### After each release

Check, without logging in to the registry:

- `:vX.Y.Z`, `:vX.Y` and, for the highest release, `:latest` resolve to the digest the workflow
  scanned, and the image's version label and `VERSION` name the release;
- the release assets are attached, and the `upgrade.json` asset equals the matrix of the tagged
  commit;
- GitHub's "latest release" is the highest version;
- `main`'s matrix declares every released tag, including this one;
- the upgrades page of the documentation site lists the new release, its edges and its advisories.
