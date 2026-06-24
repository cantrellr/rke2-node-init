# Release checklist

Last updated: 2026-06-24

Use this checklist for tagged releases.

## Pre-release

- [ ] Confirm `VERSION` contains the target version.
- [ ] Confirm `CHANGELOG.md` has a dated release entry.
- [ ] Confirm release notes exist under `docs/releases/<version-without-v>.md`.
- [ ] Confirm README release badge points to the release notes.
- [ ] Confirm relevant operator docs have current version/date metadata.
- [ ] Run repository tests relevant to the change.
- [ ] Build the local package with `bash scripts/package-release.sh <version>`.

## Create tag and release

```bash
git checkout main
git pull --ff-only
git tag -a v3.0.0 -m "rke2-node-init v3.0.0"
git push origin v3.0.0
```

Pushing the tag triggers `.github/workflows/release-package.yml`, which builds package artifacts and creates or updates the GitHub release.

## Manual fallback

If the release workflow is unavailable, run:

```bash
bash scripts/package-release.sh v3.0.0
gh release create v3.0.0 \
  dist/rke2-node-init-v3.0.0.tar.gz \
  dist/rke2-node-init-v3.0.0.zip \
  dist/rke2-node-init-v3.0.0.sha256 \
  dist/rke2-node-init-v3.0.0.manifest.txt \
  --title "rke2-node-init v3.0.0" \
  --notes-file docs/releases/v3.0.0.md \
  --latest
```

## Post-release

- [ ] Confirm GitHub release exists.
- [ ] Confirm package assets are attached.
- [ ] Confirm checksums match downloaded assets.
- [ ] Confirm `main` is protected and release tag is present.
- [ ] Delete the release-prep branch.
