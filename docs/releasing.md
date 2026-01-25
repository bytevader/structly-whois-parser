# Releasing structly-whois

This project follows a simple tag-driven release workflow. Keep releases predictable by following the checklist below.

## 1. Prep the version bump

1. Decide the next semantic version (major/minor/patch). Updating public behaviour or dependencies? Prefer a minor release; backwards-incompatible tweaks require a major bump.
2. Update `src/structly_whois/__about__.py` (or wherever the version constant lives) with the new version.
3. Run `pip install -e '.[dev]'` if needed so tooling is up to date.

## 2. Update the changelog

1. Edit `CHANGELOG.md`:
   - Add a section for the new version with the release date.
   - Summarise noteworthy changes (features/fixes/breaking changes). Avoid describing refactors that don’t affect users.
2. Link PR numbers when possible; keep bullets short.
3. Run `make lint && make test` to ensure the release commit is green.

## 3. Tag and publish

1. Commit the version + changelog updates (e.g. `chore: release vX.Y.Z`).
2. Create a signed tag: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
3. Push the branch and tag: `git push origin dev && git push origin vX.Y.Z`.
4. GitHub Actions will build wheels/sdists and publish to PyPI when the tag arrives. Monitor the workflow for success before announcing the release.

## 4. Security / provenance

All published artifacts are built by GitHub Actions. If you later add signing or Sigstore attestations, document the commands here (e.g. `pip install sigstore` + `python -m sigstore sign dist/*.whl`). For now, ensure trusted builders only have access to PyPI tokens and keep them rotated.

## 5. Post-release

1. Open a new `Unreleased` section in `CHANGELOG.md` so upcoming work has a target.
2. If the release introduced breaking changes or migration steps, update `README.md`/docs accordingly.
3. Celebrate! 🎉
