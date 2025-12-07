# Contributing

Thanks for helping improve structly_whois! 
This guide covers local setup, quality checks, and how releases are cut. 
The project builds on top of [Structly](https://pypi.org/project/structly/), so familiarity with its configuration model helps when working on parsers or overrides.

## Local setup

1. Fork/clone the repo and create a virtual environment.
2. Install dependencies: `pip install -e '.[dev]'`
3. Activate the env whenever you work on the project.

Useful Make targets:

```bash
make lint     # Ruff static checks
make fmt      # Ruff formatter
make test     # pytest + coverage (requires ≥90%)
make cov      # coverage xml/report (CI uses this target)
make bench    # Compare structly_whois vs whois-parser / python-whois
```

## Pull requests

- Keep PRs focused; split unrelated changes when possible.
- Include tests for new behavior (fixtures live under `tests/samples/`).
- Document user-visible changes in `README.md` or `CHANGELOG.md` as needed.
- Ensure `make lint test` passes locally before opening a PR. GitHub Actions reruns lint/test/build on every push.

## Versioning & releases

- The canonical version lives in `src/structly_whois/__about__.py`. Update it as part of release PRs.
- Follow SemVer. Tags must use the `vX.Y.Z` prefix and are cut from `master`.
- Pushes to `dev` automatically publish wheels to TestPyPI. Tags publish to PyPI (both use the GitHub Actions workflow).
- Keep `CHANGELOG.md` up to date; note breaking changes explicitly.

## Publishing flow

1. Land feature/fix work on `dev` via pull requests.
2. When ready, open a release PR that bumps `__about__.__version__` and updates `CHANGELOG.md`.
3. Merge the release PR into `master`, tag `vX.Y.Z`, and push the tag.
4. CI builds wheels/sdists and uploads them to PyPI using the configured API tokens.

Questions? Open an issue or reach out via the repository discussions.
