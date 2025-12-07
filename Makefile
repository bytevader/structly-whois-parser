PYTHON ?= python3
PACKAGE := structly_whois
BENCHMARK_BACKENDS ?= structly-whois,whois-parser,python-whois

.PHONY: help lint fmt dev-install test cov build bench publish-test publish

help:
	@echo "Available targets:"
	@echo "  lint           Run Ruff lint checks"
	@echo "  fmt            Apply Ruff formatting"
	@echo "  dev-install    Install project in editable mode with dev deps"
	@echo "  test           Run pytest suite"
	@echo "  cov            Run pytest with coverage report"
	@echo "  build          Build sdist and wheel artifacts"
	@echo "  bench          Execute benchmarks (set BENCHMARK_BACKENDS)"
	@echo "  publish-test   Upload dist/ artifacts to TestPyPI"
	@echo "  publish        Upload dist/ artifacts to PyPI"

lint:
	$(PYTHON) -m ruff check src tests benchmarks

fmt:
	$(PYTHON) -m ruff format src tests benchmarks

lint-fix:
	$(PYTHON) -m ruff check src tests benchmarks --fix --unsafe-fixes

dev-install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	@if $(PYTHON) -m coverage --version >/dev/null 2>&1; then \
		rm -f .coverage; \
		$(PYTHON) -m coverage run --source=src/structly_whois -m pytest; \
		$(PYTHON) -m coverage report; \
	else \
		echo "coverage module not installed; running pytest without coverage" >&2; \
		echo "hint: pip install -e .[dev] to enable coverage" >&2; \
		$(PYTHON) -m pytest -o addopts=''; \
	fi

cov:
	@if $(PYTHON) -m coverage --version >/dev/null 2>&1; then \
		rm -f .coverage; \
		$(PYTHON) -m coverage run --source=src/structly_whois -m pytest; \
		$(PYTHON) -m coverage report; \
		$(PYTHON) -m coverage xml --fail-under=0; \
	else \
		echo "coverage module not installed; install via 'pip install coverage' or 'pip install -e .[dev]'" >&2; \
		exit 1; \
	fi

build:
	rm -rf dist
	$(PYTHON) -m build

bench:
	$(PYTHON) benchmarks/run_benchmarks.py --backends $(BENCHMARK_BACKENDS)

publish-test: build
	TEST_PYPI_API_TOKEN=$${TEST_PYPI_API_TOKEN:?missing} \
		$(PYTHON) -m maturin upload -r testpypi --username __token__ --password "$$TEST_PYPI_API_TOKEN" dist/*

publish: build
	PYPI_API_TOKEN=$${PYPI_API_TOKEN:?missing} \
		$(PYTHON) -m maturin upload --username __token__ --password "$$PYPI_API_TOKEN" dist/*
