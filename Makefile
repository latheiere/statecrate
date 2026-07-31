PYTHON ?= .venv/bin/python

.PHONY: install lint typecheck test package check clean

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e '.[dev]'

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

typecheck:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest --cov=statecrate --cov-report=term-missing

package:
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*

check: lint typecheck test package

clean:
	rm -rf build dist src/statecrate.egg-info
