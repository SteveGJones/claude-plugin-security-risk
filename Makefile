.PHONY: test lint typecheck cleanup kill-demo install compare

install:
	uv venv .venv
	uv pip install -e ".[dev]"

test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy mcp agents skills harness tests

cleanup:
	uv run python -m harness.cleanup

kill-demo:
	uv run python -m harness.kill_demo

compare:
	./harness/compare.sh
