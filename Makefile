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
	uv run python -m harness.cleanup_sentinels
	uv run python -m harness.cleanup

kill-demo:
	-uv run python -m harness.cleanup_sentinels
	-@while read -r pid rest; do kill -TERM "$$pid" 2>/dev/null || true; done < capture/pids.txt 2>/dev/null || true
	-@echo benign > mode.txt
	-git tag -d latest-demo 2>/dev/null || true
	@echo "kill-demo: done. See SAFETY.md."

compare:
	./harness/compare.sh
