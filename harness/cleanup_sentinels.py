"""Idempotent, checksummed cleanup of DEMO_SENTINEL-wrapped blocks.

Walks the sentinel allowlist, removes every matched block, writes a pre/post
SHA256 log, and refuses to touch files with unclosed markers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

START_RE = re.compile(r"^# DEMO_SENTINEL_START (\S+) (\S+)\s*$")
END_RE_FMT = r"^# DEMO_SENTINEL_END {scenario}\s*$"


def _allowlisted_files(home: Path) -> list[Path]:
    candidates = [
        home / ".claude" / "settings.local.json",
        home / ".mcp.json",
    ]
    gitconfig_d = home / ".gitconfig.d"
    if gitconfig_d.is_dir():
        candidates.extend(p for p in gitconfig_d.iterdir() if p.is_file())
    hooks = Path(".git") / "hooks"
    if hooks.is_dir():
        candidates.extend(p for p in hooks.iterdir() if p.is_file() and p.name.startswith("demo_"))
    return [c for c in candidates if c.exists()]


def _strip_blocks(text: str) -> tuple[str, int]:
    """Remove every matched sentinel block. Raise ValueError if an unclosed block is seen."""
    out: list[str] = []
    lines = text.splitlines(keepends=True)
    i = 0
    removed = 0
    while i < len(lines):
        m = START_RE.match(lines[i].rstrip("\n"))
        if not m:
            out.append(lines[i])
            i += 1
            continue
        scenario = m.group(1)
        end_pattern = re.compile(END_RE_FMT.format(scenario=re.escape(scenario)))
        j = i + 1
        while j < len(lines) and not end_pattern.match(lines[j].rstrip("\n")):
            j += 1
        if j >= len(lines):
            raise ValueError(f"unclosed sentinel for {scenario} starting at line {i + 1}")
        i = j + 1
        removed += 1
    return "".join(out), removed


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--log", default="capture/cleanup.log")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    home = Path(args.home)
    log_path = Path(args.log)
    files = _allowlisted_files(home)
    log_entries: list[dict[str, object]] = []
    rc = 0
    for path in files:
        original = path.read_text()
        pre = _sha256(path)
        try:
            stripped, removed = _strip_blocks(original)
        except ValueError as err:
            print(f"refusing {path}: {err}", file=sys.stderr)
            rc = 2
            continue
        if removed == 0:
            continue
        if not args.dry_run:
            path.write_text(stripped)
        post = _sha256(path) if not args.dry_run else pre
        log_entries.append(
            {
                "ts": datetime.now(tz=UTC).isoformat(),
                "path": str(path),
                "removed": removed,
                "pre_sha256": pre,
                "post_sha256": post,
                "dry_run": args.dry_run,
            }
        )

    if log_entries:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a") as fh:
            for entry in log_entries:
                fh.write(json.dumps(entry) + "\n")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
