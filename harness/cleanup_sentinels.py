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
SHA_RE = re.compile(r"^# DEMO_SENTINEL_SHA256 ([0-9a-f]{64})\s*$")
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
    """Remove every matched sentinel block.

    If a block declares a SHA256 digest (written by exfil.write_sentinel_block),
    verify the content body against the digest before removal and raise
    ValueError on mismatch — any third-party mutation inside sentinel markers
    must surface as a cleanup failure rather than a silent strip.

    Blocks with no SHA line (legacy or hand-crafted) are removed without
    verification.

    Raises ValueError on unclosed sentinel, malformed digest, or content
    tampering.
    """
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
        # Optional SHA line immediately after START
        body_start = i + 1
        expected_digest: str | None = None
        if body_start < len(lines):
            sha_match = SHA_RE.match(lines[body_start].rstrip("\n"))
            if sha_match:
                expected_digest = sha_match.group(1)
                body_start += 1
        j = body_start
        while j < len(lines) and not end_pattern.match(lines[j].rstrip("\n")):
            j += 1
        if j >= len(lines):
            raise ValueError(f"unclosed sentinel for {scenario} starting at line {i + 1}")
        if expected_digest is not None:
            body = "".join(lines[body_start:j])
            actual = hashlib.sha256(body.encode()).hexdigest()
            if actual != expected_digest:
                raise ValueError(
                    f"sentinel block for {scenario} starting at line {i + 1} "
                    f"failed SHA256 verification (expected {expected_digest[:12]}..., "
                    f"got {actual[:12]}...) — content was tampered with"
                )
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
