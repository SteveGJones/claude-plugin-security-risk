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

FULL_REPLACE_START_RE = re.compile(r"^<!-- DEMO_SENTINEL_FULL_REPLACE_START (\S+) (\S+) -->\s*$")
FULL_REPLACE_SHA_RE = re.compile(r"^<!-- DEMO_SENTINEL_SHA256 ([0-9a-f]{64}) -->\s*$")
FULL_REPLACE_RESTORE_RE = re.compile(r"^<!-- DEMO_SENTINEL_RESTORE_MODULE (\S+) -->\s*$")
FULL_REPLACE_END_RE_FMT = r"^<!-- DEMO_SENTINEL_FULL_REPLACE_END {scenario} -->\s*$"


def _repo_roots(repo: Path | None) -> list[Path]:
    if repo is None:
        return []
    return [repo / "agents", repo / "skills"]


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


def _restore_one(path: Path) -> tuple[bool, str]:
    """Try to restore `path` from its FULL_REPLACE trailer.

    Returns (restored, message). restored=True on success, False if no
    trailer was found. Raises ValueError on SHA mismatch or malformed trailer.
    """
    import importlib

    text = path.read_text()
    lines = text.splitlines(keepends=True)
    # Find the trailer. It lives at the END of the file, so scan backwards
    # for FULL_REPLACE_START.
    start_idx: int | None = None
    scenario: str | None = None
    for idx in range(len(lines) - 1, -1, -1):
        m = FULL_REPLACE_START_RE.match(lines[idx].rstrip("\n"))
        if m:
            start_idx = idx
            scenario = m.group(1)
            break
    if start_idx is None or scenario is None:
        return (False, "")
    # Parse the next three lines: SHA, RESTORE_MODULE, END.
    if start_idx + 3 >= len(lines):
        raise ValueError(f"{path}: incomplete FULL_REPLACE trailer")
    sha_m = FULL_REPLACE_SHA_RE.match(lines[start_idx + 1].rstrip("\n"))
    restore_m = FULL_REPLACE_RESTORE_RE.match(lines[start_idx + 2].rstrip("\n"))
    end_re = re.compile(FULL_REPLACE_END_RE_FMT.format(scenario=re.escape(scenario)))
    end_m = end_re.match(lines[start_idx + 3].rstrip("\n"))
    if not sha_m or not restore_m or not end_m:
        raise ValueError(f"{path}: malformed FULL_REPLACE trailer for {scenario}")
    expected_digest = sha_m.group(1)
    restore_module = restore_m.group(1)
    body = "".join(lines[:start_idx])
    actual_digest = hashlib.sha256(body.encode()).hexdigest()
    if actual_digest != expected_digest:
        raise ValueError(
            f"{path}: SHA mismatch for {scenario} — expected {expected_digest}, got {actual_digest}"
        )
    if ":" not in restore_module:
        raise ValueError(f"{path}: RESTORE_MODULE must be 'pkg.mod:ATTR', got {restore_module!r}")
    mod_name, attr_name = restore_module.split(":", 1)
    mod = importlib.import_module(mod_name)
    benign = getattr(mod, attr_name)
    if not isinstance(benign, str):
        raise ValueError(f"{path}: {restore_module} is not a str")
    return (True, benign)


def restore_full_replace_sentinels(roots: list[Path], *, dry_run: bool) -> int:
    """Second pass: restore FULL_REPLACE-sentinel files from their canonical
    benign source in _variants.py modules.

    Returns 0 on clean success, non-zero if any restore refused (SHA mismatch
    or malformed trailer).
    """
    exit_code = 0
    for root in roots:
        if not root.exists():
            continue
        targets = [p for p in root.rglob("*") if p.is_file() and p.suffix in {".md", ".py"}]
        for path in targets:
            text = path.read_text()
            if "DEMO_SENTINEL_FULL_REPLACE_START" not in text:
                continue
            try:
                restored, benign = _restore_one(path)
            except ValueError as e:
                print(f"[cleanup] refused: {e}", file=sys.stderr)
                exit_code = 1
                continue
            if not restored:
                continue
            if dry_run:
                print(
                    f"[cleanup] would restore {path} from trailer "
                    f"(bytes {len(text)} → {len(benign)})"
                )
                continue
            path.write_text(benign)
            print(f"[cleanup] restored {path} (bytes {len(text)} → {len(benign)})")
    return exit_code


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--log", default="capture/cleanup.log")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="Repo root for agents/ + skills/ FULL_REPLACE restoration. "
        "Defaults to walk-up from this file.",
    )
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

    repo = args.repo or Path(__file__).resolve().parent.parent
    repo_roots = _repo_roots(repo)
    fr_exit = restore_full_replace_sentinels(repo_roots, dry_run=args.dry_run)
    if fr_exit:
        rc = fr_exit
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
