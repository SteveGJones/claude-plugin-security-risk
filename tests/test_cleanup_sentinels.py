"""Tests for harness.cleanup_sentinels — idempotent checksummed block removal."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "harness.cleanup_sentinels", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _sentinel_block(scenario: str, body: str) -> str:
    return (
        f"# DEMO_SENTINEL_START {scenario} 2026-04-18T00:00:00+00:00\n"
        f"{body}\n"
        f"# DEMO_SENTINEL_END {scenario}\n"
    )


def test_cleanup_removes_block_and_is_idempotent(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("keep-me\n" + _sentinel_block("scenario_17_hook_abuse", '"x": 1'))
    result1 = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result1.returncode == 0
    assert settings.read_text() == "keep-me\n"
    result2 = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result2.returncode == 0
    assert settings.read_text() == "keep-me\n"


def test_cleanup_dry_run_does_not_touch_disk(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    body = "keep-me\n" + _sentinel_block("scenario_17_hook_abuse", "x")
    settings.write_text(body)
    digest_before = hashlib.sha256(settings.read_bytes()).hexdigest()
    result = _run(["--home", str(tmp_path), "--dry-run"], cwd=Path.cwd())
    assert result.returncode == 0
    digest_after = hashlib.sha256(settings.read_bytes()).hexdigest()
    assert digest_before == digest_after


def test_cleanup_refuses_unclosed_sentinel(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        "# DEMO_SENTINEL_START scenario_17_hook_abuse 2026-04-18T00:00:00+00:00\nunclosed\n"
    )
    result = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result.returncode != 0
    assert "unclosed" in (result.stderr + result.stdout).lower()


def test_cleanup_emits_checksum_log(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(_sentinel_block("scenario_17_hook_abuse", "x"))
    result = _run(
        ["--home", str(tmp_path), "--log", str(capture / "cleanup.log")],
        cwd=Path.cwd(),
    )
    assert result.returncode == 0
    log_lines = (capture / "cleanup.log").read_text().strip().splitlines()
    entry = json.loads(log_lines[-1])
    assert "pre_sha256" in entry and "post_sha256" in entry


def test_cleanup_verifies_per_block_sha256_and_refuses_tampered_content(
    tmp_path: Path,
) -> None:
    """A sentinel block written by exfil.write_sentinel_block declares a
    SHA256 of its body; if that body is modified in-place by a third party,
    cleanup must refuse to strip the block rather than silently erase the
    tampered content. Matches SAFETY.md §3 tamper-evidence contract."""
    import sys

    # Add repo root to sys.path so we can import plugin_mcp from the test
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from plugin_mcp import exfil

    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)

    # Write a legitimate sentinel block through the chokepoint
    import unittest.mock as _mock

    with _mock.patch.object(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path / ".claude",)):
        exfil.write_sentinel_block(settings, "scenario_17_hook_abuse", '"legitimate": 1')

    # Tamper with the content body inside the sentinel markers
    text = settings.read_text()
    tampered = text.replace('"legitimate": 1', '"tampered": 1')
    assert tampered != text
    settings.write_text(tampered)

    # Cleanup must refuse
    result = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result.returncode != 0
    assert "sha256" in (result.stderr + result.stdout).lower()
    # Tampered block remains on disk — not silently erased
    assert '"tampered": 1' in settings.read_text()


def test_cleanup_accepts_untampered_sha256_block(tmp_path: Path) -> None:
    """A sentinel block written through the chokepoint (with SHA line)
    must be strippable when the content is intact."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from plugin_mcp import exfil

    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)

    import unittest.mock as _mock

    with _mock.patch.object(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path / ".claude",)):
        exfil.write_sentinel_block(settings, "scenario_17_hook_abuse", '"ok": 1')

    assert "DEMO_SENTINEL_SHA256" in settings.read_text()
    result = _run(["--home", str(tmp_path)], cwd=Path.cwd())
    assert result.returncode == 0
    assert settings.read_text() == ""


class TestFullReplaceRestore:
    """Tests for the FULL_REPLACE second-pass restoration."""

    def _make_fake_variants_module(self, tmp_path: Path, attr_value: str) -> str:
        """Create a temp package with a BENIGN constant and return its dotted name."""
        pkg = tmp_path / "fake_variants_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(f"BENIGN = {attr_value!r}\n")
        import sys

        sys.path.insert(0, str(tmp_path))
        return "fake_variants_pkg:BENIGN"

    def test_full_replace_restore_overwrites_with_benign(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from plugin_mcp import exfil

        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        restore = self._make_fake_variants_module(tmp_path, "benign body\n")
        target = tmp_path / "agent.md"
        exfil.write_sentinel_block(
            target,
            "scenario_test",
            "REPLACED BODY\n",
            full_replace=True,
            restore_module=restore,
        )
        from harness import cleanup_sentinels

        exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_path], dry_run=False)
        assert exit_code == 0
        assert target.read_text() == "benign body\n"

    def test_full_replace_refuses_on_sha_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from plugin_mcp import exfil

        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        restore = self._make_fake_variants_module(tmp_path, "benign body\n")
        target = tmp_path / "agent.md"
        exfil.write_sentinel_block(
            target,
            "scenario_test",
            "REPLACED BODY\n",
            full_replace=True,
            restore_module=restore,
        )
        # Simulate unexpected post-hoc edit: change the body without updating SHA.
        edited = target.read_text().replace("REPLACED BODY", "EDITED")
        target.write_text(edited)
        from harness import cleanup_sentinels

        exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_path], dry_run=False)
        assert exit_code != 0
        # File should be left as-is rather than silently restored over unknown edits.
        assert "EDITED" in target.read_text()

    def test_full_replace_idempotent_no_trailer(self, tmp_path: Path) -> None:
        target = tmp_path / "agent.md"
        target.write_text("plain benign\n")
        from harness import cleanup_sentinels

        exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_path], dry_run=False)
        assert exit_code == 0
        assert target.read_text() == "plain benign\n"

    def test_full_replace_dry_run_makes_no_change(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from plugin_mcp import exfil

        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        restore = self._make_fake_variants_module(tmp_path, "benign body\n")
        target = tmp_path / "agent.md"
        exfil.write_sentinel_block(
            target,
            "scenario_test",
            "REPLACED BODY\n",
            full_replace=True,
            restore_module=restore,
        )
        pre = target.read_text()
        from harness import cleanup_sentinels

        exit_code = cleanup_sentinels.restore_full_replace_sentinels([tmp_path], dry_run=True)
        assert exit_code == 0
        assert target.read_text() == pre
