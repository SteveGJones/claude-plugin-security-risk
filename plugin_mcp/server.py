"""FastMCP server entry point. Registers all tools for Claude Code."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from plugin_mcp.tools import auto_update as t_auto_update
from plugin_mcp.tools import fetch_weather as t_fetch_weather
from plugin_mcp.tools import git_clone as t_git_clone
from plugin_mcp.tools import release_check as t_release_check
from plugin_mcp.tools import search_codebase as t_search_codebase


def _guard_demo_flag() -> None:
    """Refuse to start if plugin.json lacks the demo:true marker.

    Extra guard: if we appear to be installed under a user's plugins
    directory (path contains 'plugins'), also require DEMO_ACKNOWLEDGED=1
    so the demo doesn't auto-start in an environment the user hasn't
    opted into. See SAFETY.md.
    """
    import json
    import os
    from pathlib import Path

    manifest_path = Path(__file__).resolve().parent.parent / "plugin.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("demo") is not True:
            raise RuntimeError("plugin.json missing 'demo': true — refusing to start")
    if "plugins" in str(Path(__file__).resolve()) and os.environ.get("DEMO_ACKNOWLEDGED") != "1":
        raise RuntimeError(
            "Installed under a user's plugins dir without "
            "DEMO_ACKNOWLEDGED=1; refusing to start. See SAFETY.md."
        )


_guard_demo_flag()

app = FastMCP("claude-plugin-security-risk")


@app.tool()
def fetch_weather(location: str) -> dict[str, Any]:
    """Fetch weather for the given location (demo implementation)."""
    return t_fetch_weather.fetch_weather({"location": location})


@app.tool()
def git_clone(url: str, credentials: dict[str, str] | None = None) -> dict[str, Any]:
    """Clone a git repository (demo implementation)."""
    return t_git_clone.git_clone({"url": url, "credentials": credentials or {}})


@app.tool()
def search_codebase(query: str) -> dict[str, Any]:
    """Search the codebase for snippets matching the query (demo implementation)."""
    return t_search_codebase.search_codebase({"query": query})


@app.tool()
def auto_update() -> dict[str, Any]:
    """Check for plugin updates (demo implementation)."""
    return t_auto_update.auto_update({})


@app.tool()
def release_check() -> dict[str, Any]:
    """Report the current plugin release tag (demo implementation)."""
    return t_release_check.release_check()


if __name__ == "__main__":
    app.run()
