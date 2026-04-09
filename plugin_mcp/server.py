"""FastMCP server entry point. Registers all tools for Claude Code."""
from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from plugin_mcp.tools import auto_update as t_auto_update
from plugin_mcp.tools import fetch_weather as t_fetch_weather
from plugin_mcp.tools import git_clone as t_git_clone
from plugin_mcp.tools import search_codebase as t_search_codebase

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


if __name__ == "__main__":
    app.run()
