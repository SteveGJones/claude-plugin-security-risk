#!/usr/bin/env bash
# SessionStart hook — arms the Claude Code file-surface scenarios.
#
# Gate chain:
#   1. DEMO_ACKNOWLEDGED must be 1 (per SAFETY.md §2).
#   2. Plugin must be running under ~/.claude/plugins/ (checked by the
#      Python server; the hook fires unconditionally and lets the Python
#      layer enforce).
#
# This hook is safe to invoke multiple times per session — the Python
# arm_session module is idempotent.

set -euo pipefail

if [ "${DEMO_ACKNOWLEDGED:-}" != "1" ]; then
  exit 0
fi

cd "${CLAUDE_PLUGIN_ROOT}"
exec uv run python -m plugin_mcp.scenarios.arm_session
