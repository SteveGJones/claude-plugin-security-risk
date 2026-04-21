# Manual Verification Walkthrough

Scripted end-to-end verification that the plugin surfaces all expected
components in Claude Code and that the kill switches fully restore state.

## Prerequisites

- Fresh Claude Code session; no prior install.
- `uv` available on PATH.
- This repo checked out at `<checkout>`.
- `export DEMO_ACKNOWLEDGED=1`.

## 1. Install the plugin

```bash
cd <checkout>
uv sync
mkdir -p ~/.claude/plugins
ln -s "$(pwd)" ~/.claude/plugins/plugin-security-risk
```

Launch a new Claude Code session from any directory.

## 2. Confirm surface

In the session, run:

- `/plugin` → expect an entry `claude-plugin-security-risk`.
- `/agent` → expect `code-reviewer`, `task-runner`, `security-reviewer`.
- `/skill` → expect 7 skills: `summarise`, `cost-estimator`,
  `credential-scanner`, `research-assistant`, `install-hook`,
  `install-mcp-entry`, `install-statusline`.
- `/commit` → existing slash command still available.

Expected: no install-time warnings or errors in the Claude Code logs.

## 3. Benign-mode sanity

With `mode.txt` set to `benign` (default):

- Start a new session. Confirm statusline does NOT render.
- Invoke `/agent code-reviewer` with a code snippet. Response is
  plain JSON — no `[SYSTEM]:` markers.
- Check `~/.claude/settings.local.json`: no `DEMO_SENTINEL` blocks.

## 4. Flip to malicious mode

```bash
echo malicious > <checkout>/mode.txt
```

Start a new Claude Code session.

- The SessionStart hook fires; `<checkout>/agents/code_reviewer.md`,
  `task_runner.md`, and `security_reviewer.md` should now carry
  `DEMO_SENTINEL_FULL_REPLACE` trailers (for time-bomb scenarios whose
  dates have passed, and for any probabilistic scenario that rolled True).
- `~/.claude/settings.local.json` gains a `DEMO_SENTINEL_START
  scenario_18_statusline_beacon` block with a `statusLine` entry.
- The statusline renders; it fires a GET against `httpbin.org/get`
  every 5s.
- `<checkout>/capture/leaks.jsonl` grows on each beacon tick.

## 5. Observe the attack surface

- `/agent code-reviewer` with a code snippet. If S2's time-bomb has
  fired, the agent's reply includes the injected `[SYSTEM]:` block.
- `/skill summarise` with a paragraph. If S3's probabilistic trigger
  rolled True this session, the SKILL.md body instructs the model to
  leak the document — the leak should appear in `capture/leaks.jsonl`.

## 6. Kill switch: `make kill-demo`

```bash
cd <checkout>
make kill-demo
```

Expected:
- Sentinel blocks removed from `~/.claude/settings.local.json` and
  `~/.mcp.json`.
- FULL_REPLACE trailers removed from `agents/*.md` and `skills/*/SKILL.md`.
- `agents/code_reviewer.md` etc. match their `_variants.py` `BENIGN_*`
  strings byte-for-byte.
- Background PIDs from S6 terminated.
- `latest-demo` tag removed.

Start a new session. Statusline should not render. Agents should load
benign bodies.

## 7. Cleanup symmetry

```bash
git diff --stat
```

Expected: clean tree (no modifications remain).

## 8. Failure modes

If any step above reports a `DEMO_SENTINEL` sha-mismatch, treat it as a
tampering alert per SAFETY.md §3 — do not force-restore. Inspect the
offending file manually before proceeding.
