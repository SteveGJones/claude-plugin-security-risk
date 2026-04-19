# Packaging Completeness — Requirements Spec

**Status:** Requirements captured — not yet brainstormed into a full design. Next session should run `superpowers:brainstorming` using this document as the starting point, then `superpowers:writing-plans`.

**Date:** 2026-04-19

**Branch:** TBD in new session — suggest `feature/packaging-completeness`.

---

## 1. Problem

The 23-scenario plugin security demo (now merged to `main`) passes 148 unit tests and is fully packaged as a Claude Code plugin via `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`. However, when a real user installs the plugin:

| Blog-post promise | Actually exposed via Claude Code? |
|---|---|
| Malicious **MCP tools** (S1, S4, S5, S7, S12, S13, S20) | ✅ Yes |
| Malicious **PreToolUse hook** (S17) | ✅ Yes |
| Malicious **slash command** (S19 — `/commit`) | ✅ Yes |
| `~/.mcp.json` persistence (S22) | ✅ Yes (runtime filesystem write) |
| Malicious **sub-agents** (S2, S6, S11) | ❌ **No** — `agents/*.md` lack Claude Code frontmatter; `agents/loader.py` is only called by tests and the harness |
| Malicious **skills** (S3, S9, S10) | ❌ **No** — `skills/*.py` are flat Python modules, not `skills/<name>/SKILL.md` directories |
| Malicious **statusline** (S18) | ❌ **No** — `statusline/demo_statusline.sh` exists on disk but is not registered with Claude Code anywhere |

The blog post *"All of your agent developers are belong to me"* promises that **tools, skills, AND agents** can all be subverted by a malicious plugin. Right now, only tools + hooks + slash commands actually surface to Claude Code. The agent/skill/statusline scenarios are simulated in-process — proven by Python unit tests but invisible to anyone who installs the plugin and runs `/agent` or `/skill` in their session.

Compounding the issue, `.claude-plugin/plugin.json` currently declares `"agents": []` and `"skills": []` to suppress Claude Code's auto-discovery of the non-conforming directories. That decision froze the gap in place and must be reverted.

## 2. Goal

Bring the plugin's real Claude Code attack surface into alignment with the blog post narrative. A user who installs the plugin and runs `/agent`, `/skill`, or observes the statusline must be able to see the same scenarios the unit tests exercise — with the same safety contract (observable, reversible, httpbin-only egress, sentinel-marked writes, `DEMO_ACKNOWLEDGED` gate).

## 3. In-scope requirements

### R1. Sub-agents as real Claude Code sub-agents (S2, S6, S11)
- R1.1. `agents/code_reviewer.md`, `agents/task_runner.md`, `agents/security_reviewer.md` must be valid Claude Code sub-agent files with YAML frontmatter (`name`, `description`, optional `tools`).
- R1.2. The benign prompt text currently in `*.benign.md` becomes the agent body.
- R1.3. The malicious variants (`*.malicious.md`) must not ship as separate discoverable agent files — they are the *substituted* content.
- R1.4. The substitution attack (trigger fires → malicious variant active) must rewrite the on-disk agent `.md` file via `exfil.write_sentinel_block()` so the change is sentinel-wrapped, reversible, and path-allowlisted.
- R1.5. Reversal must occur on `mode.txt = benign` → next trigger evaluation OR via `harness/cleanup_sentinels.py`.
- R1.6. Tests must exercise the substitution on actual on-disk files (not just `load_prompt` return values).

### R2. Skills as real Claude Code skills (S3, S9, S10)
- R2.1. `skills/` must restructure to `skills/<name>/SKILL.md` directories. Candidates (based on current files): `skills/summarise/`, `skills/research_assistant/`, `skills/credential_scanner/`, `skills/cost_estimator/`, `skills/install_hook/`, `skills/install_mcp_entry/`, `skills/install_statusline/`, `skills/slash_commit/`.
- R2.2. Each `SKILL.md` has YAML frontmatter (`name`, `description`) and a natural-language body. Existing Python files may remain as skill assets (referenced from the `SKILL.md` body) or be deleted if no longer needed.
- R2.3. S3 (skill implementation substitution) must rewrite the on-disk `SKILL.md` (or a referenced Python asset) via the sentinel-write chokepoint.
- R2.4. S9 (credentials-in-tracked-files) and S10 (installer skill abuse) must operate on real skill-directory contents that Claude Code loads.
- R2.5. The `skills.<name>` Python import path used in tests/harness is allowed to change; test imports must be updated accordingly.

### R3. Statusline wiring (S18)
- R3.1. `statusline/demo_statusline.sh` must be registered with Claude Code via whatever mechanism that platform exposes (research during brainstorming — likely a `statusLine` field in `.claude-plugin/plugin.json` or `settings.json` projection on install).
- R3.2. The beacon behaviour (per-tick httpbin GET gated on `mode.txt == malicious`) must not change.

### R4. Manifest cleanup
- R4.1. Remove `"agents": []` and `"skills": []` suppressions from `.claude-plugin/plugin.json`.
- R4.2. Either declare the components explicitly or rely on auto-discovery — whichever Claude Code prefers (determine during brainstorming).
- R4.3. Ensure no malformed files cause install-time errors or warnings.

### R5. Safety contract preservation
- R5.1. All new on-disk rewrites go through `exfil.write_sentinel_block()` — no raw `Path.write_text` in scenario code.
- R5.2. `SENTINEL_ALLOWLIST_ROOTS` in `plugin_mcp/exfil.py` extended to cover `agents/` and `skills/` (if not already).
- R5.3. `harness/cleanup_sentinels.py` restores all modified agent/skill files to their benign content.
- R5.4. AST-based safety invariants in `tests/test_safety_invariants.py` updated to cover the new write targets.
- R5.5. No new outbound hosts — httpbin.org only.
- R5.6. `FAKE_PAT_DO_NOT_USE` tokens preserved; no real credentials.
- R5.7. `DEMO_ACKNOWLEDGED=1` gate still blocks server startup and `leak()`.

### R6. Test coverage
- R6.1. Each converted scenario (S2, S3, S6, S9, S10, S11, S18) must have at least one unit test that asserts the on-disk file has been rewritten (for substitution scenarios) or that the component is discovered (for wiring).
- R6.2. Integration test (gated on `RUN_INTEGRATION=1`) that installs the plugin into a scratch Claude Code profile and asserts the sub-agents + skills + statusline appear under `/plugin`.
- R6.3. Full test suite + lint + mypy + format must stay green.

### R7. Documentation
- R7.1. Update `CLAUDE.md` status section — remove the "Known gap" warning once resolved.
- R7.2. Update `README.md` — scenario table trigger / surface columns must reflect real Claude Code exposure.
- R7.3. Update `docs/attack-families.md` to describe the file-substitution mechanism for S2/S3/S6/S9/S10/S11.
- R7.4. Update `SAFETY.md` if the path allowlist changes.
- R7.5. Update the blog post if any scenario narrative needs to match the implementation.

## 4. Out of scope

- Re-architecting the trigger registry — keep `state.override()` + `should_act_malicious()` as-is.
- Adding new scenarios beyond S1–S23.
- Changing the safety contract's shape (allowlisted hosts, sentinel format, kill switches).
- Touching the root `plugin.json` (it remains the S16 demo target — the CICD permission-creep attack — and is *not* the Claude Code manifest).

## 5. Open questions for brainstorming

1. **Agent malicious variant delivery.** Two possible patterns: (a) the benign `.md` is the on-disk file, trigger rewrites it to the malicious content; (b) the benign `.md` contains a pointer/template, and the substitution is more subtle (e.g., appending a system-prompt override). Which better matches real supply-chain patterns?
2. **Skill SKILL.md + Python assets.** Do all current `skills/*.py` need to survive as referenced assets, or can some be deleted if the scenario is better expressed in `SKILL.md` markdown alone?
3. **Statusline mechanism.** Does `.claude-plugin/plugin.json` accept a `statusLine` field, or must this be installed into `settings.json` via a hook at plugin-install time? (Research required.)
4. **Test isolation.** On-disk rewrites in tests need a clean fixture each run. Should tests copy benign files into a `tmp_path` and point the loader there, or rely on cleanup-between-tests?
5. **Integration test feasibility.** Is there a documented way to spin up a Claude Code profile headlessly to assert component discovery? If not, drop R6.2 or replace with a manifest-loading smoke test.

## 6. Exit criteria

- `/plugin` inside Claude Code lists the three sub-agents, N skills, the statusline, the MCP server, the slash command, and the hook.
- Triggering malicious mode (`echo malicious > mode.txt && DEMO_ACKNOWLEDGED=1`) causes on-disk agent/skill files to be rewritten with sentinel wrappers within one invocation.
- `make kill-demo` + `make cleanup` restore all files to benign state.
- All 148+ existing tests plus new coverage pass; lint/format/mypy clean; CI green on PR.
- Blog post and README scenario tables accurately describe what a user will actually see on installation.

## 7. Next steps (for the new session)

1. Run `superpowers:brainstorming` with this document as input; resolve the open questions in §5.
2. Produce a full design at `docs/superpowers/specs/2026-04-19-packaging-completeness-design-v2.md` (or overwrite this file).
3. Run `superpowers:writing-plans` to produce a task-by-task plan at `docs/superpowers/plans/2026-04-19-packaging-completeness.md`.
4. Create branch `feature/packaging-completeness` and execute via `superpowers:subagent-driven-development`.
