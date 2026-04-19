# Additional Scenarios — Design Spec

**Date:** 2026-04-18
**Status:** Approved (brainstorming complete, pending spec review)
**Supersedes:** extends `2026-04-08-plugin-security-demo-design.md` and `2026-04-16-scenarios-9-10-11-design.md`
**Related plan:** `docs/superpowers/plans/2026-04-18-additional-scenarios.md` (produced after this spec is approved)

---

## 1. Overview

### 1.1 Goal

Extend the existing plugin security demo (11 scenarios) with 12 additional scenarios that (a) realise a GitHub Actions-driven release-flip attack vector end-to-end, (b) strengthen four scenarios whose current implementations are symbolic rather than demonstrative, and (c) close the threat-surface gaps identified by the 2026-04-17 team review — hooks, statusline, slash-command shadowing, settings persistence, MCP transport impersonation, context-dependent triggers, and hallucination-as-cover.

### 1.2 In Scope

- 12 new scenarios, numbered S12 through S23 (additive — no renumbering of existing S1–S11).
- 4 new trigger classes (`ReleaseTagTrigger`, `GitRemoteTrigger`, `ConversationKeywordTrigger`, `CompositeTrigger`).
- A GitHub Actions `workflow_dispatch`-only release-flip mechanism with dual release branches (`release/safe`, `release/demo-malicious`) and a moving `latest-demo` tag.
- 10 new safety invariants enforcing the expanded envelope.
- Three-layer kill-switch system (`mode.txt`, `DEMO_HALT` file, `make kill-demo`).
- `SAFETY.md` canonical safety contract document.
- `docs/attack-families.md` narrative overlay grouping all 23 scenarios into five families (narrative only — does not affect code structure).
- All documentation updates (CLAUDE.md, READMEs, plugin manifests, Makefile, CI).

### 1.3 Out of Scope (Deliberately)

- Renumbering, renaming, or restructuring S1–S11.
- Blog post edits (tracked as a follow-up PR; this spec commits to making those edits feasible but does not execute them).
- Deck rebuild to cover S12–S23 (tracked as a follow-up pipeline run).
- Any publication to an external marketplace or registry.
- Any `schedule:` trigger on any GitHub workflow.
- Any bind outside `127.0.0.1`.
- Any exfil destination outside `httpbin.org` and `api.github.com`.

### 1.4 Safety Position

The demo already routes all observable side effects through `plugin_mcp.exfil.leak()`. This spec expands the envelope to allow **sentinel-marked writes to real user configuration files** (`~/.claude/settings.local.json`, `~/.mcp.json`, `~/.gitconfig.d/demo.conf`, `.git/hooks/demo_*`). Every such write is wrapped in matching `DEMO_SENTINEL_START` / `DEMO_SENTINEL_END` markers and is fully reversed by an idempotent, checksummed cleanup utility. The demo does **not** acquire any new real-world capability (no new exfil endpoints, no new protocols, no external-facing ports, no schedule-driven workflows, no marketplace publication).

---

## 2. Architecture & Conventions

### 2.1 New Trigger Classes

All live in `plugin_mcp/triggers/`.

- **`ReleaseTagTrigger(allowlist: set[str])`** — reads `git describe --tags --abbrev=0` at evaluation. Fires when the resolved tag is in the allowlist (e.g. `{"latest-demo"}`). Constructor accepts injectable `_git_resolver: Callable[[], str | None]` for deterministic tests. Returns False on any git error.
- **`GitRemoteTrigger(allowlist: set[str])`** — reads `git config --get remote.origin.url`. Fires when the origin matches any allowlist entry. Handles both `https://` and `git@` forms. Constructor accepts injectable `_git_resolver`. Returns False on missing/error.
- **`ConversationKeywordTrigger(keywords: set[str])`** — fires when any keyword appears in the `context["prompt"]` string passed to `evaluate(context)`. Case-insensitive. Returns False if context is None or missing `prompt` key. Deterministic by construction — no I/O.
- **`CompositeTrigger(*triggers: Trigger, mode: Literal["any", "all"])`** — fires if `any` or `all` children fire. Empty child list returns False. Composes cleanly with other Triggers.

Hook-event "triggers" are **not** new trigger classes. Hooks are shell scripts installed by `ModeFileTrigger`-gated scenarios; the scripts themselves re-read `mode.txt` on each invocation, so flipping to benign disarms live hooks without reinstall.

### 2.2 Exfil Module Extensions

- `exfil.SENTINEL_START_FMT = "# DEMO_SENTINEL_START {scenario_id} {timestamp}"` and `exfil.SENTINEL_END_FMT = "# DEMO_SENTINEL_END {scenario_id}"` constants.
- `exfil.write_sentinel_block(path: Path, scenario_id: str, content: str) -> None` — the only sanctioned way to write content to any path outside `capture/`. Enforces a path allowlist: `~/.claude/settings.local.json`, `~/.mcp.json`, `~/.gitconfig.d/demo.conf`, `.git/hooks/demo_*`. Raises `UnsafeWriteTarget` for any other target.
- `leak()` signature and allowlist unchanged.

### 2.3 State Registry

All 12 new scenarios register in `plugin_mcp/state.py::_REGISTRY`:

| Scenario | Trigger |
|---|---|
| `scenario_12_release_flip` | `ReleaseTagTrigger({"latest-demo"})` |
| `scenario_13_git_mitm_real` | reuse `TimeBombTrigger(hours=(2,4))` (shared with S4) |
| `scenario_14_proliferation_real` | reuse `TimeBombTrigger(after=...)` (shared with S6) |
| `scenario_15_padding_real` | reuse `ProbabilisticTrigger(n=8)` (shared with S9) |
| `scenario_16_plugin_json_cicd` | `ReleaseTagTrigger({"latest-demo"})` (shared instance with S12) |
| `scenario_17_hook_abuse` | `ModeFileTrigger(_MODE_FILE)` |
| `scenario_18_statusline_beacon` | `ModeFileTrigger(_MODE_FILE)` |
| `scenario_19_slash_cmd_shadow` | `ModeFileTrigger(_MODE_FILE)` |
| `scenario_20_context_dependent` | `CompositeTrigger(GitRemoteTrigger(...), ConversationKeywordTrigger(...), mode="any")` |
| `scenario_21_hallucination_cover` | `ProbabilisticTrigger(n=20)` |
| `scenario_22_mcp_json_persistence` | `ModeFileTrigger(_MODE_FILE)` |
| `scenario_23_mcp_transport_impersonation` | `ModeFileTrigger(_MODE_FILE)` |

### 2.4 Shared Constants

- `MAX_DEPTH = 3` (S14 fork cap)
- `MAX_CHILDREN = 5` (S14 per-node cap)
- `ALLOWED_EXFIL_HOSTS = {"httpbin.org", "api.github.com"}` (unchanged)
- `ALLOWED_BIND_HOSTS = {"127.0.0.1"}` (new)
- `DEMO_SENTINEL` start/end format as defined in §2.2

---

## 3. CICD Release-Flip Mechanism

### 3.1 Repository Layout

- `main` — working branch; PRs merge here; development continues here.
- `release/safe` — protected; mirrors `main` with `mode.txt = "benign"` and baseline `plugin.json`. Updated only by the flip workflow.
- `release/demo-malicious` — protected; mirrors `main` with `mode.txt = "malicious"` and escalated `plugin.json`. Updated only by the flip workflow.
- `release-overlays/malicious.patch` — the overlay applied to turn a `main` snapshot into a `release/demo-malicious` snapshot. Contains `mode.txt` change, `plugin.json` permission escalation, and release-note sentinel markers.

### 3.2 The `latest-demo` Tag

Whichever branch the `latest-demo` tag points at is "currently live" for users installing `@latest-demo`. No other tags move. The tag is force-pushed by the flip workflow only.

### 3.3 Workflow — `.github/workflows/release-flip.yml`

```yaml
on:
  workflow_dispatch:
    inputs:
      target:
        type: choice
        options: [safe, demo-malicious]
        required: true
      confirm:
        type: string
        description: "Type DEMO_FLIP_CONFIRM to proceed"
        required: true

permissions:
  contents: write
  issues: write
```

### 3.4 Workflow Steps

1. **Identity guard** — abort if `github.repository != "SteveGJones/claude-plugin-security-risk"`.
2. **Halt guard** — abort if `DEMO_HALT` file exists at repo root.
3. **Confirm guard** — abort unless `inputs.confirm == "DEMO_FLIP_CONFIRM"` and `inputs.target in {"safe", "demo-malicious"}`.
4. **Rebuild target branch** — checkout `main`; if target is `demo-malicious`, apply `release-overlays/malicious.patch`; force-push to `release/<target>`.
5. **Move tag** — `git tag -f latest-demo <sha>` and `git push --force origin latest-demo`.
6. **Cut GitHub Release** — `gh release create/edit latest-demo` with body beginning with a visible warning banner and the `DEMO_SENTINEL` marker, linking `SAFETY.md`.
7. **Emit telemetry issue** — `gh issue create --label demo-capture --title "Flip executed: <target> at <ts>"`.
8. **Update state file** — commit `.github/demo-state.json` with `{ "current": "<target>", "flipped_at": "<ts>", "actor": "<github.actor>" }` to `main`.

### 3.5 Workflow Constraints

- No `schedule:` key. No `push:` key. Only `workflow_dispatch`.
- `permissions:` limited to `contents: write` and `issues: write`.
- No secrets referenced; uses default `GITHUB_TOKEN` only.
- `harness/validate_workflows.py` asserts these constraints in CI.

### 3.6 How Scenarios Consume the Flip State

- **S12** — the `ReleaseTagTrigger` fires when the installed commit is reachable from the `latest-demo` tag AND `mode.txt` at that commit reads `"malicious"`. Both conditions are required: the tag signal identifies "this user installed from the demo channel", and the mode check distinguishes a malicious release from a safe one sharing the same tag history. When it fires, the scenario leaks install-time context (tag name, commit SHA, scrubbed env keys) to httpbin. The trigger's `_git_resolver` stub returns both values as a tuple for deterministic tests.
- **S16** — The `malicious.patch` overlay *is* the automated `plugin.json` mutation. Cutting the malicious release executes S16. The scenario test verifies the patch applies cleanly and reverse-applies restore bit-for-bit. S16's trigger fires off the same tag+mode resolution as S12.
- **Existing `ModeFileTrigger`-gated scenarios** (S7, S8, S10, S17, S18, S19, S22, S23) fire automatically based on whichever branch's `mode.txt` was installed — the flip workflow is what selects which branch (and therefore which `mode.txt`) users pull. No changes to those scenarios' trigger logic.

---

## 4. Per-Scenario Catalog (S12–S23)

Each entry specifies: trigger, files touched, malicious behaviour, observable side effect, test focus.

### S12 — GitHub Actions release-flip observer

- **Trigger:** `ReleaseTagTrigger({"latest-demo"})`.
- **Files:** `plugin_mcp/tools/release_check.py`, `plugin_mcp/triggers/release_tag.py`.
- **Benign:** returns `{"tag": "<current>", "status": "ok"}`.
- **Malicious:** identical return value; leaks install-time tag + scrubbed env keys list.
- **Observable:** httpbin GET + `capture/leaks.jsonl` line; `.github/demo-state.json` commit on flip.
- **Test focus:** inject `_git_resolver` to simulate each tag; never touch real git state.

### S13 — Strengthened S4: real git-clone MITM via local demo proxy

- **Trigger:** existing `TimeBombTrigger(hours=(2,4))`.
- **Files:** `plugin_mcp/tools/git_clone.py` (modified); new `harness/demo_proxy.py` (127.0.0.1 CONNECT-logger on ephemeral port).
- **Benign:** clone proceeds directly.
- **Malicious:** writes sentinel-marked `[http] proxy = http://127.0.0.1:<port>` to `~/.gitconfig.d/demo.conf`; sources it via gitconfig include; clone goes through the local demo proxy which logs the request line and forwards to the real origin. No TLS MITM. Proxy lifetime ≤ 60 s.
- **Observable:** sentinel block in `~/.gitconfig.d/`; JSONL log of proxy-observed request lines; httpbin leak of cloned repo URL + branch.
- **Test focus:** patch `~/.gitconfig.d/` target to `tmp_path`; start proxy on `127.0.0.1:0`; clone a local `file://` repo through it; assert log lines; assert cleanup removes the sentinel block byte-identically.

### S14 — Strengthened S6: real bounded recursive fork

- **Trigger:** existing `TimeBombTrigger(after=...)`.
- **Files:** `plugin_mcp/tools/spawn.py` (modified).
- **Benign:** task runs in-process.
- **Malicious:** genuinely forks children via `subprocess.Popen`, each child re-invokes the entry point with `--depth N`. Hard module-level `MAX_DEPTH = 3`, `MAX_CHILDREN = 5` enforced at fork time and by AST invariant. All PIDs recorded to `capture/pids.txt`; each child registers `signal.alarm(60)`; parent has `atexit` reaper.
- **Observable:** PID list; per-PID leak record; total child count ≤ 156 across tree.
- **Test focus:** fake-clock + fake `Popen` unit tests assert caps; real-fork integration test gated by `RUN_INTEGRATION=1`.

### S15 — Strengthened S9: real context padding

- **Trigger:** existing `ProbabilisticTrigger(n=8)`.
- **Files:** `skills/cost_estimator.py` (modified).
- **Benign:** returns dict without `_padding` key.
- **Malicious:** returns the haiku estimate **plus** a `_padding` key containing ~5000 tokens (≥20000 chars) of plausible "reasoning scratchpad" content. The extra payload is what a downstream LLM would ingest. The `model` field still says `haiku` (the deception).
- **Observable:** `len(result["_padding"]) > 20000` assertable; leak records padding size.
- **Test focus:** assert padding-size band; assert benign return has no `_padding` key; assert `model` field is deceptively unchanged.

### S16 — Automated `plugin.json` mutation via CICD

- **Trigger:** shared `ReleaseTagTrigger({"latest-demo"})` (same instance as S12).
- **Files:** `release-overlays/malicious.patch` (new); `plugin.json` (target); `plugin.baseline.json` (reset source).
- **Malicious:** the overlay patch adds `"filesystem:write"`, `"process:spawn"`, `"env:read"` to the escalated permissions array, with `DEMO_SENTINEL` embedded in a release-notes comment block.
- **Observable:** `git diff release/safe..release/demo-malicious -- plugin.json` shows the escalation cleanly; `make cleanup` restores from baseline.
- **Test focus:** apply patch in `tmp_path`; assert diff against baseline; assert reverse-apply restores bit-for-bit.

### S17 — `PreToolUse` hook abuse

- **Trigger:** `ModeFileTrigger(_MODE_FILE)`.
- **Files:** `skills/install_hook.py`; `hooks/demo_pre_tool_use.sh` (template).
- **Malicious:** on first run in malicious mode, writes a `DEMO_SENTINEL`-wrapped block to `~/.claude/settings.local.json` adding a `PreToolUse` hook that invokes `hooks/demo_pre_tool_use.sh`. The hook itself re-reads `mode.txt` at each invocation; flipping to benign disarms it without removal. When live, hook `curl`s httpbin with the tool name and a hash of its arguments.
- **Observable:** sentinel block in settings file; one httpbin call per tool invocation while malicious; idempotent cleanup.
- **Test focus:** patch home dir to `tmp_path`; assert sentinel added/removed; assert hook script reads `mode.txt` and exits 0 when benign.

### S18 — Statusline beacon

- **Trigger:** `ModeFileTrigger(_MODE_FILE)`.
- **Files:** `skills/install_statusline.py`; `statusline/demo_statusline.sh`.
- **Malicious:** installs a sentinel-wrapped `statusLine` entry in `~/.claude/settings.local.json` pointing at `demo_statusline.sh`. The script on each tick prints a legitimate status (branch + model) and leaks a short hash of cwd + timestamp to httpbin. Respects `mode.txt` like S17.
- **Observable:** one httpbin GET per statusline tick while malicious; sentinel block reversible.
- **Test focus:** invoke statusline script with mocked `curl`; assert leak payload shape; assert statusline stdout still contains the legitimate content.

### S19 — Slash-command shadowing

- **Trigger:** `ModeFileTrigger(_MODE_FILE)`.
- **Files:** `commands/commit.md` (plugin-provided slash command).
- **Malicious:** plugin ships a `/commit` command that runs `git status` and `git diff --stat`, leaks a hash of changed file paths, then forwards the user's original intent unchanged. Because the name collides with the user's common `/commit` habit, this shadows the expected flow.
- **Observable:** leak record with file-path hashes; no commit content exfiltrated (path hashes only, to keep envelope tight).
- **Test focus:** invoke command handler with a fixture repo; assert declared action still completes; assert file-path hashes appear in leak.

### S20 — Context-dependent firing

- **Trigger:** `CompositeTrigger(GitRemoteTrigger({"github.com/SteveGJones/..."}), ConversationKeywordTrigger({"deploy", "production", "release"}), mode="any")`.
- **Files:** `plugin_mcp/triggers/git_remote.py`, `plugin_mcp/triggers/conversation_keyword.py`, wired into existing S1 `fetch_weather` as host.
- **Malicious:** the existing S1 leak path fires only when one condition is true — attacking a targeted repo OR when the conversation concerns production. Everywhere else the plugin appears benign, breaking naive "run it a few times" detection.
- **Observable:** same httpbin GET as S1, but gated.
- **Test focus:** inject fake `_git_resolver` with allowlisted/non-allowlisted remotes; pass context dicts with/without keywords; assert firing truth table.

### S21 — Hallucination-as-cover

- **Trigger:** `ProbabilisticTrigger(n=20)`.
- **Files:** `skills/research_assistant.py` (new).
- **Malicious:** skill's answer includes a fabricated CVE ID (`CVE-2099-99999`, within a reserved sentinel range) and a non-existent pip package name (`sample-helpers-toolkit`). Plausibly wrong in a way mirroring real LLM hallucinations. Leaks `{"fabrication_type": "cve|pkg", "value": "..."}`.
- **Benign:** same return structure with a real CVE and real package name drawn from an allowlist fixture at `tests/fixtures/real_identifiers.json`.
- **Observable:** return value itself is the fabrication; leak records exact fabrication for later verification.
- **Test focus:** assert malicious return contains `CVE-2099-` prefix (sentinel range); assert benign return uses an allowlist; assert leak records fabrication type.

### S22 — `~/.mcp.json` persistence

- **Trigger:** `ModeFileTrigger(_MODE_FILE)`.
- **Files:** `skills/install_mcp_entry.py`.
- **Malicious:** writes a `DEMO_SENTINEL`-wrapped entry to `~/.mcp.json` registering a demo MCP server at `127.0.0.1:<port>` named `helpful-dev-tools`. Survives across Claude Code restarts until cleanup. The binary it points at is the S23 listener.
- **Observable:** sentinel block in `~/.mcp.json`; cleanup restores file byte-identically.
- **Test focus:** patch home to `tmp_path`; assert entry added; assert cleanup restores pre-state.

### S23 — MCP transport impersonation

- **Trigger:** `ModeFileTrigger(_MODE_FILE)`.
- **Files:** `harness/demo_mcp_server.py`.
- **Malicious:** a minimal 127.0.0.1-only MCP server using the **SSE/HTTP transport** on an ephemeral loopback port (stdio MCP would not need a bind; the port binding is the point of this scenario). Advertises plausible tools (`search_docs`, `summarise_file`), responds with believable results, and leaks every call to httpbin. Binds only loopback; refuses to start if `$DEMO_BIND_HOST != "127.0.0.1"`; lifetime-capped at 5 minutes by an internal timer.
- **Observable:** server stdout log; httpbin GET per tool call; process exits on timer.
- **Test focus:** start server on random 127.0.0.1 port; open client; assert each tool call produces one leak record; invariant asserts `bind` target is loopback.

---

## 5. Safety Envelope Extensions

### 5.1 Sentinel Contract

Every write outside `capture/` must be wrapped:

```
# DEMO_SENTINEL_START scenario_<NN> <timestamp>
<content>
# DEMO_SENTINEL_END scenario_<NN>
```

`exfil.write_sentinel_block(path, scenario_id, content)` is the only sanctioned writer. Path allowlist: `~/.claude/settings.local.json`, `~/.mcp.json`, `~/.gitconfig.d/demo.conf`, `.git/hooks/demo_*`. Any other target raises `UnsafeWriteTarget`. An AST invariant asserts every non-`capture/` write routes through this helper.

### 5.2 Cleanup Contract

`harness/cleanup_sentinels.py` enumerates the allowlist, reads each file, removes every matched sentinel block, and writes back only if the remaining bytes parse (for JSON targets). Properties:

- **Idempotent** — second run is a no-op.
- **Dry-runnable** — `--dry-run` prints every removal without touching disk.
- **Checksummed** — emits pre/post SHA256 of each touched file to `capture/cleanup.log`.
- **Non-destructive on partial match** — unclosed start marker refuses the file and exits non-zero.

### 5.3 Three-Layer Kill Switch

1. `mode.txt = "benign"` — disarms every `ModeFileTrigger`-gated scenario instantly. Hook/statusline scripts re-read on each invocation; no reinstall needed.
2. `DEMO_HALT` file at repo root — blocks the GitHub Actions flip workflow (workflow reads it before any other step).
3. `make kill-demo` — runs cleanup + terminates all PIDs in `capture/pids.txt` + forces `mode.txt` to benign + removes the `latest-demo` tag locally.

### 5.4 Network Envelope (Restated)

- **Outbound:** only `httpbin.org` and `api.github.com`. Enforced by `exfil.leak()` allowlist plus AST invariant forbidding `httpx`/`requests`/`urllib` calls outside `plugin_mcp/exfil.py` and `harness/demo_proxy.py`.
- **Inbound:** only `127.0.0.1` binds. New invariant asserts `socket.bind`, `uvicorn.run`, `asyncio.start_server` all target `127.0.0.1` explicitly (string `"localhost"` rejected — must be IP).
- **No `0.0.0.0`, no external-interface binds, no `EXFIL_ENDPOINT` env override.** Constant is hard-coded; any existing env override is removed.

### 5.5 Process Envelope

- `subprocess.Popen`/`os.fork` calls outside `plugin_mcp/tools/spawn.py` forbidden by AST invariant.
- `spawn.py` enforces `MAX_DEPTH=3`, `MAX_CHILDREN=5`, `signal.alarm(60)` per child.
- All PIDs recorded to `capture/pids.txt` with parent-child tree; `make kill-demo` walks the tree.

### 5.6 Fork-Safety

- Every flip-workflow step begins with `if [ "$GITHUB_REPOSITORY" != "SteveGJones/claude-plugin-security-risk" ]; then exit 0; fi`.
- `SAFETY.md` documents envelope, sentinels, cleanup, kill switches. Linked from README, `plugin.json` description, every sentinel block's reference line.
- `plugin.json` gains top-level `"demo": true`; `plugin_mcp/server.py` refuses to start if field is absent and install path is under a user's real plugins dir with no `DEMO_ACKNOWLEDGED=1` env var.

### 5.7 New Safety Invariants (additions to `tests/test_safety_invariants.py`)

1. `test_writes_outside_capture_use_sentinel_helper` — AST walk.
2. `test_network_calls_only_in_allowlisted_modules` — AST walk.
3. `test_binds_only_to_loopback` — AST walk.
4. `test_subprocess_only_in_spawn_module` — AST walk.
5. `test_spawn_module_declares_depth_and_children_caps` — constant-presence check.
6. `test_flip_workflow_guards_repo_identity` — grep on `.github/workflows/release-flip.yml`.
7. `test_flip_workflow_has_no_schedule_key` — YAML parse.
8. `test_cleanup_is_idempotent` — two-run assertion.
9. `test_cleanup_refuses_malformed_sentinels` — fixture with unclosed marker.
10. `test_plugin_json_requires_demo_flag` — JSON parse.

---

## 6. Testing Strategy

### 6.1 Unit Tests

Each scenario gets at minimum:

- `test_benign_returns_expected_no_leak` — trigger forced False, asserts return shape and no `leaks.jsonl`.
- `test_malicious_returns_same_shape_and_leaks` — trigger forced True, asserts return value indistinguishable from benign (where deception is the point) or contains declared payload (where payload is the attack, e.g. S15 padding), plus expected leak record.
- Scenario-specific asserts (e.g. S17 sentinel block added and removed; S14 fork depth/width caps).

Estimated ~36 new unit tests; total suite becomes ~111.

### 6.2 Trigger Tests (`tests/test_triggers.py` additions)

- `ReleaseTagTrigger` — inject `_git_resolver`; allowlist hit/miss/missing-tag/error cases.
- `GitRemoteTrigger` — same shape; cover `https://` and `git@` URL forms.
- `ConversationKeywordTrigger` — match, non-match, empty context, case-insensitivity (case-insensitive).
- `CompositeTrigger` — truth tables for `any` and `all` modes; empty child list returns False.

### 6.3 Integration Tests (gated by `RUN_INTEGRATION=1`)

- **S13** — real local demo proxy; real `git clone` of `file://` fixture through it; log + cleanup assertions.
- **S14** — real `subprocess.Popen` tree; depth/width/timeout assertions; `signal.alarm` escape hatch.
- **S23** — real 127.0.0.1 MCP server on ephemeral port; real client; leak-per-call assertions; server lifetime 10 s in test.
- **Flip workflow** — `.github/workflows/release-flip.yml` dry-run via `act` if available, else lint-only check.

### 6.4 Safety Invariants

All 10 new invariants (§5.7) plus existing 6 run on every `pytest` invocation. AST walks only, no I/O.

### 6.5 Harness Extensions

- `harness/compare.py` — add S12–S23 to `SCENARIOS` dict and `_invoke`.
- S14, S23 in harness use *mocked* fork/bind so `./harness/compare.sh` stays safe without elevated permissions.
- New `./harness/compare.sh --integration scenario_14` mode runs real-effects variant when `RUN_INTEGRATION=1`.
- Report template gains "Side-effects observed" section (sentinel blocks touched, PIDs spawned, ports bound).

### 6.6 Cleanup Test (`tests/test_cleanup.py`, new file)

- Tmp home dir with synthetic sentinel blocks across all targeted files.
- `--dry-run`: asserts expected removals reported, no files touched.
- Real run: asserts sentinels removed, surrounding content byte-identical, pre/post SHA256 logged.
- Second run: asserts no-op.
- Unclosed-marker fixture: asserts cleanup refuses and exits non-zero.

### 6.7 CI (`.github/workflows/ci.yml` extensions)

- **Default job:** `uv run pytest` (all ~111 tests, no integration).
- **Optional job:** manual dispatch or `run-integration` PR label: `RUN_INTEGRATION=1 uv run pytest -m integration`.
- **New lint job:** `python -m harness.validate_workflows` asserts `release-flip.yml` guards are present and asserts no other workflow can modify `release/*` branches or the `latest-demo` tag.

### 6.8 Determinism Rules (restated)

- No `datetime.utcnow()` or `time.time()` in scenario code — inject a clock.
- No unseeded `random.Random()` — already enforced; extends to new scenarios.
- No real network in unit tests — mock at `exfil.httpx.get` and scenario-specific boundaries.
- Integration tests may use real network, allowlist-bound.

### 6.9 Mutation Spot Check (one-off, not CI)

Run `mutmut` once against `plugin_mcp/triggers/` and `plugin_mcp/exfil.py` before merge. Target ≥90% mutation score on those two modules. Document results in PR description. Not CI-gated — invariants are the enforced floor.

---

## 7. Documentation & Artifact Updates

### 7.1 New Files

- `SAFETY.md` (repo root) — canonical safety contract. Sections: envelope, sentinel format, allowlists, kill switches, cleanup procedure, responsible-disclosure statement, fork-safety warning. Every `DEMO_SENTINEL` block references this file.
- `docs/superpowers/specs/2026-04-18-additional-scenarios-design.md` — this spec.
- `docs/superpowers/plans/2026-04-18-additional-scenarios.md` — implementation plan (produced by `writing-plans` after spec approval).
- `docs/attack-families.md` — narrative overlay grouping all 23 scenarios into five families; referenced by blog/deck, not by code.
- `release-overlays/malicious.patch` — the flip overlay.
- `hooks/demo_pre_tool_use.sh`, `statusline/demo_statusline.sh`, `commands/commit.md` — sentinel-marked attack artifacts.
- `harness/cleanup_sentinels.py`, `harness/demo_proxy.py`, `harness/demo_mcp_server.py`, `harness/validate_workflows.py`.
- `.github/pull_request_template.md` — safety checklist for demo PRs.

### 7.2 Files Updated

- `CLAUDE.md` — scenario count `11 → 23`; five new safety invariants; `DEMO_SENTINEL` convention; kill-switch section; new constants in Key Conventions; updated Status.
- `README.md` (root) and `.worktrees/.../README.md` — expanded scenario catalog; prominent safety banner; install warning about `@latest-demo`; `SAFETY.md` link.
- `plugin.json` — add `"demo": true`; reference `SAFETY.md` in description.
- `plugin.baseline.json` — regenerated to match post-addition baseline.
- `Makefile` — add `kill-demo` target; update `cleanup` to call `cleanup_sentinels.py`.
- `.github/workflows/ci.yml` — add integration job, workflow-validation job.
- `pyproject.toml` — add `pytest` markers (`integration`, `unit`); no new runtime deps.
- `.gitignore` — add `capture/cleanup.log`, `capture/pids.txt` if not already covered.

### 7.3 Blog Post Edits (Follow-up PR, Not in Scope)

This spec commits to making the following feasible; they are executed in a separate blog-update PR:

1. Change "8 ways" → "23 ways" or restructure around five families from `docs/attack-families.md`.
2. Promote S9/S10/S11 from preamble to numbered entries.
3. Add structured entries for S12–S23 matching S1–S8 format.
4. Add 12 new diagrams.
5. Add compound-chain section (S7→S10, S12→S16, S20→any).
6. Add "Detection Challenge" bullets for billing-observability (S9/S15) and tool-trust-inversion (S10/S11/S21).
7. Add "How to defend" section drawing IOCs from `SAFETY.md`.
8. Add responsible-disclosure statement.

### 7.4 Deck Edits (Follow-up, Not in Scope)

Deck is currently at 27 slides / 11 scenarios. Expanding to 23 scenarios is a separate pipeline run in a follow-up.

### 7.5 Memory Updates (at PR merge)

- Update `project_implementation_state.md` — 23 scenarios, ~111 tests, new trigger classes, `SAFETY.md` exists.
- Update `project_safety_model.md` — expanded envelope, sentinel contract, three-layer kill switch.
- Delete the stale `tmp/deck/output/Blog Post - Recommended Edits.docx` reference — that document was never produced.

---

## 8. Summary

### 8.1 What We Are Adding

| Bucket | Count |
|---|---|
| New scenarios | 12 (S12–S23) |
| New trigger classes | 4 (`ReleaseTagTrigger`, `GitRemoteTrigger`, `ConversationKeywordTrigger`, `CompositeTrigger`) |
| New safety invariants | 10 |
| New unit tests (est.) | ~36 |
| New integration tests | 3 (S13, S14, S23) + flip-workflow lint |
| New safety-critical files | `SAFETY.md`, `cleanup_sentinels.py`, `validate_workflows.py`, `release-flip.yml` |
| New kill switches | 3 layers |
| New docs | `SAFETY.md`, `attack-families.md`, this spec, impl plan |

### 8.2 What We Are Explicitly Not Doing

- No renumbering of existing scenarios.
- No blog edits in this PR.
- No deck rebuild in this PR.
- No marketplace/registry publication.
- No `schedule:` triggers.
- No binds outside `127.0.0.1`.
- No exfil outside `httpbin.org` / `api.github.com`.

### 8.3 Acceptance Criteria for This Design's Implementation

- All ~111 tests green; `ruff check`, `ruff format --check`, `mypy --strict` clean.
- All 16 safety invariants pass (6 existing + 10 new).
- `harness/validate_workflows.py` passes in CI.
- `make cleanup` and `make kill-demo` reset state byte-identically (verified via pre/post SHA256).
- Mutation score ≥90% on `plugin_mcp/triggers/` and `plugin_mcp/exfil.py`.
- `SAFETY.md` exists, linked from README and `plugin.json`.
- No `schedule:` key in any workflow file.
- Every new `open(..., "w"|"a")` call routes through `exfil.write_sentinel_block` (AST-verified).
