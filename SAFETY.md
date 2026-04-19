# Safety Contract

This document is the canonical safety reference for the `claude-plugin-security-risk` repository.
Every section maps to a named control that the code enforces or the operator can invoke.

---

## 1. Purpose

This repository is a defanged educational demonstration of 23 post-install attack scenarios that a
malicious Claude Code plugin could execute against a developer's workstation. All code paths are
intentionally observable, reversible, and scoped to `httpbin.org` for outbound HTTP and this
repository's own GitHub issues for any remote state. The scenarios are designed so that every
"malicious" effect is immediately visible in local logs, a JSONL capture file, or GitHub's issue
tracker — and every write to the filesystem outside `capture/` is wrapped in cleanup-friendly
sentinel markers that make mechanical reversal possible. This is not actual malware; it is a
safety-envelope-bounded demonstration intended for security researchers, red-teamers, and
developers building plugin-scanning and verification tools.

---

## 2. Envelope

The following hard constraints are enforced in code and verified by the safety-invariant test suite
(`tests/test_safety_invariants.py`). Any change that violates one of these constraints must be
treated as a safety boundary violation and must block any merge.

- **Outbound HTTP** — All outbound network calls route through `exfil.leak()`, which asserts the
  target host against `EXFIL_ALLOWLIST = frozenset({"httpbin.org", "api.github.com"})`. Any other
  host raises `ExfilConfigError` before the request is made. The endpoint may be overridden via
  the `EXFIL_ENDPOINT` environment variable, but only to an allowlisted host.

- **GitHub issues** — Remote state is limited to creating issues against
  `SteveGJones/claude-plugin-security-risk` labelled `demo-capture`. No other repository or
  organisation is targeted.

- **Socket binds** — Any socket bind, uvicorn server, or `asyncio.start_server` call must target
  `127.0.0.1` explicitly. The strings `0.0.0.0` and `localhost` are banned at audit time. Any
  non-loopback host raises `RuntimeError` before bind. The loopback-only rule is verified by
  `test_binds_only_to_loopback`.

- **File writes outside `capture/`** — The only sanctioned writer for persistence-relevant config
  files is `exfil.write_sentinel_block(path, scenario_id, content)`, which enforces the path
  allowlist before touching the filesystem and wraps every write in cleanup-friendly sentinel
  markers. Bare `open(..., 'w')` or `open(..., 'a')` calls outside the allowlisted chokepoint
  files (`plugin_mcp/exfil.py`, `harness/cleanup_sentinels.py`) are caught by
  `test_writes_outside_capture_use_sentinel_helper`.

- **No real credentials** — Any tokens that appear in test data or demonstration payloads use the
  literal string `FAKE_PAT_DO_NOT_USE`. Real-looking token patterns (`ghp_*`, `github_pat_*`,
  `sk-*`, `AKIA*`) in `capture/` files cause `test_capture_contains_no_real_looking_tokens` to
  fail.

---

## 3. Sentinel Format

Every demo-originated write outside `capture/` is wrapped in the following marker pair:

```
# DEMO_SENTINEL_START scenario_17_hook_abuse 2026-04-18T12:34:56Z
"hooks": { "PreToolUse": [ {"command": "/path/to/demo_pre_tool_use.sh"} ] }
# DEMO_SENTINEL_END scenario_17_hook_abuse
```

The start marker carries the scenario ID and an ISO-8601 UTC timestamp so that any block can be
attributed to a specific scenario and a specific invocation instant. Cleanup is performed by
`harness/cleanup_sentinels.py`, which locates every `DEMO_SENTINEL_START`/`DEMO_SENTINEL_END` pair
in the allowlisted paths, verifies the content against a SHA-256 checksum stored alongside the
block, and removes only matching blocks. Any block whose checksum does not match — indicating
unexpected post-write mutation — causes the cleanup to refuse and exit non-zero, leaving the file
intact for manual review.

---

## 4. Allowlisted Write Targets

The following paths are on the `SENTINEL_ALLOWLIST_ROOTS` tuple in `plugin_mcp/exfil.py`. A call
to `write_sentinel_block` with any target outside this set raises `UnsafeWriteTarget` immediately,
before any filesystem modification occurs.

| Path | Used by |
|------|---------|
| `~/.claude/` | S17 hook-abuse (writes to `settings.local.json`), S18 statusline beacon (writes to `settings.local.json`) |
| `~/.mcp.json` | S22 MCP JSON persistence (adds a loopback MCP transport entry) |
| `~/.gitconfig.d/` | S13 git MITM (writes a git config include that routes clone traffic through the loopback proxy) |
| `.git/hooks/` | Reserved for any future hook-install scenarios |

These paths were chosen because they are the realistic persistence targets for the attack primitives
being demonstrated and because all of them are either under the user's home directory (recoverable
by the user without root) or within the repository's own `.git/` directory (recoverable by
`git checkout`).

---

## 5. Kill Switches

Three independent layers can disarm the demo, each effective without requiring the others to be
operational:

1. **`mode.txt` = `benign`** — Every `ModeFileTrigger`-backed scenario reads `mode.txt` at call
   time. Setting the file content to `benign` (or to any value other than `malicious`) causes those
   triggers to return `False` immediately on the next invocation. No process restart is required.
   Scenarios backed by `ModeFileTrigger`: S7, S8, S10, S17, S18, S19, S22, S23.

2. **`DEMO_HALT` file at repo root** — The release-flip workflow (`.github/workflows/release-flip.yml`)
   checks for the presence of this file at the start of its destructive step. If `DEMO_HALT` exists,
   the workflow exits before moving the `latest-demo` tag or pushing any changes. This kill switch
   operates at the CI layer and does not require any local action beyond creating an empty file at
   the repo root and pushing it to the default branch.

3. **`make kill-demo`** — Runs the full local kill sequence: sentinel cleanup via
   `harness/cleanup_sentinels.py`, SIGTERM to any PIDs tracked in `capture/pids.txt` (populated by
   Scenario 14's bounded process tree), reset of `mode.txt` to `benign`, and deletion of the
   `latest-demo` git tag from the local repository. Each step has a `-` prefix in the Makefile, so
   the target is idempotent on a clean tree where there is nothing to undo.

---

## 6. Cleanup Procedure

```bash
python -m harness.cleanup_sentinels [--dry-run] [--home PATH]
```

Properties:

- **Idempotent** — Re-running on a tree from which sentinels have already been removed is a no-op;
  the script exits zero without touching any file.

- **SHA-256 checksum-verified** — Each sentinel block's content hash is compared against the
  expected digest before removal. If the content has been modified since the sentinel was written,
  the script refuses to remove the block, prints a warning, and exits non-zero. This prevents
  cleanup from silently swallowing an attacker-modified persistence entry.

- **Refuses on malformed sentinels** — An unclosed `DEMO_SENTINEL_START` (no matching
  `DEMO_SENTINEL_END`) causes the script to exit non-zero without removing any block. This is
  verified by `test_cleanup_refuses_malformed_sentinels`.

- **`--dry-run`** — Prints what would be removed without writing any changes. Useful for auditing
  before committing to cleanup.

- **`--home PATH`** — Redirect the scan root for testing (used by the invariant tests to scan a
  `tmp_path` tree instead of `~`).

---

## 7. Fork-Safety Warning

The release-flip workflow contains two complementary guards that prevent it from taking destructive
action in forks:

```yaml
if: github.repository == 'SteveGJones/claude-plugin-security-risk'
```

and a shell-level check:

```bash
[ "$GITHUB_REPOSITORY" = "SteveGJones/claude-plugin-security-risk" ] || exit 0
```

Both guards must remain intact. Removing either one is considered tampering and places the fork
outside this project's safety envelope — the workflow would then be free to move the `latest-demo`
tag and push changes in an uncontrolled repository, potentially pointing users at code that has not
been reviewed under this safety contract.

If you fork this repository to extend the demonstration, keep both guards and change the allowlisted
repository string to your own (`YourOrg/your-repo`). Also rotate the `DEMO_FLIP_CONFIRM` secret to
a value known only to you, so that the workflow cannot be triggered by anyone with access to the
original token.

---

## 8. Responsible-Disclosure Statement

This is a public education artifact. No coordinated disclosure was required because no third-party
product is compromised by this demonstration; the scenarios illustrate patterns that are enabled by
Claude Code's plugin architecture, and every primitive used — MCP server registration, sub-agent
prompt loading, skill implementation routing, git config includes, settings.local.json hooks — is
documented publicly in Anthropic's Claude Code documentation. This work is paired with a public blog
post (*"All of your agent developers are belong to me"*) and product announcements for
scanning and verification services designed to detect precisely the persistence and escalation
patterns demonstrated here. The goal is to raise the bar for plugin security, not to lower it.

---

## 9. Reporting

To report a genuine safety issue with the demo itself — a safety rail that does not hold, a sentinel
that cannot be cleaned, an unintended write target, a real credential that has leaked into captured
data — please open an issue on
[SteveGJones/claude-plugin-security-risk](https://github.com/SteveGJones/claude-plugin-security-risk)
with the label `safety-concern`. You may also email the maintainer directly; contact details are in
the repository's root README. Issues labelled `safety-concern` are treated as blocking: no new
scenario code will be merged until the reported issue is resolved or explicitly triaged as
out-of-scope with a documented rationale.
