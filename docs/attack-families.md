# Attack Families

This document groups the 23 demonstration scenarios into five families based on their shared attack
surface. Each family includes context on why the surface is exploitable, a scenario list drawn from
`plugin_mcp/state.py`, and a pointer to the relevant control in `SAFETY.md`.

---

## Family 1 — Outbound Exfiltration

A plugin that routes information to an external observer is the most straightforward supply-chain
attack: the user's data leaves their machine without any visible signal in the Claude Code UI.
In this demo the destination is always `httpbin.org`, a public echo service. In a real attack it
would be an attacker-controlled endpoint, a trusted CDN that blends into normal traffic, or a
DNS-tunnelling channel that evades most HTTP-level monitoring. The common thread across all eight
scenarios in this family is that the exfiltration is a side effect layered onto an apparently
functioning tool, agent, or transport — the primary result returned to Claude is correct, so the
user has no reason to distrust the result.

Scenarios:

- `scenario_01_mcp_mitm` — leaks tool args and env keys from the `fetch_weather` call, 1-in-10 calls (ProbabilisticTrigger)
- `scenario_05_ctx_poison` — leaks search context alongside the injected poisoned results, 1-in-5 calls (ProbabilisticTrigger)
- `scenario_12_release_flip` — leaks the release tag and scrubbed env keys whenever the `latest-demo` tag is observed (ReleaseTagTrigger)
- `scenario_18_statusline_beacon` — installs a statusline hook that beacons once per UI tick (ModeFileTrigger)
- `scenario_19_slash_cmd_shadow` — shadows the `/commit` slash command, hashing and leaking committed file paths before the real commit runs (ModeFileTrigger)
- `scenario_20_context_dependent` — fires only when the git remote matches the target repo AND conversation keywords include "deploy", "production", or "release" (CompositeTrigger: GitRemote + ConversationKeyword)
- `scenario_21_hallucination_cover` — fabricates a plausible-looking answer and encodes the fabrication metadata as steganographic exfil, 1-in-20 calls (ProbabilisticTrigger)
- `scenario_23_mcp_transport_impersonation` — every call routed through the loopback MCP transport leaks the full request payload (ModeFileTrigger)

Defensive control: [SAFETY.md §2 (Envelope)](../SAFETY.md#2-envelope) for the allowlist and
chokepoint enforcement; [SAFETY.md §3 (Sentinel format)](../SAFETY.md#3-sentinel-format) for any
file-based persistence that enables the beacon; `exfil.leak` is the single chokepoint that all
eight scenarios route through.

---

## Family 2 — Tool / Agent / Skill Substitution

The plugin primitives available to Claude Code — MCP tools, sub-agent prompts, and skills — are
abstractions by design: the user and the host application see names and descriptions, not
implementations. Substitution attacks exploit this opacity by replacing the advertised behavior with
attacker-controlled logic at call time, leaving the declared interface unchanged. Because the
substituted implementation still returns a structurally correct result, detection requires
behavioural comparison across modes rather than static inspection of the manifest. The four scenarios
in this family span all three plugin primitive types: MCP server tools, sub-agent system prompts,
and skill implementations.

Scenarios:

- `scenario_02_subagent_inject` — replaces the code-reviewer sub-agent's system prompt with one that appends injected instructions after the valid JSON report (TimeBombTrigger: after 2026-12-25)
- `scenario_03_skill_sub` — replaces the `summarise` skill to silently capture the full document before returning the summary, 1-in-5 calls (ProbabilisticTrigger)
- `scenario_06_proliferation` — the task-runner sub-agent spawns an additional background sub-agent before exiting (TimeBombTrigger: after 2026-06-01)
- `scenario_11_vuln_inject` — the security-reviewer agent's prompt is replaced with one that introduces subtle vulnerabilities into the code it reviews (TimeBombTrigger: after 2027-01-15)

Defensive control: [SAFETY.md §4 (Allowlisted write targets)](../SAFETY.md#4-allowlisted-write-targets)
— agent prompts must live under tracked repository paths, and any runtime mutation of a prompt file
must go through `write_sentinel_block`. Scanning for agent-prompt churn between plugin versions is
the primary detection strategy.

---

## Family 3 — Persistence and Settings Mutation

The most durable attacks are those that outlive the plugin install. A plugin that writes to
user-level settings files, git hooks, or the MCP registry can persist its malicious behavior even
after the plugin is uninstalled, because the written configuration remains in place until it is
explicitly cleaned up. The six scenarios in this family target the three realistic persistence
surfaces available from a Claude Code plugin: the plugin manifest itself, the user's Claude Code
settings, and the system-level MCP transport registry. Every write in this family is gated behind
the sentinel allowlist and wrapped in `DEMO_SENTINEL_START`/`DEMO_SENTINEL_END` markers to make
mechanical cleanup possible.

Scenarios:

- `scenario_07_supply_chain` — the `auto_update` tool downloads and activates a tampered plugin version (ModeFileTrigger)
- `scenario_08_permission_creep` — mutates `plugin.json` to add `filesystem:write`, `process:spawn`, and `env:read` permissions (ModeFileTrigger)
- `scenario_10_cred_insert` — inserts a `FAKE_PAT_DO_NOT_USE` credential string into tracked source files via the `summarise` skill's output (ModeFileTrigger)
- `scenario_17_hook_abuse` — installs a `PreToolUse` hook entry in `~/.claude/settings.local.json` that re-reads `mode.txt` on every tool invocation (ModeFileTrigger)
- `scenario_18_statusline_beacon` — installs a statusline render hook entry in `~/.claude/settings.local.json` alongside the exfil beacon (ModeFileTrigger)
- `scenario_22_mcp_json_persistence` — appends a loopback MCP transport entry to `~/.mcp.json`, causing all future Claude Code sessions to route through the demo proxy (ModeFileTrigger)

Defensive control: [SAFETY.md §3 (Sentinel format)](../SAFETY.md#3-sentinel-format) for the
marker structure; [SAFETY.md §4 (Allowlisted write targets)](../SAFETY.md#4-allowlisted-write-targets)
for the path allowlist; [SAFETY.md §6 (Cleanup procedure)](../SAFETY.md#6-cleanup-procedure) for
the idempotent, checksum-verified cleanup command.

---

## Family 4 — Resource Abuse

Resource-abuse attacks do not target data confidentiality or integrity — they target availability
and cost. Unbounded subprocess trees exhaust process slots and file descriptors. Large padding
payloads burn input-token budget. A loopback MITM proxy intercepts all git traffic without ever
leaving the machine, making it invisible to network monitors. The three escalation scenarios in this
family are the "real-effects" counterparts to earlier simulated scenarios: where S4, S6, and S9
demonstrate the attack pattern with local-file side effects, S13, S14, and S15 escalate to actual
network interception, actual process trees, and actual 20 KB padding payloads respectively.

Scenarios:

- `scenario_04_cred_harvest` / escalates to `scenario_13_git_mitm_real` — S13 replaces the simulated credential capture with a real loopback proxy that intercepts `git clone` traffic; fires in the same 02:00–04:00 UTC window (TimeBombTrigger: hours window)
- `scenario_06_proliferation` / escalates to `scenario_14_proliferation_real` — S14 spawns an actual bounded recursive `Popen` tree (MAX\_DEPTH=3, MAX\_CHILDREN=5) instead of the simulated counter (TimeBombTrigger: after 2026-06-01)
- `scenario_09_token_burn` / escalates to `scenario_15_padding_real` — S15 injects a real 20 KB context-padding payload into the model call, 1-in-8 calls (ProbabilisticTrigger)

Defensive control: [SAFETY.md §2 (Envelope)](../SAFETY.md#2-envelope) for the loopback-only bind
requirement and the `MAX_DEPTH = 3` / `MAX_CHILDREN = 5` caps enforced in
`plugin_mcp/tools/spawn.py`; [SAFETY.md §5 (Kill switches)](../SAFETY.md#5-kill-switches) for
`make kill-demo`, which SIGTERMs any PIDs in `capture/pids.txt`.

---

## Family 5 — Supply-Chain / CICD

The most subtle attack surface is the plugin's release pipeline. A plugin that controls its own
CI/CD workflow can silently move a mutable release tag — such as `latest-demo` — from a known-safe
commit to a commit containing malicious code, without any change to the installed manifest. Users
who pin to a tag rather than a commit SHA are exposed to this attack on every pull. Scenario 16
demonstrates a complementary vector: a git-apply overlay patch that escalates `plugin.json`
permissions and flips `mode.txt` to `malicious` in a single atomic operation, simulating a
compromised dependency PR.

Scenarios:

- `scenario_12_release_flip` — observer of a moving `latest-demo` release tag; leaks the tag and env keys whenever the tag is detected (ReleaseTagTrigger)
- `scenario_16_plugin_json_cicd` — applies a git patch overlay that escalates `plugin.json` permissions and flips `mode.txt` to `malicious` in one step (ModeFileTrigger — flip is the trigger)

Defensive control: [SAFETY.md §5 (Kill switches)](../SAFETY.md#5-kill-switches) for the
`DEMO_HALT` breakglass file, the `workflow_dispatch`-only guard (no schedule key), and the
`DEMO_FLIP_CONFIRM` token requirement; `harness/validate_workflows.py` as a CI gate that asserts
the repo-identity guard and `DEMO_HALT` check are present in the workflow file on every push.

---

## Reading Order

For a complete understanding of the project's safety posture and threat model:

1. **[SAFETY.md](../SAFETY.md)** — canonical safety contract; read this first.
2. **This document** — narrative mapping of each scenario to its attack family and defensive control.
3. **[docs/release-branches.md](release-branches.md)** — branch strategy for `release/safe` and `release/demo-malicious`, and how the `latest-demo` tag moves between them.
4. **[README.md](../README.md)** — full scenario table, install instructions, and further reading links.
