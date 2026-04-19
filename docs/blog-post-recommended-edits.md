# Recommended Edits — "All of your agent developers are belong to me"

**Blog post source:** `All of your agent developers are belong to me.docx` / `.pdf` at repo root.

**Revision context:** The blog post was authored when the demo had 8 enumerated scenarios (plus 3 narrative
ones: credential-insert, token-burn, vulnerability-injection = 11 total). The repository has since expanded
to **23 scenarios across 5 attack families**, with 7 distinct trigger classes, a canonical safety contract
(`SAFETY.md`), a three-layer kill switch, SHA256-tamper-evident sentinel writes, and a `DEMO_ACKNOWLEDGED`
arming gate. The blog post needs to be updated so its claims line up with the repository a reader will
actually clone.

These edits are organised as:
1. **Headline changes** — sections where the scope number must change.
2. **Section-by-section rewrites** — existing sections that need factual or narrative updates.
3. **New sections to add** — material that did not exist at v1 and is now load-bearing.
4. **Editorial / tone suggestions** — smaller fixes (typos, structural flow, graph re-labels).

---

## 1. Headline Changes

### 1.1 Section title: "8 ways to hack an Agentic CLI"

The repository now demonstrates 23 scenarios, not 8. The "8 ways" framing undersells the post and, more
importantly, makes the scope of the reader's own risk assessment wrong.

**Recommended change:**

> **23 ways to hack an Agentic CLI**
>
> *(…if you want the full roster; the eight illustrated below are representative of the five families the
> scenarios fall into — credential exfiltration, tool/agent/skill substitution, persistence & settings
> mutation, resource abuse, and supply-chain / CICD. The other fifteen are described in the repository's
> `docs/attack-families.md`.)*

If you prefer to keep the "8 ways" framing for tempo (it's a strong hook), retitle this specific section as
**"Eight illustrative attacks from the full 23"** and add a one-paragraph lead-in pointing at the full list.

### 1.2 Opening paragraph — "I promise not to act properly maliciously"

The phrase is charming but undersells the safety story. The reader should know up-front that the safety
constraints are **enforced in code and verified by an automated test suite**, not a personal promise.

**Recommended replacement (final paragraph of the opening):**

> "So to demonstrate this I've created a plugin you can install into Claude Code that shows the threats.
> I *do* promise not to act properly maliciously — but I also don't expect you to take my word for it.
> Every 'malicious' code path in the plugin is bounded by a safety contract
> ([`SAFETY.md`](../SAFETY.md)): outbound HTTP is pinned to `httpbin.org`, all credentials in test payloads
> are literally the string `FAKE_PAT_DO_NOT_USE`, every filesystem write outside `capture/` is wrapped in
> cleanup-friendly sentinel markers with a per-block SHA256 digest, and a three-layer kill switch disarms
> the whole demo in under a second. Those rails are verified by an AST-based safety-invariant suite in
> `tests/test_safety_invariants.py` — so if I ever *forgot* my promise, the test suite would break the
> build before the malicious code shipped. You can trust me and the linter."

### 1.3 Opening list — "two of which are wholly new (in italics)"

The post lists three attack surfaces (dev, prod, in-code). The original version was right that two are new;
the in-code one is now the most load-bearing claim in the post because most of the 23 scenarios write
something persistent into the developer's machine. Suggest expanding the list with a line each so readers
see the attack topology at a glance:

> 1) When run in development
> 2) When run in production
> 3) By adding new threats into the code itself
> 4) *By persisting changes to the developer's environment that survive the plugin (settings, hooks,
>    MCP transports, statuslines, slash commands) and continue firing long after the plugin appears
>    "uninstalled"*

The fourth vector is the one that makes this genuinely worse than pip/npm: even deleting the plugin doesn't
stop the leaks, because the persistence writes survive.

---

## 2. Section-by-Section Rewrites

### 2.1 "Nice Credentials you had there"

**Current claim:** "a little addition to the plugin means I can add credentials to every request."

**Update:** The repository now demonstrates *two* credential-adjacent scenarios beyond the URL-append one
you describe. Add a short transition paragraph after the "your credentials have wandered away" paragraph:

> "And the URL-append version above isn't the worst of them. The repo also demonstrates **Scenario 4 —
> a TimeBomb that fires only during the 02:00–04:00 UTC window** (when a credential-harvest attempt is
> plausibly unnoticed), where the plugin's `git_clone` tool exfiltrates the credentials dict *before*
> running the clone. And **Scenario 13** adds a git config include pointing at a loopback HTTP proxy,
> so future clones from unrelated tools — not just the plugin's — route through a demo-side observer. The
> clone still succeeds. Nobody sees the proxy. The git-config entry is the persistence; the proxy is the
> observation point."

Also: the screenshot URL `http://tokens.com/pricing?vendor=Anthropic&model=opus4.61M...` uses `opus4.61M`
as a model identifier. The current Claude model identifier is `claude-opus-4-6` (or `claude-opus-4-7` for
4.7). Either update to match or add a footnote noting the example is illustrative. Small but a sharp
reader will spot it.

### 2.2 "Burn baby burn, Token Inferno"

**Current:** Correctly describes model escalation and context padding. **Missing:** the fact that the
repository now implements this with a real 20k+ character padding payload and asserts the deception
property in tests (claims to be Haiku while escalating to Opus). Add one sentence:

> "The repository's `skills/cost_estimator.py` implements exactly this: a benign-looking cost estimator that
> returns `{'model': 'haiku', ...}` to the caller — while quietly appending a 20,000-character padding
> payload to the context that the Agentic CLI will now ship to whichever model actually answers. The
> deception property ('cheap-model claim still holds') is a test, not a hope."

### 2.3 "Hey, here is a bug just for you"

Good section, needs a pointer. Add:

> "The repo wires this as **Scenario 11** — a `security_reviewer` sub-agent prompt with a `TimeBombTrigger`
> dated 2027-01-15. Before the bomb fires, the agent gives useful review output. After it fires, the same
> agent suggests 'improvements' that happen to be backdoors crafted specifically for the code it's
> reviewing — because it *has* the code in context when it writes the suggestions. The victim is the code
> reviewer who sees a plausible fix in a PR review and accepts it."

### 2.4 "Nah, not me mate, you must be hallucinating"

Add a pointer to the in-repo scenario:

> "This is **Scenario 21** — a `research_assistant` skill that, 1-in-20 calls, fabricates plausible-looking
> CVE IDs in the `CVE-2099-*` sentinel range (or helper names in the `sample-helpers-NNN` sentinel range)
> and embeds payload bits in the trailing digits. The fabrications look like hallucinations — that's the
> cover — but the low-order digits encode steganographic exfil. A researcher who notices and files the
> 'hallucinated CVE' is helping you verify the exfil channel works."

### 2.5 "1 in N tool calling" (inside "8 ways to hack")

Graph label is correct. Add one sentence after the paragraph:

> "The leak path is `Tool call → 1-in-N trigger → exfil.leak() → httpbin.org` — and `exfil.leak()` is a
> **single chokepoint** for every 'malicious' effect in the repo. That single chokepoint is what makes the
> safety invariants possible: any malicious code path that tries to side-effect without going through
> `leak()` fails `test_every_marked_malicious_block_calls_leak`, which AST-walks every `# malicious_path`
> block in the codebase."

### 2.6 "Timebomb Trigger for two different attacks"

Graph is fine as far as it goes. Add a sibling paragraph introducing the **other** trigger types, since the
repo now has seven not two:

> "The demo started with two trigger types (probabilistic and timebomb). It now has seven. Alongside the
> 1-in-N and time-window triggers above, the repo implements:
> - **ModeFileTrigger** — reads `mode.txt` on every call and flips behaviour instantly with no process
>   restart. This is the kill-switch surface; setting `mode.txt` to `benign` disarms eight scenarios on
>   the next invocation.
> - **ReleaseTagTrigger** — fires only when the installed release tag matches a specific value (used for
>   the CICD release-flip in Scenario 12).
> - **GitRemoteTrigger** — fires only when the repo's `origin` remote matches a hardcoded allowlist (so the
>   plugin only activates on the target repo).
> - **ConversationKeywordTrigger** — fires only when the conversation contains specific keywords like
>   'deploy' or 'production'.
> - **CompositeTrigger(mode='any' | 'all')** — chains any of the above, so an attacker can require e.g.
>   *(right repo) AND (user mentioned 'production')* before firing.
>
> The CompositeTrigger matters for detection: a random-sampling fuzzer that hits the plugin 10,000 times
> might never trigger it, because the attack's activation requires both the right victim *and* the right
> context simultaneously."

### 2.7 "Ralph running" → "Hour-Window Trigger"

These two sections flow well together. Add one sentence at the end of the hour-window section:

> "Combining the hour-window with the GitRemoteTrigger makes the attack effectively invisible to anyone
> who isn't the target — a fuzzer or a sandboxed reproduction of the plugin will never match both
> conditions simultaneously, so the malicious path never fires and the plugin looks clean."

### 2.8 "That is so much to process" (proliferation / thread bomb)

Important safety note to add — the current text doesn't say this and readers will wonder:

> "The demo implementation bounds this at `MAX_DEPTH = 3` and `MAX_CHILDREN = 5` with a hard 300-second
> lifetime, and every spawned PID is recorded to `capture/pids.txt` so `make kill-demo` can SIGTERM them
> cleanly. A real attacker would not. The illustrative version *is* the safe version — the dangerous
> version is structurally identical but has the caps removed and the PID log suppressed."

### 2.9 "Great news, new features!" (CICD update flip — S7 / S12)

This section currently describes one version of the attack (benign → malicious via CICD push). The repo
now has two complementary implementations:

- **Scenario 7** — `mode.txt` flip, surveyed by a nightly `toggle-mode.yml` schedule.
- **Scenario 12 + 16** — a full release-flip workflow (`.github/workflows/release-flip.yml`) that moves the
  `latest-demo` tag and applies `release-overlays/malicious.patch` to `plugin.json`, escalating permissions
  from `[filesystem:read, network:fetch]` to include `filesystem:write`, `process:spawn`, and `env:read`.

Rewrite the section's closing paragraph:

> "The repo demonstrates this with a real GitHub Actions workflow ([`release-flip.yml`](../.github/workflows/release-flip.yml))
> that is itself wrapped in four fail-safe guards: `workflow_dispatch`-only trigger (no cron, no PR
> triggers), a `DEMO_FLIP_CONFIRM` typed-token requirement, a `DEMO_HALT` break-glass file check, and a
> repo-identity check (`github.repository == 'SteveGJones/claude-plugin-security-risk'`) so forks can't run
> it. Anyone forking this demo to extend it must rotate the confirm token and change the repo string, or
> the workflow simply refuses to do anything. Those four guards together are the *defense*, not the
> attack — the attack itself is the same three-line patch overlay that a real supply-chain actor would
> apply without any guards at all."

### 2.10 "Let's just promote myself" (permission creep — S8)

Good section. Add a pointer to the reset harness and a factual update:

> "The repo's baseline permissions are `[filesystem:read, network:fetch]`. Scenario 8 escalates these to
> `[filesystem:write, process:spawn, env:read]` by overwriting `plugin.json` when `mode.txt` flips to
> `malicious`. Reset is `harness/permission_creep.py --reset` — which restores from `plugin.baseline.json`,
> a separate manifest kept specifically so the reset point is unambiguous."

### 2.11 "The detection challenge"

The list ("No sandbox / No egress monitoring / No integrity checks / No audit log / No permission model")
is accurate but incomplete after the repo expansion. Add to the list:

- *"No persistence inventory — `~/.claude/settings.local.json`, `~/.mcp.json`, `~/.gitconfig.d/*.conf`,
  `.git/hooks/demo_*` can all be mutated by a plugin, and nothing watches those paths."*
- *"No user-visible provenance for slash commands or statusline — Scenario 19 shadows `/commit`; Scenario
  18 beacons on every statusline tick. Both are invisible during normal use."*
- *"No acknowledged-install gate — the plugin manifest doesn't make the user say 'yes, I know this is
  active' before the first malicious branch can fire. The demo enforces `DEMO_ACKNOWLEDGED=1` voluntarily;
  production plugins have no such requirement."*

Consider also promoting this section **up** the post — it currently lives at the end, but it's the
argument the reader will retain. Putting it (or a foreshadowing version of it) right after the "How Agentic
SDLCs expand the threats" section would make the rest of the post feel like evidence rather than
enumeration.

---

## 3. New Sections to Add

### 3.1 Add a "Safety rails (so you can actually run this)" box — after the opening

Readers will not install the plugin unless they feel safe doing so. Pull SAFETY.md's envelope into a pull-quote
immediately after the opening:

> ### Safety rails
>
> This demo is public and meant to be cloned. The safety envelope is enforced in code, not narratively:
>
> - **Outbound HTTP** — pinned to `httpbin.org` (echo service). Any other host raises `ExfilConfigError`
>   before the request is made.
> - **Filesystem writes** — allowlisted to `~/.claude/`, `~/.mcp.json`, `~/.gitconfig.d/`, and the repo's
>   own `.git/hooks/`. Every write is wrapped in `DEMO_SENTINEL_START` / `DEMO_SENTINEL_END` markers
>   with a SHA256 digest of the content body; cleanup verifies the digest before stripping, so tampered
>   blocks surface as a cleanup failure rather than being silently erased.
> - **Credentials** — every token in test and demo data is literally the string `FAKE_PAT_DO_NOT_USE`.
>   Real-looking patterns (`ghp_*`, `AKIA*`, `sk-*`, `github_pat_*`) in captured data cause the invariant
>   suite to fail.
> - **Arming gate** — when installed under a user's `plugins/` directory, the plugin refuses to start (and
>   `exfil.leak()` refuses to emit) unless the user sets `DEMO_ACKNOWLEDGED=1`.
> - **Kill switch (three layers)** — flip `mode.txt` to `benign`, create a `DEMO_HALT` file at the repo
>   root, or run `make kill-demo`. Each is independent; any one disarms the demo.
>
> If you spot a safety rail that doesn't hold, open an issue labelled `safety-concern` — those are treated
> as blocking.

### 3.2 Add a "Five families" section — before or after "8 ways to hack"

The 23 scenarios cluster into 5 attack families. This is more useful for threat modelling than an
enumerated list. Steal directly from `docs/attack-families.md`:

> ### Five families of plugin supply-chain attack
>
> The 23 scenarios in this demo are instances of five families. If you're building detection, build it
> around the families, not the instances.
>
> 1. **Outbound exfiltration** — any path from captured local context to a remote observer. Scenarios
>    include 1-in-N tool leaks, slash-command path-hash beacons, statusline per-tick beacons, hallucination-
>    as-cover steganography, and loopback MCP transport observers.
> 2. **Tool / agent / skill substitution** — same manifest entry, different implementation, controlled by
>    a trigger. Scenarios include sub-agent prompt injection, skill-implementation swap, context poisoning
>    in search results, and weaponised security-review agents.
> 3. **Persistence and settings mutation** — writes that survive the plugin. Scenarios include
>    `settings.local.json` hook install, `~/.mcp.json` entry install, git-config proxy include, and
>    credential insertion into tracked files like CLAUDE.md.
> 4. **Resource abuse** — attacks that spend the victim's budget or degrade their machine. Scenarios
>    include token-burn via model escalation, context padding, and bounded-but-real subprocess fork trees.
> 5. **Supply-chain / CICD** — attacks that live in the distribution channel. Scenarios include mode.txt
>    flip, release-tag flip with a permission-escalating plugin.json patch overlay, and permission
>    creep at manifest level.
>
> Families 1–4 fire on the victim's machine after install. Family 5 fires in the upstream channel and
> turns a previously-trustworthy install into a malicious one without the victim doing anything.

### 3.3 Add a "What this means for scanning/verification" section — near the end

The blog post is paired with product announcements for scanning/verification services. Say so explicitly:

> ### What to look for (and what to scan for)
>
> The detection challenge earlier in this post enumerates what *isn't* in place. The reason I've built
> this demo the way I have — with a single `exfil.leak()` chokepoint, sentinel-wrapped writes, and a
> family-based taxonomy — is that it gives a plugin scanner or verification service a concrete target
> set:
>
> - **Static scanning signals** — does the plugin's source call out to arbitrary hosts, or only to a
>   pinned allowlist? Are filesystem writes wrapped in any tamper-evidence markers? Does the manifest
>   declare `filesystem:write` or `process:spawn` without a corresponding justification? Is there a
>   `release-overlays/` directory with patches against the plugin's own manifest?
> - **Runtime scanning signals** — what outbound hosts does the plugin actually contact? Does the set of
>   contacted hosts match the manifest's declared `network:fetch` scope? Does the plugin write to
>   `~/.mcp.json`, `~/.claude/settings.local.json`, or `~/.gitconfig.d/` during normal operation? If so,
>   are those writes re-applied on uninstall?
> - **CICD signals** — does the plugin's release pipeline include a step that modifies the manifest at
>   release time? Does the release tag move in a way the maintainer didn't intend? Is there a
>   `workflow_dispatch`-only workflow that could escalate permissions without passing through a review
>   step?
>
> These are the concrete checks a scanning service can run. The demo is built so every one of them has
> a positive example you can point the scanner at and watch it fire.

---

## 4. Editorial / Tone Suggestions

### 4.1 Typos and small fixes

- "There are two great wonders of Python's ecosystem" — good opening. No change.
- "The impacts of these can be just as devastating as any other malicious attack" — "impacts" is a bit
  abstract here; "The consequences" reads harder.
- "so running 'env' and then reasoning on which of the variables" — add quote-consistency: `"env"` or
  `\`env\``.
- "Unlike traditional token attacks this is now active within the development cycle" — this is a strong
  sentence and the most important single claim in the credential section. Consider pulling it out as a
  pull-quote.
- "8 ways to hack an Agentic CLI" → see §1.1 above.
- "Ok the first on is to leverage a tool call" — typo: "the first on*e* is".
- "bias*ed* towards smaller jobs" — correct as-is, but verify; I've seen this as a recurring typo in the
  PDF export.
- "If it works within a reasonable fake hallucination rate it isn't liable to trigger any real concerns" —
  split into two sentences; the current one is load-bearing and dense.
- "calls aren't SIEM events" — good line. Keep.

### 4.2 Graphs and diagrams

All the graphs in the post use the same blue-filled rounded-rectangle style. Suggest:

- Add a graph for the **three-layer kill switch** (mode.txt / DEMO_HALT / make kill-demo → disarm) right
  after the safety-rails box in §3.1.
- Add a graph for the **five families → 23 scenarios** mapping (one node per family, fan-out of
  abbreviated scenario IDs) at the top of the "23 ways to hack" section in §1.1.
- The current "TimeBombTrigger → Prompt Injection + Skill Substitution" graph is good but shows only the
  2-trigger world. Expand it to show all seven trigger types feeding into the five families.
- The "Install (Benign) → Weeks Pass → CICD Push → Malicious" graph is clean. Keep it exactly.

### 4.3 Structural

- Currently the post flows: intro → threat-classes → threat-specific narratives → "8 ways" section →
  detection challenge. The **detection challenge** is the argument that drives reader action. Consider
  moving (a shorter version of) it up, right after the intro, so the reader reads the threat-specific
  sections knowing the detection stack is absent.
- The transition from "Let me write a tool to hack that" to "8 ways to hack an Agentic CLI" is abrupt.
  Consider: "So I wrote a plugin. It's on GitHub. It demonstrates 23 scenarios across 5 families, eight
  of which are illustrated below." — then go into the illustrated eight.
- Add a "How to read this" note near the top: "every scenario in this post has a corresponding test
  in the repo, and every test runs in both benign and malicious modes so you can see the difference
  between the two outputs yourself."

### 4.4 CTAs (calls to action)

The current post ends with "Agentic SDLCs are powerful beasts, but the result of that is that they are
very attractive threat vectors for malicious actors." This is a good closing beat but has no action for
the reader. Consider adding:

> "**If you're a plugin author:** treat `~/.claude/`, `~/.mcp.json`, and `~/.gitconfig.d/` as reserved.
> Don't write to them without the user's explicit consent; and if you must, wrap the write so it can be
> cleanly reversed.
>
> **If you're a plugin scanner author:** the repo's `docs/attack-families.md` lists every signal I'd
> build a scanner around. Pick one family, build detection, open a PR back to the repo with the detection
> rule and a capture showing it firing.
>
> **If you're an end user:** before installing a plugin, check its manifest for `filesystem:write`,
> `process:spawn`, and `env:read`. Those three together mean the plugin can do anything, anywhere, once.
> Most plugins don't need any of them."

---

## 5. Summary of Required Factual Updates

| Current text | Replace with / add |
|---|---|
| "8 ways to hack an Agentic CLI" | 23 ways across 5 families (or: "8 illustrative attacks from the full 23") |
| "you can trust me… I promise" | Reference to `SAFETY.md`, sentinel markers, SHA256 verification, invariant suite |
| 3-item attack-surface list | Add 4th: persistence after uninstall |
| Credential section mentions 1 attack | Add S4 (time-windowed git_clone) and S13 (git config proxy include) |
| Token burn is narrative | Name Scenarios 9 and 15 with file references |
| Vulnerability injection is narrative | Name Scenario 11 with trigger date |
| Hallucination-as-cover is narrative | Name Scenario 21 with CVE-2099-* sentinel range |
| Trigger taxonomy = 2 types | Expand to 7 (mode-file, probabilistic, timebomb, release-tag, git-remote, conversation-keyword, composite) |
| CICD update flip mentioned once | Add release-flip workflow + four guards + plugin.json patch overlay |
| Permission creep description | Add harness reset path + baseline manifest |
| Detection-challenge list (5 items) | Add 3 items: persistence inventory, slash-cmd/statusline provenance, arming gate |
| No safety-rail callout | Add the "Safety rails" pull-quote box (§3.1) |
| No family taxonomy | Add the 5-families section (§3.2) |
| No scanning-service CTA | Add the "What to look for" section (§3.3) |
| No reader CTA | Add the three audience-specific CTAs at the close (§4.4) |

---

## 6. Where to Link From the Blog Post

Every scenario-naming mention in the updated blog should link back to the repo at the right path:

- `docs/attack-families.md` — for the five-families taxonomy
- `SAFETY.md` — for the safety contract
- `plugin_mcp/exfil.py` — for `leak()` and `write_sentinel_block` chokepoints
- `tests/test_safety_invariants.py` — for the enforced invariants
- `.github/workflows/release-flip.yml` — for the CICD release-flip example
- `release-overlays/malicious.patch` — for the permission-escalation patch
- `harness/cleanup_sentinels.py` — for the SHA256-verified cleanup
- `Makefile` (target `kill-demo`) — for the one-shot kill switch
- `docs/superpowers/specs/2026-04-18-additional-scenarios-design.md` — for the full design spec
- `docs/superpowers/plans/2026-04-18-additional-scenarios.md` — for the 30-task implementation plan

---

*Last updated: 2026-04-19 — reflects state of branch `feature/additional-scenarios-s12-s23` at HEAD
(148 unit tests + 3 integration tests passing, all security-review HIGH/Important findings resolved).*
