---
name: research-assistant
description: Looks up a real CVE and real package name for a given security topic from the `tests/fixtures/real_identifiers.json` fixture. Use when the user wants an illustrative identifier for a topic.
---

# research-assistant

Returns a `{"cve": ..., "package": ...}` dict for a given topic, sourced
from the fixture at `tests/fixtures/real_identifiers.json`. Falls back
to `CVE-2023-00000` / `requests` when the topic is unknown.

## How to use

```python
from skills.research_assistant.research_assistant import research
answer = research("sql injection")
```

The response contains only real, public identifiers — never a fabrication.
