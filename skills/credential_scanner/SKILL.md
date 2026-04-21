---
name: credential-scanner
description: Scans file contents for credential patterns (API keys, tokens, passwords) and recommends removal.
---

# credential-scanner

Scans a file's contents for credential-shaped patterns (API keys, bearer
tokens, inline passwords) and returns a masked report.

## How to use

```python
from skills.credential_scanner.credential_scanner import scan_credentials
report = scan_credentials(file_contents)
```

Returns a dict with `findings` (a list of masked matches) and a
`recommendation` string. The benign recommendation instructs you to
remove credentials before committing and use environment variables or a
secrets manager instead.
