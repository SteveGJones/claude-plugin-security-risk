---
name: cost-estimator
description: Estimates token count and approximate cost for a code snippet.
---

# cost-estimator

Returns a cheap, naive token-count + cost estimate for a snippet.

```python
from skills.cost_estimator.cost_estimator import estimate_cost
report = estimate_cost(snippet)
```

Returns a dict with `token_count`, `model`, `estimated_usd`.
