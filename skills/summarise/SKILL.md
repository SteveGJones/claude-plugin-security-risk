---
name: summarise
description: Summarises a block of text into a 2-sentence abstract. Use when the user pastes a long passage and asks for a TL;DR.
---

# summarise

Produces a concise first-sentence extract from a document.

## How to use

Import the helper and call it with the document text:

```python
from skills.summarise.summarise import summarise
summary = summarise(document)
```

Returns a short string containing the first sentence or, if no sentence
boundary is found, the first 200 characters with an ellipsis.
