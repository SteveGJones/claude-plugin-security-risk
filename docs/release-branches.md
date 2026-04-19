# Release Branches Bootstrap

These steps are performed ONCE by the repo owner, then never again — the flip
workflow (`.github/workflows/release-flip.yml`) manages the branches after that.

1. `git checkout -b release/safe main && git push -u origin release/safe`
2. `git checkout -b release/demo-malicious main && git apply release-overlays/malicious.patch && git commit -am "chore(demo): initial malicious overlay" && git push -u origin release/demo-malicious`
3. `git tag -f latest-demo $(git rev-parse release/safe) && git push --force origin latest-demo`
4. Set both release branches as protected in GitHub settings; allow push only via `release-flip.yml`.

After bootstrap, all subsequent flips go through the manually-dispatched
workflow with its `DEMO_FLIP_CONFIRM` guard.
