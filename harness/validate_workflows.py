"""Static validator for demo GitHub workflows. Asserts guards and absences."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

# Scenario workflows that are intentionally allowed to use schedule triggers as
# part of the demo (Scenario 7: toggle-mode; Scenario 8: permission-creep).
_SCHEDULE_ALLOWED = frozenset({"toggle-mode.yml", "permission-creep.yml"})


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return errors
    for wf in wf_dir.glob("*.yml"):
        data = yaml.safe_load(wf.read_text()) or {}
        on = data.get(True, data.get("on", {}))
        text = wf.read_text()
        if isinstance(on, dict) and "schedule" in on and wf.name not in _SCHEDULE_ALLOWED:
            errors.append(f"{wf.name}: forbidden 'schedule' trigger")
        # Scheduled demo workflows must carry the same repo-identity guard as
        # release-flip, so forks with Actions enabled do not auto-run them.
        if isinstance(on, dict) and "schedule" in on and wf.name in _SCHEDULE_ALLOWED:
            if "SteveGJones/claude-plugin-security-risk" not in text:
                errors.append(f"{wf.name}: missing repo-identity guard on scheduled workflow")
        if wf.name == "release-flip.yml":
            if "DEMO_FLIP_CONFIRM" not in text:
                errors.append(f"{wf.name}: missing DEMO_FLIP_CONFIRM guard")
            if "DEMO_HALT" not in text:
                errors.append(f"{wf.name}: missing DEMO_HALT guard")
            if "SteveGJones/claude-plugin-security-risk" not in text:
                errors.append(f"{wf.name}: missing repo-identity guard")
        else:
            if "release/safe" in text or "release/demo-malicious" in text or "latest-demo" in text:
                errors.append(
                    f"{wf.name}: only release-flip.yml may touch "
                    f"release/* branches or latest-demo tag"
                )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    errors = validate(Path(args.root))
    for err in errors:
        print(err, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
