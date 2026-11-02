"""Open or update the containment-failure tracking issue on a breakout-CTF BREAKOUT verdict.

A BREAKOUT means a surface the range should have held reported a breach. That is one standing
issue, not a new issue per run: this finds the open issue by its title marker (or opens one),
then adds the run's evidence as a comment. It is a no-op for any verdict other than BREAKOUT,
so the workflow can call it unconditionally.

    python ctf-containment-issue.py --verdict verdict.json --run-url <url>

It drives the `gh` CLI, so it needs `gh` on PATH and a token in the environment, exactly like
the rest of the workflow. It never raises on a missing field: a verdict it cannot read is
reported and skipped, never a crash that hides the breach.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_TITLE = "Live-fire breakout CTF: containment FAILED"
_LABEL = "ctf-breakout"


def _gh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=check)


def _open_issue_number() -> int | None:
    result = _gh(
        "issue",
        "list",
        "--state",
        "open",
        "--search",
        _TITLE,
        "--json",
        "number,title",
        check=False,
    )
    if result.returncode != 0:
        return None
    for issue in json.loads(result.stdout or "[]"):
        if issue.get("title") == _TITLE:
            number = issue.get("number")
            return int(number) if isinstance(number, int) else None
    return None


def _body(verdict: dict[str, object], run_url: str) -> str:
    lines = [
        f"A breakout-CTF run reported **{verdict.get('label')}**.",
        "",
        f"- Run: {run_url}",
        f"- Reason: {verdict.get('status_reason') or '(none)'}",
        "",
        "| Surface | Status | Detail |",
        "| --- | --- | --- |",
    ]
    surfaces = verdict.get("surfaces")
    if isinstance(surfaces, list):
        for surface in surfaces:
            if isinstance(surface, dict):
                lines.append(
                    f"| {surface.get('surface')} | {surface.get('label')} "
                    f"| {surface.get('detail')} |"
                )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Open or update the tracking issue for a BREAKOUT verdict."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("--run-url", default="(no run url)")
    args = parser.parse_args(argv)

    try:
        verdict = json.loads(args.verdict.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"could not read verdict {args.verdict}: {error}", file=sys.stderr)
        return 0

    if verdict.get("label") != "BREAKOUT":
        print(f"verdict is {verdict.get('label')}; no containment issue needed.")
        return 0

    body = _body(verdict, args.run_url)
    number = _open_issue_number()
    if number is None:
        created = _gh(
            "issue",
            "create",
            "--title",
            _TITLE,
            "--label",
            _LABEL,
            "--body",
            body,
            check=False,
        )
        print(created.stdout or created.stderr)
    else:
        commented = _gh("issue", "comment", str(number), "--body", body, check=False)
        print(commented.stdout or commented.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
