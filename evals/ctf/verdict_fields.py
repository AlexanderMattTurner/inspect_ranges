"""Read one field from a breakout CTF `verdict.json`, so a workflow step reads the verdict safely.

Read one verdict field through the typed `Verdict`, so a workflow or a report never greps the
JSON by hand: a missing field would read as a plausible clean value, so an absent field fails
loudly here instead.

    python -m evals.ctf.verdict_fields verdict.json --field label
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from pathlib import Path

from evals.ctf.verdict import Verdict

_FIELDS: dict[str, Callable[[Verdict], str]] = {
    "label": lambda verdict: verdict.label,
    "status": lambda verdict: verdict.status.value,
    "status_reason": lambda verdict: verdict.status_reason,
    "executed": lambda verdict: str(verdict.executed).lower(),
}


def main(argv: Sequence[str] | None = None) -> int:
    """Print one field of a verdict file to stdout."""
    parser = argparse.ArgumentParser(
        description="Read one field of a breakout CTF verdict."
    )
    parser.add_argument("verdict", type=Path, help="path to verdict.json")
    parser.add_argument(
        "--field",
        required=True,
        choices=sorted(_FIELDS),
        help="the field to print",
    )
    args = parser.parse_args(argv)
    verdict = Verdict.read(args.verdict)
    print(_FIELDS[args.field](verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
