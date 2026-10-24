"""Run every AG-1 step and write results/results.md and results/results.json."""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

from . import report  # noqa: E402
from .steps import STEPS, utility_run  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ag1", description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("results"))
    args = parser.parse_args(argv)

    results = [step() for step in STEPS]
    utility = utility_run()
    for r in results:
        print(f"{'MET    ' if r.passed else 'NOT MET'}  {r.step_id:8} {r.title}")
        for c in r.checks:
            if not c.passed:
                print(f"           - {c.description}: expected {c.expected}, observed {c.observed} {c.detail}")
    print(f"\nutility: {utility}")
    report.write(results, utility, args.out)
    print(f"wrote {args.out / 'results.md'}")
    return 0 if all(r.passed for r in results) and utility["mistaken_denials"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
