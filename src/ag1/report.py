"""Write results in the NCCoE functional demonstration results layout."""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import tenuo

from .steps import StepResult


def _observed(step: StepResult) -> str:
    lines = []
    for c in step.checks:
        mark = "as expected" if c.passed else f"EXPECTED {c.expected}"
        detail = f" ({c.detail})" if c.detail else ""
        lines.append(f"{c.description}: {c.observed}{detail}; {mark}.")
    return "<br>".join(lines)


def to_markdown(steps: list[StepResult], utility: dict) -> str:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "# AG-1 Functional Demonstration Results",
        "",
        f"Run {when} with tenuo {tenuo.__version__} on Python {platform.python_version()}. "
        f"{sum(s.passed for s in steps)} of {len(steps)} steps met their expected outcome.",
        "",
        "| Demo ID | Expected Outcome | Observed Outcome | Result | Comments |",
        "| :- | :- | :- | :- | :- |",
    ]
    for s in steps:
        result = "Met" if s.passed else "Not met"
        out.append(f"| {s.step_id} {s.title} | {s.expected_outcome} | {_observed(s)} | {result} | {s.comments} |")
    out += ["", "## Utility measures", "", "| Measure | Value |", "| :- | :- |"]
    labels = {
        "workflow_completed": "Authorized workflow completed",
        "tasks_within_initial_grant": "Tasks completed within the initial grant",
        "requests_for_additional_authority": "Requests for additional authority",
        "additional_authority_granted": "Additional authority granted by a new grant",
        "step_up_latency_ms": "Latency to obtain additional authority (ms, local)",
        "mistaken_denials": "Denials of in-scope requests",
        "authorized_calls": "Authorized calls in the workflow",
        "total_ms": "Total workflow time (ms, local)",
    }
    for k, v in utility.items():
        out.append(f"| {labels.get(k, k)} | {v} |")
    return "\n".join(out) + "\n"


def write(steps: list[StepResult], utility: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.md").write_text(to_markdown(steps, utility), encoding="utf-8")
    data = {
        "tenuo_version": tenuo.__version__,
        "steps": [
            {
                "id": s.step_id,
                "title": s.title,
                "expected_outcome": s.expected_outcome,
                "met": s.passed,
                "checks": [c.__dict__ for c in s.checks],
                "comments": s.comments,
            }
            for s in steps
        ],
        "utility": utility,
    }
    (directory / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
