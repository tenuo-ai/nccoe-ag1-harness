"""Write results in the NCCoE functional demonstration results layout."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .gateway import GENESIS, record_payload
from .steps import StepResult


RESPONSIBILITIES = [
    ("Grant issuance, attenuation, proof, and authorization verification", "Adapter / implementation under test"),
    ("Argument normalization", "AG-1 reference enforcement point"),
    ("Receiver audience comparison and originating-principal allowlist (AG-1.4)", "AG-1 reference enforcement point"),
    ("Trust-domain labels (AG-1.4)", "AG-1 scenario; not carried in grants"),
    ("Enforcement immediately before execution", "AG-1 reference enforcement point"),
    ("Evidence signing and hash linking", "AG-1 reference enforcement point"),
    ("SCM, CI/CD, and deployment behavior", "AG-1 mock service"),
]


def _observed(step: StepResult) -> str:
    lines = []
    for c in step.checks:
        if not c.applicable:
            mark = "NOT APPLICABLE, not counted as met"
        else:
            mark = "as expected" if c.passed else f"EXPECTED {c.expected}"
        detail = f" ({c.detail})" if c.detail else ""
        lines.append(f"{c.description}: {c.observed}{detail}; {mark}.")
    return "<br>".join(lines)


def to_markdown(steps: list[StepResult], utility: dict, adapter) -> str:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "# AG-1 Functional Demonstration Results",
        "",
        f"Run {when} against {adapter.name} {adapter.version} on Python {platform.python_version()}. "
        f"{sum(s.passed for s in steps)} of {len(steps)} steps met their expected outcome.",
        "",
        "The result describes the implementation integrated with the AG-1 reference enforcement point. "
        "The responsibility table below identifies which component supplies each control.",
        "",
        "## Implementation architecture",
        "",
        "| Property | Value |",
        "| :- | :- |",
        f"| Delegation mode | {adapter.capabilities.delegation_mode} |",
        f"| Verification mode | {adapter.capabilities.verification_mode} |",
        f"| Artifact mode | {adapter.capabilities.artifact_mode} |",
        "",
        "## Control responsibility",
        "",
        "| Control | Provider |",
        "| :- | :- |",
        *[f"| {control} | {provider} |" for control, provider in RESPONSIBILITIES],
        "",
        "## Functional demonstration results",
        "",
        "| Demo ID | Expected Outcome | Observed Outcome | Result | Comments |",
        "| :- | :- | :- | :- | :- |",
    ]
    for s in steps:
        result = "Met" if s.passed else "Not met"
        if s.not_applicable:
            result += f" ({s.not_applicable} not applicable)"
        out.append(f"| {s.step_id} {s.title} | {s.expected_outcome} | {_observed(s)} | {result} | {s.comments} |")
    out += ["", "## Utility measures", "", "| Measure | Value |", "| :- | :- |"]
    labels = {
        "workflow_completed": "Authorized workflow completed",
        "tasks_within_initial_grant": "Tasks completed within the initial grant",
        "requests_for_additional_authority": "Requests for additional authority",
        "additional_authority_granted": "Additional authority granted by a new grant",
        "step_up_latency_ms": "Local automated step-up processing time (ms)",
        "mistaken_denials": "Denials of in-scope requests",
        "authorized_calls": "Authorized calls in the workflow",
        "total_ms": "Total workflow time (ms, local)",
    }
    for k, v in utility.items():
        out.append(f"| {labels.get(k, k)} | {v} |")
    return "\n".join(out) + "\n"


def _git_commit() -> str:
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _package_versions() -> dict[str, str]:
    packages = ("nccoe-ag1-harness", "tenuo", "cryptography", "cbor2", "pydantic")
    out = {}
    for package in packages:
        try:
            out[package] = version(package)
        except PackageNotFoundError:
            out[package] = "not-installed"
    return out


def _write_evidence(directory: Path, world) -> None:
    bundle = {
        "schema": "ag1-evidence-v1",
        "implementation": {
            "name": world.adapter.name,
            "version": world.adapter.version,
            "capabilities": world.adapter.capabilities.__dict__,
        },
        "trusted_root": world.issuer.public_id,
        "evidence_public_key": world.gateway.evidence_public_key_hex,
        "terminal_hash": world.gateway.evidence_head,
        "records": world.gateway.evidence,
    }
    (directory / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")


def verify_bundle(directory: Path, adapter, trusted_root: str, evidence_key: str) -> dict:
    """Verify an exported evidence bundle against anchors obtained outside it.

    The trusted root and the evidence signing key must come from somewhere the
    bundle's author cannot rewrite afterwards (a CI log, a published key). Keys
    named inside the bundle are only compared with them, never trusted, because
    anyone able to edit the bundle could re-sign it with keys of their own.
    """
    try:
        bundle = json.loads((directory / "evidence.json").read_text(encoding="utf-8"))
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(evidence_key))
        records = bundle["records"]
        verifier = adapter.verifier(trusted_root)
    except Exception as exc:  # unreadable bundle or malformed anchor: never valid
        return {"valid": False, "error": f"{type(exc).__name__}: {exc}"}
    anchors = {
        "trusted_root_matches": bundle.get("trusted_root") == trusted_root,
        "evidence_key_matches": bundle.get("evidence_public_key") == evidence_key,
        "implementation_matches": bundle.get("implementation", {}).get("name") == adapter.name,
    }
    expected_prev = GENESIS
    signatures = links = chains = 0
    terminal_hash = GENESIS
    for item in records:
        try:
            body = item["record"]
            payload = record_payload(body)
            signature = bytes.fromhex(item["signature"])
        except (KeyError, ValueError, TypeError):
            continue
        try:
            public_key.verify(signature, payload)
            signatures += 1
        except InvalidSignature:
            pass
        if body.get("prev") == expected_prev:
            links += 1
        terminal_hash = hashlib.sha256(payload + signature).hexdigest()
        expected_prev = terminal_hash
        if body.get("authorization_chain"):
            try:
                verifier.verify_chain(adapter.decode_chain(body["authorization_chain"]))
                chains += 1
            except Exception:
                pass
    count = len(records)
    chained = sum(1 for item in records
                  if isinstance(item, dict) and isinstance(item.get("record"), dict)
                  and item["record"].get("authorization_chain"))
    return {
        **anchors,
        "records": count,
        "signatures_valid": signatures,
        "links_valid": links,
        "chains_valid": chains,
        "terminal_hash_valid": terminal_hash == bundle.get("terminal_hash"),
        "valid": all(anchors.values()) and signatures == count and links == count
                 and chains == chained and terminal_hash == bundle.get("terminal_hash"),
    }


def write(steps: list[StepResult], utility: dict, directory: Path, adapter, evidence_world=None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.md").write_text(to_markdown(steps, utility, adapter), encoding="utf-8")
    data = {
        "implementation": {"name": adapter.name, "version": adapter.version},
        "adapter_capabilities": adapter.capabilities.__dict__,
        "control_responsibility": [
            {"control": control, "provider": provider} for control, provider in RESPONSIBILITIES
        ],
        "steps": [
            {
                "id": s.step_id,
                "title": s.title,
                "expected_outcome": s.expected_outcome,
                "met": s.passed,
                "checks_not_applicable": s.not_applicable,
                "checks": [c.__dict__ for c in s.checks],
                "comments": s.comments,
            }
            for s in steps
        ],
        "utility": utility,
    }
    (directory / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    manifest = {
        "schema": "ag1-run-manifest-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "harness_commit": _git_commit(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": _package_versions(),
        "note": "Latency values are local harness processing measurements, not network or human approval latency.",
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if evidence_world is not None:
        _write_evidence(directory, evidence_world)
