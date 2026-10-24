import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ag1 import report
from ag1.__main__ import main
from ag1.adapters import load
from ag1.gateway import GENESIS, NormalizationError, parse_argv, record_payload
from ag1.spec import AdapterCapabilities
from ag1.steps import STEPS, StepResult, evidence_run, utility_run

ADAPTER = load(os.environ.get("AG1_ADAPTER", "tenuo"))


@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.__name__)
def test_step_meets_expected_outcome(step):
    result = step(ADAPTER)
    failed = [c for c in result.checks if c.applicable and not c.passed]
    assert not failed, [(c.description, c.expected, c.observed, c.detail) for c in failed]


def test_utility_run():
    u = utility_run(ADAPTER)
    assert u["workflow_completed"]
    assert u["mistaken_denials"] == 0
    assert u["additional_authority_granted"]


def _anchors(world):
    return world.issuer.public_id, world.gateway.evidence_public_key_hex


def test_exported_evidence_bundle_verifies_and_detects_tampering(tmp_path):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, evidence_world=world)
    assert report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]

    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    bundle["records"][0]["record"]["decision"] = "tampered"
    path.write_text(json.dumps(bundle))
    assert not report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]


def test_resigned_bundle_fails_against_independent_anchors(tmp_path):
    """Editing, truncating, and re-signing with the editor's own key must not verify."""
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())

    forger = Ed25519PrivateKey.generate()
    prev, records = GENESIS, []
    for item in bundle["records"][:-1]:
        body = {**item["record"], "decision": "forged", "prev": prev}
        payload = record_payload(body)
        signature = forger.sign(payload)
        records.append({"record": body, "signature": signature.hex()})
        prev = hashlib.sha256(payload + signature).hexdigest()
    bundle["records"], bundle["terminal_hash"] = records, prev
    bundle["evidence_public_key"] = forger.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    path.write_text(json.dumps(bundle))

    result = report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))
    assert not result["valid"]
    assert not result["evidence_key_matches"]
    assert result["signatures_valid"] == 0


@pytest.mark.parametrize("keep", [1, 0], ids=["drop-suffix", "drop-all"])
def test_truncated_bundle_fails_even_with_recomputed_head(tmp_path, keep):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    bundle["records"] = bundle["records"][:keep]
    head = GENESIS
    for item in bundle["records"]:
        head = hashlib.sha256(record_payload(item["record"]) + bytes.fromhex(item["signature"])).hexdigest()
    bundle["terminal_hash"] = head
    path.write_text(json.dumps(bundle))
    result = report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))
    assert result["terminal_hash_valid"] and not result["checkpoint_valid"] and not result["valid"]


def test_bundle_naming_another_root_fails(tmp_path):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    bundle["trusted_root"] = ADAPTER.new_principal("other-root").public_id
    path.write_text(json.dumps(bundle))
    result = report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))
    assert not result["valid"] and not result["trusted_root_matches"]


def test_verify_requires_independent_anchors(tmp_path):
    with pytest.raises(SystemExit):
        main(["--verify", str(tmp_path)])


def test_capability_declarations_are_validated():
    with pytest.raises(ValueError):
        AdapterCapabilities("holder_signed", "offline_chain", "anything")


def test_inapplicable_check_is_not_counted_as_met():
    r = StepResult("X", "t", "e")
    r.fact("real check", "ok", "ok", True)
    r.inapplicable("mutation check", "rejected", "opaque artifact")
    assert r.passed and r.not_applicable == 1
    assert "NOT APPLICABLE" in report._observed(r)
    r.fact("failing check", "ok", "bad", False)
    assert not r.passed


@pytest.mark.parametrize("argv,expected", [
    ("--suite parser", {"suite": "parser"}),
    ("--suite=parser --verbose", {"suite": "parser", "verbose": "true"}),
    ("--fail-fast --suite 'unit'", {"fail_fast": "true", "suite": "unit"}),
])
def test_parse_argv_accepts_flags(argv, expected):
    assert parse_argv(argv) == expected


@pytest.mark.parametrize("argv", [
    "--suite parser; rm -rf /",
    "--suite parser && curl x",
    "--suite $(whoami)",
    "--suite parser extra",
    "--suite a --suite b",
    "--suite 'unterminated",
])
def test_parse_argv_refuses(argv):
    with pytest.raises(NormalizationError):
        parse_argv(argv)
