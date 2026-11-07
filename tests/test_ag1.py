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
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
    assert report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]

    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    bundle["records"][0]["record"]["decision"] = "tampered"
    path.write_text(json.dumps(bundle))
    assert not report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]


def test_resigned_bundle_fails_against_independent_anchors(tmp_path):
    """Editing, truncating, and re-signing with the editor's own key must not verify."""
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
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
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
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


@pytest.mark.parametrize("field,value", [
    ("version", "9.9.9"),
    ("capabilities", {"delegation_mode": "authorization_server", "verification_mode": "online_introspection",
                      "artifact_mode": "opaque"}),
])
def test_edited_implementation_header_fails(tmp_path, field, value):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    bundle["implementation"][field] = value
    path.write_text(json.dumps(bundle))
    result = report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))
    assert not result["checkpoint_valid"] and not result["valid"]


def test_online_verifier_is_not_credited_with_offline_checks():
    class OnlineDeclared(type(ADAPTER)):
        capabilities = AdapterCapabilities("authorization_server", "online_introspection", "structured_signed")

    for step in (STEPS[7], STEPS[8]):  # AG-1.8, AG-1.9
        result = step(OnlineDeclared())
        assert result.not_applicable >= 1
        assert not any("offline" in c.description for c in result.checks if c.applicable)


@pytest.mark.parametrize("edit", [
    lambda b: b.update(implementation=None),
    lambda b: b.update(records=None),
    lambda b: b["records"].__setitem__(0, {"record": "not an object", "signature": "00"}),
    lambda b: b["records"].__setitem__(0, 7),
    lambda b: b.update(checkpoint=[]),
], ids=["implementation-null", "records-null", "record-string", "record-number", "checkpoint-list"])
def test_malformed_bundle_is_invalid_not_a_crash(tmp_path, edit):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    edit(bundle)
    path.write_text(json.dumps(bundle))
    assert not report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]


def test_bundle_naming_another_root_fails(tmp_path):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
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


def test_bundle_from_before_the_service_field_still_verifies(tmp_path):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    del bundle["service"]
    # What a writer without the field produced: same key, header without `service`.
    header = {k: bundle[k] for k in report.HEADER_FIELDS if k in bundle}
    body = {**bundle["checkpoint"]["checkpoint"], "header": header}
    bundle["checkpoint"] = {"checkpoint": body, "signature": world.gateway._signer.sign(record_payload(body)).hex()}
    path.write_text(json.dumps(bundle))
    assert report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]


def test_dropping_the_service_field_fails(tmp_path):
    world = evidence_run(ADAPTER)
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
    path = tmp_path / "evidence.json"
    bundle = json.loads(path.read_text())
    del bundle["service"]
    path.write_text(json.dumps(bundle))
    assert not report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]


def test_mock_run_resets_a_previously_chosen_service(tmp_path, monkeypatch):
    from ag1 import __main__ as cli
    from ag1 import scenario
    from ag1.scm import MockSCM

    def unreachable():
        raise AssertionError("a mock run used the previously chosen service")

    scenario.use_service(unreachable)
    monkeypatch.setattr(cli, "STEPS", [])
    monkeypatch.setattr(cli, "utility_run", lambda adapter: {"mistaken_denials": 0, "workflow_completed": True})
    try:
        assert main(["--service", "mock", "--out", str(tmp_path)]) == 0
    finally:
        scenario.use_service(MockSCM)


def test_incomplete_workflow_fails_the_run(tmp_path, monkeypatch):
    from ag1 import __main__ as cli

    monkeypatch.setattr(cli, "STEPS", [])
    monkeypatch.setattr(cli, "utility_run", lambda adapter: {"mistaken_denials": 0, "workflow_completed": False})
    assert main(["--out", str(tmp_path)]) == 1


def test_historical_bundle_survives_expiry_but_live_authorization_does_not(tmp_path):
    import time
    from ag1.scenario import REPO, build_world
    from ag1.spec import Exact
    from ag1.steps import verify_evidence

    world = build_world(ADAPTER)
    holder = ADAPTER.new_principal("short-lived-reader")
    grant = ADAPTER.issue(world.issuer, holder, {"repo.read": {"repo": Exact(REPO)}}, ttl=1)
    agent = world.agent(holder, [grant])
    assert world.call(agent, "repo.read", {"repo": REPO}).allowed
    report.write([], {}, tmp_path, ADAPTER, world.scm, evidence_world=world)
    assert report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]
    time.sleep(2.2)
    assert report.verify_bundle(tmp_path, ADAPTER, *_anchors(world))["valid"]
    assert verify_evidence(world.gateway.evidence, world.gateway.evidence_public_key,
                           ADAPTER, world.issuer)[0]["chain"] is True
    assert not world.call(agent, "repo.read", {"repo": REPO}).allowed
    verifier = ADAPTER.verifier(world.issuer)
    with pytest.raises(Exception):
        verifier.verify_chain([grant])
    with pytest.raises(Exception):
        verifier.verify_chain([grant], as_of=int(ADAPTER.expires_at(grant)) + 3)
    alien = ADAPTER.verifier(ADAPTER.new_principal("untrusted-root"))
    with pytest.raises(Exception):
        alien.verify_chain([grant], as_of=world.gateway.evidence[0]["record"]["time"])
